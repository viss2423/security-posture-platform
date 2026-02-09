#!/usr/bin/env bash
set -euo pipefail

OS_URL="${OS_URL:-http://localhost:9200}"
ASSETS_INDEX="${ASSETS_INDEX:-secplat-assets}"
EVENTS_INDEX="${EVENTS_INDEX:-secplat-events}"
STATUS_INDEX="${STATUS_INDEX:-secplat-asset-status}"

now_epoch() { date -u +%s; }

# Convert ISO8601 (e.g. 2026-02-04T20:12:01Z) to epoch seconds
iso_to_epoch() {
  # GNU date supports this on Ubuntu
  date -u -d "$1" +%s 2>/dev/null || echo 0
}

# Get current stored status_num for an asset from secplat-asset-status (if exists)
get_prev_status_num() {
  local asset_id="$1"
  curl -s "$OS_URL/$STATUS_INDEX/_doc/$asset_id" \
    -H 'Content-Type: application/json' \
    ${OS_AUTH:+-u "$OS_AUTH"} \
  | jq -r '._source.status_num // empty'
}

# Get current stored last_status_change (if exists)
get_prev_last_change() {
  local asset_id="$1"
  curl -s "$OS_URL/$STATUS_INDEX/_doc/$asset_id" \
    -H 'Content-Type: application/json' \
    ${OS_AUTH:+-u "$OS_AUTH"} \
  | jq -r '._source.last_status_change // empty'
}


# STALE threshold (5 minutes)
STALE_THRESHOLD_SECONDS="${STALE_THRESHOLD_SECONDS:-300}"

now_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
now_epoch="$(date -u +%s)"

# Convert ISO8601 -> epoch seconds (GNU date on Ubuntu)
to_epoch() {
  local iso="$1"
  if [[ -z "$iso" || "$iso" == "null" ]]; then
    echo ""
    return 0
  fi
  date -u -d "$iso" +%s 2>/dev/null || echo ""
}

# Create status index if missing
if curl -sS "$OS_URL/$STATUS_INDEX" | jq -e 'has("error")' >/dev/null 2>&1; then
  echo "creating index: $STATUS_INDEX"
  curl -sS -X PUT "$OS_URL/$STATUS_INDEX" \
    -H "Content-Type: application/json" \
    -d '{
      "settings": { "index": { "number_of_shards": 1, "number_of_replicas": 0 } },
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "asset_key": { "type": "keyword" },
          "name": { "type": "keyword" },
          "type": { "type": "keyword" },
          "environment": { "type": "keyword" },
          "criticality": { "type": "integer" },
          "owner": { "type": "keyword" },
          "owner_team": { "type": "keyword" },

          "status": { "type": "keyword" },
          "status_num": { "type": "integer" },
          "code": { "type": "integer" },
          "latency_ms": { "type": "integer" },
          "last_seen": { "type": "date" },
          "source_event_timestamp": { "type": "date" },
          "staleness_seconds": { "type": "integer" },
          "posture_score": { "type": "integer" },
          "posture_state": { "type": "keyword" },
          "last_status_change": { "type": "date" }
        }
      }
    }' | jq .
else
  echo "index exists: $STATUS_INDEX"
fi

# Fetch all assets
assets_json="$(curl -sS "$OS_URL/$ASSETS_INDEX/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":1000,"track_total_hits":true,"query":{"match_all":{}}}')"

echo "assets fetched: $(echo "$assets_json" | jq -r '.hits.total.value')"

echo "$assets_json" | jq -c '.hits.hits[]?._source' | while read -r asset; do
  asset_key="$(echo "$asset" | jq -r '.asset_key')"
  name="$(echo "$asset" | jq -r '.name // ""')"
  atype="$(echo "$asset" | jq -r '.type // ""')"
  env="$(echo "$asset" | jq -r '.environment // "dev"')"
  crit="$(echo "$asset" | jq -r '.criticality // 3')"
  owner="$(echo "$asset" | jq -r '.owner // ""')"
  owner_team="$(echo "$asset" | jq -r '.owner_team // ""')"

  # Latest health event that matches this asset.
  latest_event="$(curl -sS "$OS_URL/$EVENTS_INDEX/_search" \
  -H "Content-Type: application/json" \
  -d "{
    \"size\": 1,
    \"sort\": [{\"@timestamp\":\"desc\"}],
    \"query\": {
      \"bool\": {
        \"filter\": [
          {\"term\": {\"level\": \"health\"}}
        ],
        \"should\": [
          {\"term\": {\"asset.keyword\": \"${asset_key}\"}},
          {\"match\": {\"asset\": \"${asset_key}\"}},
          {\"term\": {\"service.keyword\": \"${asset_key}\"}},
          {\"match\": {\"service\": \"${asset_key}\"}}
        ],
        \"minimum_should_match\": 1
      }
    }
  }")"

  event_src="$(echo "$latest_event" | jq -c '.hits.hits[0]._source // empty')"

  # Defaults
  status="unknown"
  status_num=-1
  code="null"
  latency_ms="null"
  last_seen="null"
  event_ts="null"
  last_seen_epoch=""

  if [[ -n "$event_src" ]]; then
    # Pull raw fields from event
    raw_status="$(echo "$event_src" | jq -r '.status // "unknown"')"
    code="$(echo "$event_src" | jq -r '.code // null')"
    latency_ms="$(echo "$event_src" | jq -r '.latency_ms // null')"
    last_seen="$(echo "$event_src" | jq -r '.["@timestamp"] // null')"
    event_ts="$last_seen"

    # Decide STALE vs FRESH first
    last_seen_epoch="$(to_epoch "$last_seen")"

    if [[ -n "$last_seen_epoch" ]]; then
      age_seconds=$(( now_epoch - last_seen_epoch ))

      if (( age_seconds > STALE_THRESHOLD_SECONDS )); then
        status="stale"
        status_num=0
        # Fallback: juice-shop and example-com share the same backend (JUICE_URL). If example-com is down, treat juice-shop as down.
        if [[ "$asset_key" == "juice-shop" ]]; then
          other_event="$(curl -sS "$OS_URL/$EVENTS_INDEX/_search" \
            -H "Content-Type: application/json" \
            -d '{"size":1,"sort":[{"@timestamp":"desc"}],"query":{"bool":{"filter":[{"term":{"level":"health"}},{"term":{"asset.keyword":"example-com"}}]}}}')"
          other_src="$(echo "$other_event" | jq -r '.hits.hits[0]._source // empty')"
          if [[ -n "$other_src" ]]; then
            other_status="$(echo "$other_src" | jq -r '.status // ""')"
            other_ts="$(echo "$other_src" | jq -r '.["@timestamp"] // ""')"
            other_epoch="$(to_epoch "$other_ts")"
            if [[ "$other_status" == "down" && -n "$other_epoch" ]]; then
              other_age=$(( now_epoch - other_epoch ))
              if (( other_age < STALE_THRESHOLD_SECONDS * 2 )); then
                status="down"
                status_num=-2
              fi
            fi
          fi
        fi
      else
        # FRESH: decide UP/DOWN using code/status
        # "up" if code==200 OR raw_status=="up"
        if [[ "$code" == "200" ]] || [[ "$raw_status" == "up" ]]; then
          status="up"
          status_num=1
        else
          status="down"
          status_num=-2
        fi
      fi
    else
      # If timestamp parsing failed, keep unknown (safe fallback)
      status="unknown"
      status_num=-1
    fi
  fi

  # --- Posture scoring ---
  STALE_SEC=0
  if [[ -n "$last_seen_epoch" && "$last_seen_epoch" != "" ]]; then
    STALE_SEC=$(( now_epoch - last_seen_epoch ))
  fi

  # posture_score + posture_state
  POSTURE_SCORE=100
  POSTURE_STATE="green"

  if [[ "$status_num" == "-2" ]]; then
    POSTURE_SCORE=0
    POSTURE_STATE="red"
  elif [[ "$status_num" == "-1" ]]; then
    # No health events ever seen
    POSTURE_SCORE=0
    POSTURE_STATE="red"
  elif (( STALE_SEC > 300 )); then
    POSTURE_SCORE=60
    POSTURE_STATE="amber"
  fi

  # last_status_change (changes only when status flips)
  PREV_STATUS_NUM="$(get_prev_status_num "$asset_key")"
  PREV_LAST_CHANGE="$(get_prev_last_change "$asset_key")"

  LAST_STATUS_CHANGE="$PREV_LAST_CHANGE"
  if [[ -z "$LAST_STATUS_CHANGE" ]]; then
    LAST_STATUS_CHANGE="$last_seen"
  fi

  if [[ -n "$PREV_STATUS_NUM" && "$PREV_STATUS_NUM" != "$status_num" ]]; then
    LAST_STATUS_CHANGE="$last_seen"
  fi
  # --- End posture scoring ---

  # Build doc safely (no --argjson surprises)
  doc="$(jq -n \
    --arg ts "$now_iso" \
    --arg asset_key "$asset_key" \
    --arg name "$name" \
    --arg type "$atype" \
    --arg environment "$env" \
    --arg owner "$owner" \
    --arg owner_team "$owner_team" \
    --arg status "$status" \
    --arg criticality "$crit" \
    --arg status_num "$status_num" \
    --arg code "$code" \
    --arg latency_ms "$latency_ms" \
    --arg last_seen "$last_seen" \
    --arg source_event_timestamp "$event_ts" \
    --arg staleness_seconds "$STALE_SEC" \
    --arg posture_score "$POSTURE_SCORE" \
    --arg posture_state "$POSTURE_STATE" \
    --arg last_status_change "$LAST_STATUS_CHANGE" \
    '{
      "@timestamp": $ts,
      asset_key: $asset_key,
      name: $name,
      type: $type,
      environment: $environment,
      criticality: ($criticality | tonumber),
      owner: $owner,
      owner_team: $owner_team,
      status: $status,
      status_num: ($status_num | tonumber),
      code: (if $code=="null" then null else ($code|tonumber) end),
      latency_ms: (if $latency_ms=="null" then null else ($latency_ms|tonumber) end),
      last_seen: (if $last_seen=="null" then null else $last_seen end),
      source_event_timestamp: (if $source_event_timestamp=="null" then null else $source_event_timestamp end),
      staleness_seconds: ($staleness_seconds | tonumber),
      posture_score: ($posture_score | tonumber),
      posture_state: $posture_state,
      last_status_change: (if $last_status_change=="null" then null else $last_status_change end)
    }'
  )"

  if [[ -z "$doc" ]]; then
    echo "ERROR: empty doc for asset_key=$asset_key"
    exit 1
  fi

  resp="$(curl -sS -X PUT "$OS_URL/$STATUS_INDEX/_doc/$asset_key" \
    -H "Content-Type: application/json" \
    -d "$doc")"

  echo "$resp" | jq -c '{result, _id, _index, error}'
  echo "status upserted asset_key=$asset_key status=$status status_num=$status_num"
done

curl -sS -X POST "$OS_URL/$STATUS_INDEX/_refresh" >/dev/null
echo "refreshed index=$STATUS_INDEX"
