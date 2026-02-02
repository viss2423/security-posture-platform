#!/usr/bin/env bash
set -euo pipefail

OS_URL="${OS_URL:-http://localhost:9200}"
ASSETS_INDEX="${ASSETS_INDEX:-secplat-assets}"
EVENTS_INDEX="${EVENTS_INDEX:-secplat-events}"
STATUS_INDEX="${STATUS_INDEX:-secplat-asset-status}"

now_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

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
          "source_event_timestamp": { "type": "date" }
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

  status="unknown"
  status_num=-1
  code="null"
  latency_ms="null"
  last_seen="null"
  event_ts="null"

  if [[ -n "$event_src" ]]; then
    status="$(echo "$event_src" | jq -r '.status // "unknown"')"
    status_num="$(echo "$event_src" | jq -r 'if has("status_num") then .status_num else (if .status=="up" then 1 elif .status=="down" then 0 else -1 end) end')"
    code="$(echo "$event_src" | jq -r '.code // null')"
    latency_ms="$(echo "$event_src" | jq -r '.latency_ms // null')"
    last_seen="$(echo "$event_src" | jq -r '.["@timestamp"] // null')"
    event_ts="$last_seen"
  fi

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
      source_event_timestamp: (if $source_event_timestamp=="null" then null else $source_event_timestamp end)
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
  echo "status upserted asset_key=$asset_key status=$status"
done

curl -sS -X POST "$OS_URL/$STATUS_INDEX/_refresh" >/dev/null
echo "refreshed index=$STATUS_INDEX"
