"""Attack graph builders for incidents and asset-centric investigations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text


def _safe_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        import json

        raw = value.strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        import json

        raw = value.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return parsed
    return []


def _iso(value: Any) -> str | None:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if value is None:
        return None
    return str(value)


def _kill_chain_phase(technique: str) -> str:
    key = str(technique or "").strip().upper()
    if key.startswith("T159") or key.startswith("T158"):
        return "reconnaissance"
    if key.startswith("T119") or key.startswith("T1078") or key.startswith("T1133"):
        return "initial_access"
    if key.startswith("T1059") or key.startswith("T1204"):
        return "execution"
    if key.startswith("T1053") or key.startswith("T1543") or key.startswith("T1547"):
        return "persistence"
    if key.startswith("T1068") or key.startswith("T1548"):
        return "privilege_escalation"
    if key.startswith("T1021") or key.startswith("T1563"):
        return "lateral_movement"
    if key.startswith("T1041") or key.startswith("T1567"):
        return "exfiltration"
    return "unknown"


def _new_graph() -> dict[str, Any]:
    return {
        "nodes": [],
        "edges": [],
        "kill_chain": [],
        "summary": {
            "node_count": 0,
            "edge_count": 0,
            "kill_chain_phases": 0,
        },
    }


def _upsert_node(
    nodes: dict[str, dict[str, Any]],
    *,
    node_id: str,
    node_type: str,
    label: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    current = nodes.get(node_id)
    if current:
        if metadata:
            merged = dict(current.get("metadata") or {})
            merged.update({k: v for k, v in metadata.items() if v is not None})
            current["metadata"] = merged
        return
    nodes[node_id] = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "metadata": metadata or {},
    }


def _upsert_edge(
    edges: dict[tuple[str, str, str], dict[str, Any]],
    *,
    source: str,
    target: str,
    relation: str,
    observed_at: Any = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    key = (source, target, relation)
    current = edges.get(key)
    observed_iso = _iso(observed_at)
    if current:
        current["weight"] = int(current.get("weight") or 1) + 1
        if observed_iso:
            existing_first = current.get("first_seen")
            existing_last = current.get("last_seen")
            if existing_first is None or observed_iso < str(existing_first):
                current["first_seen"] = observed_iso
            if existing_last is None or observed_iso > str(existing_last):
                current["last_seen"] = observed_iso
        if metadata:
            merged = dict(current.get("metadata") or {})
            merged.update({k: v for k, v in metadata.items() if v is not None})
            current["metadata"] = merged
        return
    edges[key] = {
        "id": f"edge:{source}:{relation}:{target}",
        "source": source,
        "target": target,
        "relation": relation,
        "weight": 1,
        "first_seen": observed_iso,
        "last_seen": observed_iso,
        "metadata": metadata or {},
    }


def _collect_asset_graph(
    conn: Any,
    *,
    asset_keys: set[str],
    lookback_hours: int,
    nodes: dict[str, dict[str, Any]],
    edges: dict[tuple[str, str, str], dict[str, Any]],
    kill_chain_counter: dict[str, int],
) -> None:
    if not asset_keys:
        return
    since = datetime.now(UTC) - timedelta(hours=max(1, min(int(lookback_hours), 720)))
    asset_list = sorted(asset_keys)
    alert_rows = (
        conn.execute(
            text(
                """
                SELECT
                  alert_id,
                  asset_key,
                  source,
                  title,
                  severity,
                  first_seen_at,
                  last_seen_at,
                  mitre_techniques,
                  payload_json,
                  context_json
                FROM security_alerts
                WHERE asset_key = ANY(CAST(:asset_keys AS text[]))
                  AND COALESCE(last_seen_at, first_seen_at, NOW()) >= :since
                ORDER BY COALESCE(last_seen_at, first_seen_at) DESC
                LIMIT 500
                """
            ),
            {"asset_keys": asset_list, "since": since},
        )
        .mappings()
        .all()
    )

    for row in alert_rows:
        alert_id = int(row.get("alert_id") or 0)
        if alert_id <= 0:
            continue
        asset_key = str(row.get("asset_key") or "")
        alert_node_id = f"alert:{alert_id}"
        asset_node_id = f"asset:{asset_key}"
        _upsert_node(
            nodes,
            node_id=alert_node_id,
            node_type="alert",
            label=str(row.get("title") or f"Alert {alert_id}"),
            metadata={
                "severity": row.get("severity"),
                "source": row.get("source"),
                "first_seen_at": _iso(row.get("first_seen_at")),
                "last_seen_at": _iso(row.get("last_seen_at")),
            },
        )
        _upsert_edge(
            edges,
            source=alert_node_id,
            target=asset_node_id,
            relation="targets",
            observed_at=row.get("last_seen_at") or row.get("first_seen_at"),
        )

        payload = _safe_json(row.get("payload_json"))
        context = _safe_json(row.get("context_json"))
        source_ip = str(payload.get("src_ip") or context.get("src_ip") or "").strip()
        domain = str(payload.get("domain") or context.get("domain") or "").strip()
        user_name = str(payload.get("user") or context.get("user") or "").strip()
        process_name = str(payload.get("process") or context.get("process") or "").strip()
        observed_at = row.get("last_seen_at") or row.get("first_seen_at")

        if source_ip:
            ip_node_id = f"ip:{source_ip}"
            _upsert_node(nodes, node_id=ip_node_id, node_type="ip", label=source_ip)
            _upsert_edge(
                edges,
                source=ip_node_id,
                target=asset_node_id,
                relation="communicated_with",
                observed_at=observed_at,
                metadata={"source": row.get("source")},
            )
        if domain:
            domain_node_id = f"domain:{domain}"
            _upsert_node(nodes, node_id=domain_node_id, node_type="domain", label=domain)
            _upsert_edge(
                edges,
                source=asset_node_id,
                target=domain_node_id,
                relation="communicated_with",
                observed_at=observed_at,
                metadata={"source": row.get("source")},
            )
        if user_name:
            user_node_id = f"user:{user_name}"
            _upsert_node(nodes, node_id=user_node_id, node_type="user", label=user_name)
            _upsert_edge(
                edges,
                source=user_node_id,
                target=asset_node_id,
                relation="authenticated_to",
                observed_at=observed_at,
            )
        if process_name:
            process_node_id = f"process:{asset_key}:{process_name}"
            _upsert_node(
                nodes,
                node_id=process_node_id,
                node_type="process",
                label=process_name,
                metadata={"asset_key": asset_key},
            )
            _upsert_edge(
                edges,
                source=process_node_id,
                target=asset_node_id,
                relation="executed_on",
                observed_at=observed_at,
            )

        for technique in _safe_list(row.get("mitre_techniques")):
            value = str(technique or "").strip()
            if not value:
                continue
            phase = _kill_chain_phase(value)
            kill_chain_counter[phase] = int(kill_chain_counter.get(phase) or 0) + 1

    relationship_rows = (
        conn.execute(
            text(
                """
                SELECT
                  source_asset_key,
                  target_asset_key,
                  relation_type,
                  confidence,
                  updated_at
                FROM attack_surface_relationships
                WHERE source_asset_key = ANY(CAST(:asset_keys AS text[]))
                   OR target_asset_key = ANY(CAST(:asset_keys AS text[]))
                ORDER BY updated_at DESC
                LIMIT 500
                """
            ),
            {"asset_keys": asset_list},
        )
        .mappings()
        .all()
    )
    for row in relationship_rows:
        source_asset = str(row.get("source_asset_key") or "").strip()
        target_asset = str(row.get("target_asset_key") or "").strip()
        if not source_asset or not target_asset:
            continue
        source_id = f"asset:{source_asset}"
        target_id = f"asset:{target_asset}"
        _upsert_node(nodes, node_id=source_id, node_type="asset", label=source_asset)
        _upsert_node(nodes, node_id=target_id, node_type="asset", label=target_asset)
        _upsert_edge(
            edges,
            source=source_id,
            target=target_id,
            relation=str(row.get("relation_type") or "connected_to"),
            observed_at=row.get("updated_at"),
            metadata={"confidence": row.get("confidence")},
        )


def build_incident_attack_graph(
    conn: Any, *, incident_id: int, lookback_hours: int = 72
) -> dict[str, Any]:
    incident = (
        conn.execute(
            text(
                """
                SELECT id, title, severity, status, created_at
                FROM incidents
                WHERE id = :incident_id
                """
            ),
            {"incident_id": int(incident_id)},
        )
        .mappings()
        .first()
    )
    if not incident:
        return _new_graph()

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    kill_chain_counter: dict[str, int] = {}

    incident_node_id = f"incident:{int(incident['id'])}"
    _upsert_node(
        nodes,
        node_id=incident_node_id,
        node_type="incident",
        label=str(incident.get("title") or f"Incident {incident_id}"),
        metadata={
            "severity": incident.get("severity"),
            "status": incident.get("status"),
            "created_at": _iso(incident.get("created_at")),
        },
    )

    linked = (
        conn.execute(
            text(
                """
                SELECT asset_key, alert_id, added_at
                FROM incident_alerts
                WHERE incident_id = :incident_id
                ORDER BY added_at ASC
                """
            ),
            {"incident_id": int(incident_id)},
        )
        .mappings()
        .all()
    )
    asset_keys: set[str] = set()
    for row in linked:
        asset_key = str(row.get("asset_key") or "").strip()
        if not asset_key:
            continue
        asset_keys.add(asset_key)
        asset_node_id = f"asset:{asset_key}"
        _upsert_node(nodes, node_id=asset_node_id, node_type="asset", label=asset_key)
        _upsert_edge(
            edges,
            source=incident_node_id,
            target=asset_node_id,
            relation="impacts",
            observed_at=row.get("added_at"),
        )

        if row.get("alert_id") is not None:
            alert_id = int(row.get("alert_id") or 0)
            if alert_id > 0:
                alert_node_id = f"alert:{alert_id}"
                _upsert_node(
                    nodes, node_id=alert_node_id, node_type="alert", label=f"Alert {alert_id}"
                )
                _upsert_edge(
                    edges,
                    source=incident_node_id,
                    target=alert_node_id,
                    relation="contains",
                    observed_at=row.get("added_at"),
                )
                _upsert_edge(
                    edges,
                    source=alert_node_id,
                    target=asset_node_id,
                    relation="targets",
                    observed_at=row.get("added_at"),
                )

    _collect_asset_graph(
        conn,
        asset_keys=asset_keys,
        lookback_hours=lookback_hours,
        nodes=nodes,
        edges=edges,
        kill_chain_counter=kill_chain_counter,
    )

    graph = {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "kill_chain": [
            {"phase": phase, "count": count}
            for phase, count in sorted(
                kill_chain_counter.items(), key=lambda item: item[1], reverse=True
            )
        ],
        "summary": {
            "incident_id": int(incident_id),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "kill_chain_phases": len(kill_chain_counter),
        },
    }
    return graph


def build_asset_attack_graph(
    conn: Any, *, asset_key: str, lookback_hours: int = 72
) -> dict[str, Any]:
    normalized = str(asset_key or "").strip()
    if not normalized:
        return _new_graph()
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    kill_chain_counter: dict[str, int] = {}
    _upsert_node(nodes, node_id=f"asset:{normalized}", node_type="asset", label=normalized)
    _collect_asset_graph(
        conn,
        asset_keys={normalized},
        lookback_hours=lookback_hours,
        nodes=nodes,
        edges=edges,
        kill_chain_counter=kill_chain_counter,
    )
    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "kill_chain": [
            {"phase": phase, "count": count}
            for phase, count in sorted(
                kill_chain_counter.items(), key=lambda item: item[1], reverse=True
            )
        ],
        "summary": {
            "asset_key": normalized,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "kill_chain_phases": len(kill_chain_counter),
        },
    }
