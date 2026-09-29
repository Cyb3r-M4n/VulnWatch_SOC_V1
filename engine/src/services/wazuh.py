# engine/src/services/wazuh.py
"""Sync inventaire Wazuh manager (Syscollector) → PostgreSQL.

Pas de module vulnerability-detection Wazuh : la corrélation CVE reste
dans VulnWatch (NVD + KEV + run_correlation).
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Optional

import httpx
from loguru import logger

from ..database.connection import get_db_connection

WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000").rstrip("/")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
PAGE_SIZE = 500


def _clip(value: Optional[str], n: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in ("unknown", "none", "null"):
        return None
    return text[:n]


def _safe_ip(value: Optional[str]) -> Optional[str]:
    raw = (value or "").strip()
    if not raw or raw.lower() in ("any", "unknown", "none"):
        return None
    try:
        return str(ipaddress.ip_address(raw.split("/")[0]))
    except ValueError:
        return None


def _map_process_status(state: Optional[str]) -> str:
    s = (state or "").strip().lower()
    if s.startswith("run"):
        return "RUNNING"
    if s.startswith("sleep"):
        return "SLEEPING"
    if s.startswith("stop"):
        return "STOPPED"
    if s.startswith("zom"):
        return "ZOMBIE"
    return (state or "UNKNOWN").upper()[:20]


class WazuhInventoryError(Exception):
    pass


async def _auth_token(client: httpx.AsyncClient) -> str:
    if not WAZUH_API_PASSWORD:
        raise WazuhInventoryError("WAZUH_API_PASSWORD manquant")
    response = await client.get(
        f"{WAZUH_API_URL}/security/user/authenticate",
        params={"raw": "true"},
        auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
    )
    if response.status_code >= 400:
        raise WazuhInventoryError(
            f"Auth Wazuh HTTP {response.status_code}: {response.text[:300]}"
        )
    token = response.text.strip().strip('"')
    if not token:
        raise WazuhInventoryError("Jeton Wazuh vide")
    return token


async def _paged(
    client: httpx.AsyncClient,
    path: str,
    headers: dict[str, str],
    extra_params: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    offset = 0
    while True:
        params: dict[str, Any] = {"limit": PAGE_SIZE, "offset": offset}
        if extra_params:
            params.update(extra_params)
        response = await client.get(f"{WAZUH_API_URL}{path}", headers=headers, params=params)
        if response.status_code >= 400:
            raise WazuhInventoryError(
                f"GET {path} HTTP {response.status_code}: {response.text[:300]}"
            )
        payload = response.json()
        data = payload.get("data") or {}
        batch = data.get("affected_items") or []
        items.extend(batch)
        total = int(data.get("total_affected_items") or len(items))
        if not batch or offset + len(batch) >= total:
            break
        offset += PAGE_SIZE
    return items


async def sync_inventory() -> dict[str, int]:
    """Upsert agents / packages / processes depuis l'API manager."""
    stats = {
        "agents": 0,
        "software": 0,
        "processes": 0,
        "skipped_manager": 0,
        "stopped_processes": 0,
    }

    async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
        token = await _auth_token(client)
        headers = {"Authorization": f"Bearer {token}"}
        agents = await _paged(
            client,
            "/agents",
            headers,
            extra_params={"select": "id,name,ip,status,os.name,os.version,os.platform"},
        )

        async with get_db_connection() as conn:
            async with conn.transaction():
                for agent in agents:
                    agent_id = str(agent.get("id") or "")
                    if agent_id == "000":
                        stats["skipped_manager"] += 1
                        continue
                    hostname = _clip(agent.get("name"), 255)
                    if not hostname:
                        continue
                    os_info = agent.get("os") or {}
                    os_name = _clip(os_info.get("name") or os_info.get("platform"), 100)
                    os_version = _clip(os_info.get("version"), 50)
                    status = "active" if (agent.get("status") == "active") else "inactive"
                    ip_addr = _safe_ip(agent.get("ip"))

                    row = await conn.fetchrow(
                        """
                        INSERT INTO assets (hostname, ip_address, os_name, os_version, status, last_seen, updated_at)
                        VALUES ($1, $2::inet, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        ON CONFLICT (hostname) DO UPDATE SET
                            ip_address = COALESCE(EXCLUDED.ip_address, assets.ip_address),
                            os_name = COALESCE(EXCLUDED.os_name, assets.os_name),
                            os_version = COALESCE(EXCLUDED.os_version, assets.os_version),
                            status = EXCLUDED.status,
                            last_seen = CURRENT_TIMESTAMP,
                            updated_at = CURRENT_TIMESTAMP
                        RETURNING id
                        """,
                        hostname,
                        ip_addr,
                        os_name,
                        os_version,
                        status,
                    )
                    asset_id = row["id"]
                    stats["agents"] += 1

                    try:
                        packages = await _paged(
                            client, f"/syscollector/{agent_id}/packages", headers
                        )
                    except WazuhInventoryError as exc:
                        logger.warning(f"Packages agent {agent_id}/{hostname}: {exc}")
                        packages = []
                    for pkg in packages:
                        name = _clip(pkg.get("name"), 255)
                        if not name:
                            continue
                        version = _clip(pkg.get("version"), 50) or "unknown"
                        vendor = _clip(pkg.get("vendor"), 100)
                        fmt = _clip(pkg.get("format"), 50)
                        await conn.execute(
                            """
                            INSERT INTO software (asset_id, name, version, vendor, package_manager, last_seen)
                            VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
                            ON CONFLICT (asset_id, name, version) DO UPDATE SET
                                vendor = COALESCE(EXCLUDED.vendor, software.vendor),
                                package_manager = COALESCE(EXCLUDED.package_manager, software.package_manager),
                                last_seen = CURRENT_TIMESTAMP
                            """,
                            asset_id,
                            name,
                            version,
                            vendor,
                            fmt,
                        )
                        stats["software"] += 1

                    try:
                        processes = await _paged(
                            client, f"/syscollector/{agent_id}/processes", headers
                        )
                    except WazuhInventoryError as exc:
                        logger.warning(f"Processus agent {agent_id}/{hostname}: {exc}")
                        processes = []
                    seen_pids: list[int] = []
                    for proc in processes:
                        try:
                            pid = int(proc.get("pid"))
                        except (TypeError, ValueError):
                            continue
                        name = _clip(proc.get("name"), 255)
                        if not name:
                            continue
                        seen_pids.append(pid)
                        await conn.execute(
                            """
                            INSERT INTO processes (asset_id, pid, name, path, cmdline, status, last_seen)
                            VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
                            ON CONFLICT (asset_id, pid) DO UPDATE SET
                                name = EXCLUDED.name,
                                path = COALESCE(EXCLUDED.path, processes.path),
                                cmdline = COALESCE(EXCLUDED.cmdline, processes.cmdline),
                                status = EXCLUDED.status,
                                last_seen = CURRENT_TIMESTAMP
                            """,
                            asset_id,
                            pid,
                            name,
                            _clip(proc.get("cmd"), 10000),
                            _clip(proc.get("argvs"), 10000),
                            _map_process_status(proc.get("state")),
                        )
                        stats["processes"] += 1

                    if seen_pids:
                        stopped = await conn.execute(
                            """
                            UPDATE processes
                            SET status = 'STOPPED'
                            WHERE asset_id = $1
                              AND status = 'RUNNING'
                              AND NOT (pid = ANY($2::int[]))
                            """,
                            asset_id,
                            seen_pids,
                        )
                        # asyncpg returns status string like "UPDATE 3"
                        try:
                            stats["stopped_processes"] += int(stopped.split()[-1])
                        except (ValueError, IndexError):
                            pass

    logger.info(f"Inventaire Wazuh synchronisé: {stats}")
    return stats
