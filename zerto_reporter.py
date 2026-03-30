#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore")
"""
Zerto Analytics API → Elasticsearch Reporter

Pulls the following data from the Zerto Analytics API and prints it to stdout:
  - VPG information (name, type, peer site, protection status, state, actual RPO)
  - Site status
  - VM information
  - Protected storage (TB)
  - Compression statistics (per VPG)
  - Average RPO (per VPG)

Note: VPG priority is not exposed in the Zerto Analytics API.
      Use the ZVM REST API if priority is required.

Usage:
    Set environment variables (see Configuration section below), then run:
        python zerto_reporter.py

Environment variables (set on the VM):
    AZURE_VAULT_URL       - Azure Key Vault URL (e.g. https://kv-zerto-collector.vault.azure.net)
    AZURE_CLIENT_ID       - Service Principal app ID
    AZURE_CLIENT_SECRET   - Service Principal secret
    AZURE_TENANT_ID       - Azure AD tenant ID
    REPORT_HOURS          - Hours of history to pull for RPO/compression reports (default: 24)

Secrets loaded from Azure Key Vault (Managed Identity):
    zerto-username      - Zerto Analytics portal username (email)
    zerto-password      - Zerto Analytics portal password
    es-uk-host          - UK Elasticsearch host URL
    es-uk-api-key       - UK Elasticsearch API key
    es-us-host          - US Elasticsearch host URL
    es-us-api-key       - US Elasticsearch API key
"""

import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ZERTO_BASE_URL   = "https://analytics.api.zerto.com"
AZURE_VAULT_URL  = os.getenv("AZURE_VAULT_URL")   # e.g. https://kv-zerto.vault.azure.net

# How many hours back to pull for RPO / compression report data (non-secret, stays as env var)
REPORT_HOURS = int(os.getenv("REPORT_HOURS", "24"))


def load_secrets(vault_url: str) -> dict:
    """Fetch all required secrets from Azure Key Vault using Managed Identity."""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)

    secret_names = [
        "zerto-username",
        "zerto-password",
        "es-uk-host",
        "es-uk-api-key",
        "es-us-host",
        "es-us-api-key",
    ]

    secrets = {}
    for name in secret_names:
        log.info("Loading secret: %s", name)
        secrets[name] = client.get_secret(name).value

    return secrets

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Zerto Analytics API client
# ---------------------------------------------------------------------------

class ZertoAnalyticsClient:
    def __init__(self, username: str, password: str, base_url: str = ZERTO_BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def authenticate(self) -> None:
        """Obtain a Bearer token using username/password."""
        url = f"{self.base_url}/v2/auth/token"
        resp = self.session.post(
            url,
            json={"username": self.username, "password": self.password},
            timeout=30,
        )
        resp.raise_for_status()
        token = resp.json().get("token")
        if not token:
            raise ValueError("Authentication succeeded but no token was returned.")
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        log.info("Authenticated with Zerto Analytics API.")

    def _get(self, path: str, params: Optional[dict] = None) -> Union[dict, list]:
        url = f"{self.base_url}{path}"
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        if not resp.content:
            return {}
        return resp.json()

    # --- Monitoring endpoints -----------------------------------------------

    def get_account_summary(self) -> dict:
        """Account-level aggregations including total protected data size."""
        return self._get("/v2/monitoring/")

    def get_vpgs(self) -> list:
        """All VPGs with real-time status."""
        data = self._get("/v2/monitoring/vpgs")
        # Response may be a list directly or wrapped in a dict
        if isinstance(data, list):
            return data
        return data.get("vpgs", data.get("data", []))

    def get_sites(self) -> list:
        """All sites with connection status."""
        data = self._get("/v2/monitoring/sites")
        if isinstance(data, list):
            return data
        return data.get("sites", data.get("data", []))

    def get_protected_vms(self) -> list:
        """All protected VMs."""
        data = self._get("/v2/monitoring/protected-vms")
        if isinstance(data, list):
            return data
        return data.get("vms", data.get("data", []))

    # --- Report endpoints (require date range) ------------------------------

    def get_vpg_network_summary(
        self, vpg_id: str, start_date: str, end_date: str
    ) -> Optional[dict]:
        """Per-VPG network summary including avgCompressionRate."""
        try:
            return self._get(
                "/v2/reports/vpg-network-summary",
                params={"vpgIdentifier": vpg_id, "startDate": start_date, "endDate": end_date},
            )
        except (requests.HTTPError, requests.exceptions.JSONDecodeError) as exc:
            log.warning("network-summary failed for VPG %s: %s", vpg_id, exc)
            return None

    def get_vpg_rpo_summary(
        self, vpg_id: str, start_date: str, end_date: str
    ) -> Optional[dict]:
        """Per-VPG RPO summary (avg, configured, meetingSlaPercentage)."""
        try:
            return self._get(
                "/v2/reports/rpo-summary",
                params={"vpgIdentifier": vpg_id, "startDate": start_date, "endDate": end_date},
            )
        except (requests.HTTPError, requests.exceptions.JSONDecodeError) as exc:
            log.warning("rpo-summary failed for VPG %s: %s", vpg_id, exc)
            return None

# ---------------------------------------------------------------------------
# Document builders
# ---------------------------------------------------------------------------

def _date_str(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_vpg_document(
    vpg: dict,
    network_summary: Optional[dict],
    rpo_summary: Optional[dict],
    ts: datetime,
) -> dict:
    protected_site = vpg.get("protectedSite") or {}
    recovery_site = vpg.get("recoverySite") or {}

    # Derive a human-readable type from site types (e.g. "vCenter → AWS")
    src_type = protected_site.get("type", "Unknown")
    dst_type = recovery_site.get("type", "Unknown")
    vpg_type = f"{src_type} → {dst_type}"

    doc = {
        "@timestamp": _date_str(ts),
        "vpg_id": vpg.get("identifier"),
        "vpg_name": vpg.get("name"),
        "vpg_type": vpg_type,
        "peer_site": {
            "name": recovery_site.get("name"),
            "type": recovery_site.get("type"),
            "zvm_ip": recovery_site.get("zvmIp"),
            "identifier": recovery_site.get("identifier"),
        },
        "protected_site": {
            "name": protected_site.get("name"),
            "type": protected_site.get("type"),
            "zvm_ip": protected_site.get("zvmIp"),
            "identifier": protected_site.get("identifier"),
        },
        # Priority is not available in the Analytics API
        "protection_status": vpg.get("status"),
        "vpg_sub_status": vpg.get("subStatus"),
        "vpg_health": vpg.get("health"),
        "actual_rpo_seconds": vpg.get("actualRpo"),
        "configured_rpo_seconds": vpg.get("configuredRpo"),
        "vms_count": vpg.get("vmsCount"),
        "zorg_name": vpg.get("zorgName"),
        "configured_journal_history_minutes": vpg.get("configuredJournalHistory"),
        "actual_journal_history_minutes": vpg.get("actualJournalHistory"),
    }

    # Compression stats from network summary
    if network_summary:
        doc["compression"] = {
            "avg_throughput_mb": network_summary.get("avgThroughput"),
            "avg_outgoing_wan_mb": network_summary.get("avgOutgoingWANtraffic"),
            "avg_iops": network_summary.get("avgIops"),
            "avg_compression_rate_pct": network_summary.get("avgCompressionRate"),
        }

    # RPO stats from RPO summary
    if rpo_summary:
        doc["rpo_report"] = {
            "avg_rpo_seconds": rpo_summary.get("avg"),
            "configured_rpo_seconds": rpo_summary.get("configured"),
            "meeting_sla_pct": rpo_summary.get("meetingSlaPercentage"),
        }

    return doc


def build_site_document(site: dict, ts: datetime) -> dict:
    return {
        "@timestamp": _date_str(ts),
        "site_id": site.get("identifier"),
        "site_name": site.get("name"),
        "site_type": site.get("type"),
        "zvm_version": site.get("vesrion") or site.get("version"),  # API has a typo
        "zvm_ip": site.get("zvmpIp") or site.get("zvmIp"),
        "connection_status": site.get("connectionStatus"),
        "last_connection_time": site.get("lastConnetionTime") or site.get("lastConnectionTime"),
        "is_connected": site.get("isConnected"),
        "is_transmission_enabled": site.get("isTransmissionEnabled"),
        "zorgs_count": site.get("zorgsCount"),
    }


def build_vm_document(vm: dict, ts: datetime) -> dict:
    provisioned_mb = vm.get("provisionedStorageMb") or 0
    used_mb = vm.get("usedStorageMb") or 0

    vpg_list = vm.get("vpgs") or []
    vpg_names = [v.get("name") for v in vpg_list if v.get("name")]
    vpg_statuses = {v.get("name"): v.get("status") for v in vpg_list if v.get("name")}

    return {
        "@timestamp": _date_str(ts),
        "vm_id": vm.get("identifier"),
        "vm_name": vm.get("name"),
        "provisioned_storage_mb": provisioned_mb,
        "provisioned_storage_tb": round(provisioned_mb / 1_048_576, 6) if provisioned_mb else 0,
        "used_storage_mb": used_mb,
        "used_storage_tb": round(used_mb / 1_048_576, 6) if used_mb else 0,
        "vpg_names": vpg_names,
        "vpg_statuses": vpg_statuses,
        "zorg_name": (vm.get("zorg") or {}).get("name"),
    }


def build_account_document(summary: dict, ts: datetime) -> dict:
    protected_bytes = summary.get("protectedDataSize") or 0
    return {
        "@timestamp": _date_str(ts),
        "healthy_vpgs_count": summary.get("healthyVpgsCount"),
        "alerted_vpgs_count": summary.get("alertedVpgsCount"),
        "faulted_vpgs_count": summary.get("faultedVpgsCount"),
        "total_vpgs_count": summary.get("vpgsCount"),
        "total_vms_count": summary.get("vmsCount"),
        "sites_count": summary.get("sitesCount"),
        "alerts_count": summary.get("alertsCount"),
        "tasks_count": summary.get("tasksCount"),
        "average_actual_rpo_seconds": summary.get("averageActualRpo"),
        "average_configured_rpo_seconds": summary.get("averageConfiguredRpo"),
        "protected_data_bytes": protected_bytes,
        "protected_data_tb": round(protected_bytes / 1_099_511_627_776, 6) if protected_bytes else 0,
    }

# ---------------------------------------------------------------------------
# Elasticsearch helpers
# ---------------------------------------------------------------------------

def _rpo_str(seconds) -> str:
    if seconds is None:
        return "N/A"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60}s"


def _tb_str(mb) -> str:
    if mb is None:
        return "N/A"
    return f"{mb / 1_048_576:.4f} TB"


def _print_vpg_list(vpg_list: list, vms_by_vpg: dict) -> None:
    for vpg in sorted(vpg_list, key=lambda v: v.get("vpg_name", "")):
        vpg_name  = vpg.get("vpg_name", "Unknown")
        status    = vpg.get("protection_status", "Unknown")
        health    = vpg.get("vpg_health", "")
        rpo       = _rpo_str(vpg.get("actual_rpo_seconds"))
        peer      = (vpg.get("peer_site") or {}).get("name", "?")
        vpg_type  = vpg.get("vpg_type", "?")
        comp_rate = (vpg.get("compression") or {}).get("avg_compression_rate_pct")
        avg_rpo   = (vpg.get("rpo_report") or {}).get("avg_rpo_seconds")
        sla_pct   = (vpg.get("rpo_report") or {}).get("meeting_sla_pct")

        print(f"\n    ┌─ VPG: {vpg_name}")
        print(f"    │   Type:        {vpg_type}")
        print(f"    │   Peer Site:   {peer}")
        print(f"    │   Status:      {status}  ({health})")
        print(f"    │   Actual RPO:  {rpo}")
        print(f"    │   Avg RPO:     {_rpo_str(avg_rpo)}", end="")
        if avg_rpo is not None and sla_pct is not None:
            print(f"  (Meeting SLA: {sla_pct:.1f}%)", end="")
        print()
        if comp_rate is not None:
            print(f"    │   Compression: {comp_rate:.1f}%")

        vms = vms_by_vpg.get(vpg_name, [])
        if not vms:
            print(f"    │   (no VMs)")
        else:
            print(f"    │")
            for i, vm in enumerate(sorted(vms, key=lambda v: v.get("vm_name", ""))):
                prefix = "    └──" if i == len(vms) - 1 else "    ├──"
                used   = _tb_str(vm.get("used_storage_mb"))
                prov   = _tb_str(vm.get("provisioned_storage_mb"))
                print(f"    │{prefix} VM: {vm.get('vm_name', 'Unknown')}  |  Used: {used}  |  Provisioned: {prov}")


def print_hierarchy(account_doc: dict, site_docs: list, vpg_docs: list, vm_docs: list) -> None:
    # Build lookup: vpg_name -> vm list
    vms_by_vpg: dict = {}
    for vm in vm_docs:
        for vpg_name in vm.get("vpg_names", []):
            vms_by_vpg.setdefault(vpg_name, []).append(vm)

    # Build lookup: zorg_name -> vpg list
    vpgs_by_zorg: dict = {}
    for vpg in vpg_docs:
        zorg = vpg.get("zorg_name") or "No ZORG"
        vpgs_by_zorg.setdefault(zorg, []).append(vpg)

    # Account summary header
    print(f"\n{'═' * 70}")
    print(f"  ZERTO REPORT  —  {account_doc['@timestamp']}")
    print(f"{'═' * 70}")
    print(
        f"  VPGs: {account_doc['total_vpgs_count']}  |  "
        f"VMs: {account_doc['total_vms_count']}  |  "
        f"Sites: {account_doc['sites_count']}  |  "
        f"Protected: {account_doc['protected_data_tb']:.4f} TB  |  "
        f"Avg RPO: {_rpo_str(account_doc['average_actual_rpo_seconds'])}"
    )

    for zorg_name in sorted(vpgs_by_zorg):
        print(f"\n{'─' * 70}")
        print(f"  ZORG  {zorg_name}")
        print(f"{'─' * 70}")
        _print_vpg_list(vpgs_by_zorg[zorg_name], vms_by_vpg)

    print(f"\n{'═' * 70}\n")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Elasticsearch document builders
# ---------------------------------------------------------------------------

def es_snapshot_zerto(site_docs: list, account_doc: dict, snapshot_id: str) -> list:
    """One document per site for the snapshot_zerto index."""
    docs = []
    for site in site_docs:
        docs.append({
            "snapshot_id":            snapshot_id,
            "@timestamp":             account_doc["@timestamp"],
            "site_id":                site["site_id"],
            "site_name":              site["site_name"],
            "site_type":              site["site_type"],
            "zvm_version":            site["zvm_version"],
            "zvm_ip":                 site["zvm_ip"],
            "connection_status":      site["connection_status"],
            "last_connection_time":   site["last_connection_time"],
            "is_connected":           site["is_connected"],
            "is_transmission_enabled": site["is_transmission_enabled"],
            "zorgs_count":            site["zorgs_count"],
            # Account-level totals on every site doc for easy filtering
            "account_total_vpgs":     account_doc["total_vpgs_count"],
            "account_total_vms":      account_doc["total_vms_count"],
            "account_protected_tb":   account_doc["protected_data_tb"],
            "account_avg_rpo_seconds": account_doc["average_actual_rpo_seconds"],
        })
    return docs


def es_snapshot_zerto_vpg(vpg_docs: list, snapshot_id: str) -> list:
    """One document per VPG for the snapshot_zerto_vpg index."""
    docs = []
    for vpg in vpg_docs:
        doc = {
            "snapshot_id":              snapshot_id,
            "@timestamp":               vpg["@timestamp"],
            "vpg_id":                   vpg["vpg_id"],
            "vpg_name":                 vpg["vpg_name"],
            "vpg_type":                 vpg["vpg_type"],
            "zorg_name":                vpg["zorg_name"],
            "protected_site_name":      (vpg.get("protected_site") or {}).get("name"),
            "protected_site_id":        (vpg.get("protected_site") or {}).get("identifier"),
            "peer_site_name":           (vpg.get("peer_site") or {}).get("name"),
            "peer_site_id":             (vpg.get("peer_site") or {}).get("identifier"),
            "protection_status":        vpg["protection_status"],
            "vpg_sub_status":           vpg["vpg_sub_status"],
            "vpg_health":               vpg["vpg_health"],
            "actual_rpo_seconds":       vpg["actual_rpo_seconds"],
            "configured_rpo_seconds":   vpg["configured_rpo_seconds"],
            "vms_count":                vpg["vms_count"],
            "configured_journal_history_minutes": vpg["configured_journal_history_minutes"],
            "actual_journal_history_minutes":     vpg["actual_journal_history_minutes"],
        }
        if vpg.get("compression"):
            doc.update({
                "avg_throughput_mb":        vpg["compression"]["avg_throughput_mb"],
                "avg_outgoing_wan_mb":      vpg["compression"]["avg_outgoing_wan_mb"],
                "avg_iops":                 vpg["compression"]["avg_iops"],
                "avg_compression_rate_pct": vpg["compression"]["avg_compression_rate_pct"],
            })
        if vpg.get("rpo_report"):
            doc.update({
                "avg_rpo_seconds":      vpg["rpo_report"]["avg_rpo_seconds"],
                "meeting_sla_pct":      vpg["rpo_report"]["meeting_sla_pct"],
            })
        docs.append(doc)
    return docs


def es_snapshot_zerto_item(vm_docs: list, vpg_docs: list, snapshot_id: str) -> list:
    """One document per VM for the snapshot_zerto_item index.
    Each VM is linked to its VPG(s) via vpg_id and snapshot_id."""
    # Build vpg_name -> vpg_id lookup
    vpg_id_by_name = {v["vpg_name"]: v["vpg_id"] for v in vpg_docs if v.get("vpg_name")}

    docs = []
    for vm in vm_docs:
        # A VM can belong to multiple VPGs — emit one doc per VPG relationship
        vpg_names = vm.get("vpg_names") or []
        if not vpg_names:
            vpg_names = [None]
        for vpg_name in vpg_names:
            docs.append({
                "snapshot_id":          snapshot_id,
                "@timestamp":           vm["@timestamp"],
                "vm_id":                vm["vm_id"],
                "vm_name":              vm["vm_name"],
                "vpg_name":             vpg_name,
                "vpg_id":               vpg_id_by_name.get(vpg_name),
                "zorg_name":            vm["zorg_name"],
                "provisioned_storage_mb": vm["provisioned_storage_mb"],
                "provisioned_storage_tb": vm["provisioned_storage_tb"],
                "used_storage_mb":      vm["used_storage_mb"],
                "used_storage_tb":      vm["used_storage_tb"],
                "vpg_status":           (vm.get("vpg_statuses") or {}).get(vpg_name),
            })
    return docs


# ---------------------------------------------------------------------------
# Elasticsearch helpers
# ---------------------------------------------------------------------------

def get_es_client(host: str, api_key: str) -> Elasticsearch:
    kwargs = {"hosts": [host]}
    # if api_key:
    #     kwargs["api_key"] = api_key
    return Elasticsearch(**kwargs)


def zorg_region(zorg_name: Optional[str]) -> str:
    """Return 'uk', 'us', or 'unknown' based on the ZORG prefix."""
    if not zorg_name:
        return "unknown"
    prefix = zorg_name.lower()[:4]
    if prefix == "ukcu":
        return "uk"
    if prefix == "uscu":
        return "us"
    return "unknown"


def index_to_es(es: Elasticsearch, index: str, docs: list) -> None:
    if not docs:
        log.info("No documents to index for %s.", index)
        return
    actions = [{"_index": index, "_source": doc} for doc in docs]
    success, errors = bulk(es, actions, raise_on_error=False)
    log.info("Indexed %d documents into '%s' (%d errors).", success, index, len(errors))
    for err in errors:
        log.error("Bulk index error: %s", err)


def main() -> None:
    if not AZURE_VAULT_URL:
        log.error("AZURE_VAULT_URL environment variable must be set.")
        sys.exit(1)

    # --- Load all secrets from Azure Key Vault ---
    log.info("Loading secrets from Azure Key Vault ...")
    secrets = load_secrets(AZURE_VAULT_URL)
    zerto_username = secrets["zerto-username"]
    zerto_password = secrets["zerto-password"]
    es_uk_host     = secrets["es-uk-host"]
    # es_uk_api_key  = secrets["es-uk-api-key"]
    es_us_host     = secrets["es-us-host"]
    # es_us_api_key  = secrets["es-us-api-key"]

    now = datetime.now(tz=timezone.utc)
    report_start = now - timedelta(hours=REPORT_HOURS)
    start_str = _date_str(report_start)
    end_str = _date_str(now)
    snapshot_id = str(uuid.uuid4())
    log.info("Snapshot ID: %s", snapshot_id)

    # --- Connect to Elasticsearch (UK + US) ---
    es_clients = {}
    for region, host, api_key in [
        ("uk", es_uk_host, None),
        ("us", es_us_host, None),
    ]:
        log.info("Connecting to %s Elasticsearch at %s ...", region.upper(), host)
        client = get_es_client(host, api_key)
        if not client.ping():
            log.error("Cannot reach %s Elasticsearch at %s.", region.upper(), host)
            sys.exit(1)
        es_clients[region] = client
        log.info("%s Elasticsearch connection OK.", region.upper())

    # --- Connect to Zerto Analytics API ---
    zerto = ZertoAnalyticsClient(zerto_username, zerto_password)
    zerto.authenticate()

    # --- Fetch all data ---
    log.info("Fetching account summary ...")
    account_doc = build_account_document(zerto.get_account_summary(), now)

    log.info("Fetching site status ...")
    sites = zerto.get_sites()
    log.info("Found %d sites.", len(sites))
    site_docs = [build_site_document(s, now) for s in sites]

    log.info("Fetching protected VM information ...")
    vms = zerto.get_protected_vms()
    log.info("Found %d protected VMs.", len(vms))
    vm_docs = [build_vm_document(v, now) for v in vms]

    log.info("Fetching VPG information ...")
    vpgs = zerto.get_vpgs()
    log.info("Found %d VPGs. Fetching per-VPG reports (last %d hours) ...", len(vpgs), REPORT_HOURS)

    vpg_docs = []
    for vpg in vpgs:
        vpg_id   = vpg.get("identifier")
        vpg_name = vpg.get("name", vpg_id)
        log.info("  Processing VPG: %s", vpg_name)
        net_summary = zerto.get_vpg_network_summary(vpg_id, start_str, end_str)
        rpo_summary = zerto.get_vpg_rpo_summary(vpg_id, start_str, end_str)
        vpg_docs.append(build_vpg_document(vpg, net_summary, rpo_summary, now))

    # --- Print hierarchy ---
    print_hierarchy(account_doc, site_docs, vpg_docs, vm_docs)

    # --- Index to Elasticsearch, routed by ZORG prefix ---
    log.info("Indexing to Elasticsearch (snapshot_id: %s) ...", snapshot_id)

    # Split VPG and VM docs by region
    vpg_by_region:  dict = {"uk": [], "us": [], "unknown": []}
    item_by_region: dict = {"uk": [], "us": [], "unknown": []}

    for doc in es_snapshot_zerto_vpg(vpg_docs, snapshot_id):
        vpg_by_region[zorg_region(doc.get("zorg_name"))].append(doc)

    for doc in es_snapshot_zerto_item(vm_docs, vpg_docs, snapshot_id):
        item_by_region[zorg_region(doc.get("zorg_name"))].append(doc)

    # Sites are routed by their name prefix (UKDC* → uk, USDC* → us)
    site_es_docs = es_snapshot_zerto(site_docs, account_doc, snapshot_id)
    site_by_region: dict = {"uk": [], "us": [], "unknown": []}
    for doc in site_es_docs:
        name = (doc.get("site_name") or "").lower()
        if name.startswith("uk"):
            site_by_region["uk"].append(doc)
        elif name.startswith("us"):
            site_by_region["us"].append(doc)
        else:
            site_by_region["unknown"].append(doc)

    for region, es in es_clients.items():
        log.info("Writing %s data ...", region.upper())
        index_to_es(es, "snapshot_zerto",      site_by_region[region])
        index_to_es(es, "snapshot_zerto_vpg",  vpg_by_region[region])
        index_to_es(es, "snapshot_zerto_item", item_by_region[region])

    # Warn about any docs that couldn't be routed
    for collection, by_region in [("sites", site_by_region), ("VPGs", vpg_by_region), ("VMs", item_by_region)]:
        if by_region["unknown"]:
            log.warning("%d %s could not be routed (ZORG prefix not ukcu/uscu) — skipped.", len(by_region["unknown"]), collection)

    log.info("Done.")


if __name__ == "__main__":
    main()
