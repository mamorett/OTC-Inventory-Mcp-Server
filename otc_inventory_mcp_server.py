# /// script
# dependencies = [
#     "fastmcp",
#     "requests",
#     "pyyaml",
# ]
# ///

"""
OTC Telekom Cloud MCP Server – Read-Only Inventory
Covers: Projects, Compute (ECS), Flavors, Volumes (EVS), Networks (VPC),
        Subnets, Security Groups, Object Storage (OBS), Load Balancers (ELB),
        DNS Zones, NAT Gateways, VPN Services, RDS Instances, CCE Clusters,
        CSS Clusters, DCS Instances, CBR Vaults.

Authentication is based on clouds.yaml (OS_CLIENT_CONFIG_FILE / OS_CLOUD).
All operations are READ-ONLY (GET / list).
"""

import os
import time
import datetime
import logging
import json
import yaml
from typing import Any, Dict, List, Optional
from pathlib import Path
import requests
from fastmcp import FastMCP

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("otc-inventory-mcp-server")


# ---------------------------------------------------------------------------
# clouds.yaml loader
# ---------------------------------------------------------------------------

def load_clouds_yaml(cloud_name: str = "otc") -> Dict[str, Any]:
    """
    Load cloud configuration.
    Priority 1: OS_CLIENT_CONFIG_FILE environment variable.
    Priority 2: Standard OpenStack search paths.
    """
    custom_path_env = os.getenv("OS_CLIENT_CONFIG_FILE")
    search_paths = []

    if custom_path_env:
        custom_path = Path(custom_path_env)
        if not custom_path.exists():
            raise FileNotFoundError(
                f"OS_CLIENT_CONFIG_FILE is set to '{custom_path}' but file does not exist."
            )
        search_paths.append(custom_path)
        logger.info(f"Using configuration file from OS_CLIENT_CONFIG_FILE: {custom_path}")
    else:
        search_paths = [
            Path.cwd() / "clouds.yaml",
            Path.home() / ".config" / "openstack" / "clouds.yaml",
            Path("/etc/openstack/clouds.yaml"),
        ]

    config = None
    used_path = None

    for path in search_paths:
        if path.exists():
            try:
                with open(path, "r") as f:
                    data = yaml.safe_load(f)
                    if data and "clouds" in data and cloud_name in data["clouds"]:
                        config = data["clouds"][cloud_name]
                        used_path = path
                        break
            except Exception as e:
                logger.warning(f"Error reading {path}: {e}")
                if custom_path_env:
                    raise ValueError(
                        f"Failed to parse explicitly requested config file {path}: {e}"
                    )

    if not config:
        if custom_path_env:
            raise ValueError(f"Cloud '{cloud_name}' not found in {custom_path_env}")
        else:
            raise FileNotFoundError(
                f"Could not find configuration for cloud '{cloud_name}' in standard locations."
            )

    logger.info(f"Loaded '{cloud_name}' configuration from {used_path}")

    auth = config.get("auth", {})
    return {
        "auth_url": auth.get("auth_url"),
        "username": auth.get("username"),
        "password": auth.get("password"),
        "domain_name": auth.get("user_domain_name") or auth.get("domain_name"),
        "project_name": auth.get("project_name"),
        "region": config.get("region_name", "eu-de"),
    }


# ---------------------------------------------------------------------------
# OTC Inventory Client
# ---------------------------------------------------------------------------

class OTCInventoryClient:
    """
    Read-only OTC client covering major services.

    Endpoint map (all GETs):
    ┌──────────────────────────────────────────────────────────────────────────┐
    │ Service  │ API Base                                                       │
    ├──────────┼─────────────────────────────────────────────────────────────  │
    │ IAM      │ https://iam.{region}.otc.t-systems.com                        │
    │ ECS      │ https://ecs.{region}.otc.t-systems.com                        │
    │ EVS      │ https://evs.{region}.otc.t-systems.com                        │
    │ VPC      │ https://vpc.{region}.otc.t-systems.com                        │
    │ OBS      │ https://obs.{region}.otc.t-systems.com  (S3-compat)           │
    │ ELB      │ https://elb.{region}.otc.t-systems.com                        │
    │ DNS      │ https://dns.{region}.otc.t-systems.com                        │
    │ NAT      │ https://nat.{region}.otc.t-systems.com                        │
    │ VPN      │ https://vpn.{region}.otc.t-systems.com                        │
    │ RDS      │ https://rds.{region}.otc.t-systems.com                        │
    │ CCE      │ https://cce.{region}.otc.t-systems.com                        │
    │ CSS      │ https://css.{region}.otc.t-systems.com                        │
    │ DCS      │ https://dcs.{region}.otc.t-systems.com                        │
    │ CBR      │ https://cbr.{region}.otc.t-systems.com                        │
    └──────────┴─────────────────────────────────────────────────────────────  ┘
    """

    def __init__(
        self,
        auth_url: str,
        username: str,
        password: str,
        domain_name: str,
        project_name: str,
        region: str,
    ):
        self.auth_url = auth_url.rstrip("/")
        self.username = username
        self.password = password
        self.domain_name = domain_name
        self.project_name = project_name
        self.region = region

        self.token: Optional[str] = None
        self.project_id: Optional[str] = None
        self.token_expires: Optional[str] = None

        # Service base URLs
        self._iam_base = f"https://iam.{region}.otc.t-systems.com"
        self._ecs_base = f"https://ecs.{region}.otc.t-systems.com"
        self._evs_base = f"https://evs.{region}.otc.t-systems.com"
        self._vpc_base = f"https://vpc.{region}.otc.t-systems.com"
        self._obs_base = f"https://obs.{region}.otc.t-systems.com"
        self._elb_base = f"https://elb.{region}.otc.t-systems.com"
        self._dns_base = f"https://dns.{region}.otc.t-systems.com"
        self._nat_base = f"https://nat.{region}.otc.t-systems.com"
        self._vpn_base = f"https://vpn.{region}.otc.t-systems.com"
        self._rds_base = f"https://rds.{region}.otc.t-systems.com"
        self._cce_base = f"https://cce.{region}.otc.t-systems.com"
        self._css_base = f"https://css.{region}.otc.t-systems.com"
        self._dcs_base = f"https://dcs.{region}.otc.t-systems.com"
        self._cbr_base = f"https://cbr.{region}.otc.t-systems.com"

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Auth-Token": self.token or "",
        }

    def authenticate(self, scope: str = "project") -> bool:
        """Obtain a scoped IAM token (project or domain scope)."""
        if scope == "domain":
            scope_block = {"domain": {"name": self.domain_name}}
        else:
            scope_block = {"project": {"name": self.project_name}}

        auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "password": self.password,
                            "domain": {"name": self.domain_name},
                        }
                    },
                },
                "scope": scope_block,
            }
        }
        try:
            resp = requests.post(
                f"{self.auth_url}/auth/tokens",
                json=auth_data,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            if resp.status_code == 201:
                self.token = resp.headers["X-Subject-Token"]
                data = resp.json()
                if scope == "project":
                    self.project_id = data["token"]["project"]["id"]
                    self.token_expires = data["token"]["expires_at"]
                    logger.info(f"Auth OK. Project: {self.project_id} Expires: {self.token_expires}")
                return True
            else:
                logger.error(f"Auth failed ({scope}): {resp.status_code} – {resp.text}")
                return False
        except Exception as exc:
            logger.error(f"Auth error: {exc}")
            return False

    def check_token_validity(self) -> bool:
        """Re-authenticate if token is missing or expiring within 5 minutes."""
        if not self.token or not self.token_expires:
            return self.authenticate()
        try:
            expiry = datetime.datetime.strptime(self.token_expires, "%Y-%m-%dT%H:%M:%S.%fZ")
            if (expiry - datetime.datetime.utcnow()).total_seconds() < 300:
                return self.authenticate()
            return True
        except Exception as exc:
            logger.error(f"Token validation error: {exc}")
            return self.authenticate()

    def set_project(self, project_name: str) -> bool:
        self.project_name = project_name
        return self.authenticate()

    # ------------------------------------------------------------------
    # Generic HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, url: str, params: Optional[Dict] = None) -> Optional[Any]:
        if not self.check_token_validity():
            return None
        try:
            resp = requests.get(url, headers=self._auth_headers(), params=params, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            logger.error(f"GET {url} → {resp.status_code}: {resp.text[:300]}")
            return None
        except Exception as exc:
            logger.error(f"GET {url} error: {exc}")
            return None

    def _get_list(
        self,
        url: str,
        result_key: str,
        params: Optional[Dict] = None,
        paginate: bool = True,
        next_key: str = "next",
    ) -> Optional[List[Dict]]:
        """
        Fetch a paginated list resource.  Follows 'next' links automatically
        when paginate=True.
        """
        if not self.check_token_validity():
            return None
        items: List[Dict] = []
        current_url: Optional[str] = url
        current_params = params

        while current_url:
            try:
                resp = requests.get(
                    current_url,
                    headers=self._auth_headers(),
                    params=current_params,
                    timeout=30,
                )
                if resp.status_code != 200:
                    logger.error(f"GET {current_url} → {resp.status_code}: {resp.text[:300]}")
                    return items or None
                data = resp.json()
                page_items = data.get(result_key, [])
                if isinstance(page_items, list):
                    items.extend(page_items)
                else:
                    items.append(page_items)

                if not paginate:
                    break

                # Try to follow pagination
                next_url = None
                if "links" in data:
                    for link in data["links"]:
                        if link.get("rel") == "next":
                            next_url = link.get("href")
                            break
                elif next_key in data and data[next_key]:
                    next_url = data[next_key]

                current_url = next_url
                current_params = None  # params are embedded in the next URL
            except Exception as exc:
                logger.error(f"GET {current_url} error: {exc}")
                break

        return items

    # ------------------------------------------------------------------
    # IAM / Projects
    # ------------------------------------------------------------------

    def list_projects(self) -> Optional[List[Dict]]:
        """List all projects using a domain-scoped token."""
        # Temporarily get a domain-scoped token
        saved_token = self.token
        saved_expires = self.token_expires
        saved_project_id = self.project_id

        try:
            if not self.authenticate(scope="domain"):
                return None
            domain_token = self.token

            resp = requests.get(
                f"{self.auth_url}/auth/projects",
                headers={"Content-Type": "application/json", "X-Auth-Token": domain_token},
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json().get("projects", [])
            logger.error(f"list_projects failed: {resp.status_code} – {resp.text}")
            return None
        finally:
            # Restore project-scoped token state
            self.token = saved_token
            self.token_expires = saved_expires
            self.project_id = saved_project_id

    # ------------------------------------------------------------------
    # ECS – Compute Instances & Flavors
    # ------------------------------------------------------------------

    def list_instances(
        self,
        status: Optional[str] = None,
        limit: int = 1000,
    ) -> Optional[List[Dict]]:
        """GET /v2.1/{project_id}/servers/detail"""
        params: Dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status.upper()
        return self._get_list(
            f"{self._ecs_base}/v2.1/{self.project_id}/servers/detail",
            result_key="servers",
            params=params,
        )

    def get_instance_detail(self, server_id: str) -> Optional[Dict]:
        """GET /v2.1/{project_id}/servers/{server_id}"""
        data = self._get(f"{self._ecs_base}/v2.1/{self.project_id}/servers/{server_id}")
        return data.get("server") if data else None

    def list_flavors(self) -> Optional[List[Dict]]:
        """GET /v2.1/{project_id}/flavors/detail"""
        return self._get_list(
            f"{self._ecs_base}/v2.1/{self.project_id}/flavors/detail",
            result_key="flavors",
        )

    def list_availability_zones(self) -> Optional[List[Dict]]:
        """GET /v2.1/{project_id}/os-availability-zone"""
        data = self._get(f"{self._ecs_base}/v2.1/{self.project_id}/os-availability-zone")
        return data.get("availabilityZoneInfo") if data else None

    def list_keypairs(self) -> Optional[List[Dict]]:
        """GET /v2.1/{project_id}/os-keypairs"""
        return self._get_list(
            f"{self._ecs_base}/v2.1/{self.project_id}/os-keypairs",
            result_key="keypairs",
        )

    # ------------------------------------------------------------------
    # EVS – Volumes (Disks)
    # ------------------------------------------------------------------

    def list_volumes(self, status: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/volumes/detail"""
        params: Dict[str, Any] = {}
        if status:
            params["status"] = status
        return self._get_list(
            f"{self._evs_base}/v3/{self.project_id}/volumes/detail",
            result_key="volumes",
            params=params or None,
        )

    def get_volume_detail(self, volume_id: str) -> Optional[Dict]:
        """GET /v3/{project_id}/volumes/{volume_id}"""
        data = self._get(f"{self._evs_base}/v3/{self.project_id}/volumes/{volume_id}")
        return data.get("volume") if data else None

    def list_volume_types(self) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/types"""
        return self._get_list(
            f"{self._evs_base}/v3/{self.project_id}/types",
            result_key="volume_types",
        )

    def list_snapshots(self) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/snapshots/detail"""
        return self._get_list(
            f"{self._evs_base}/v3/{self.project_id}/snapshots/detail",
            result_key="snapshots",
        )

    # ------------------------------------------------------------------
    # VPC – Networks, Subnets, Security Groups, Floating IPs, Peerings
    # ------------------------------------------------------------------

    def list_vpcs(self) -> Optional[List[Dict]]:
        """GET /v1/{project_id}/vpcs"""
        return self._get_list(
            f"{self._vpc_base}/v1/{self.project_id}/vpcs",
            result_key="vpcs",
        )

    def get_vpc_detail(self, vpc_id: str) -> Optional[Dict]:
        """GET /v1/{project_id}/vpcs/{vpc_id}"""
        data = self._get(f"{self._vpc_base}/v1/{self.project_id}/vpcs/{vpc_id}")
        return data.get("vpc") if data else None

    def list_subnets(self, vpc_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v1/{project_id}/subnets"""
        params: Dict[str, Any] = {}
        if vpc_id:
            params["vpc_id"] = vpc_id
        return self._get_list(
            f"{self._vpc_base}/v1/{self.project_id}/subnets",
            result_key="subnets",
            params=params or None,
        )

    def list_security_groups(self) -> Optional[List[Dict]]:
        """GET /v1/{project_id}/security-groups"""
        return self._get_list(
            f"{self._vpc_base}/v1/{self.project_id}/security-groups",
            result_key="security_groups",
        )

    def list_security_group_rules(self, security_group_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v1/{project_id}/security-group-rules"""
        params: Dict[str, Any] = {}
        if security_group_id:
            params["security_group_id"] = security_group_id
        return self._get_list(
            f"{self._vpc_base}/v1/{self.project_id}/security-group-rules",
            result_key="security_group_rules",
            params=params or None,
        )

    def list_floating_ips(self) -> Optional[List[Dict]]:
        """GET /v2.0/floatingips  (Neutron-compatible endpoint)"""
        return self._get_list(
            f"{self._vpc_base}/v2.0/floatingips",
            result_key="floatingips",
        )

    def list_vpc_peerings(self) -> Optional[List[Dict]]:
        """GET /v2.0/vpc/peerings"""
        return self._get_list(
            f"{self._vpc_base}/v2.0/vpc/peerings",
            result_key="peerings",
        )

    def list_routes(self, vpc_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v2.0/vpc/routes"""
        params: Dict[str, Any] = {}
        if vpc_id:
            params["vpc_id"] = vpc_id
        return self._get_list(
            f"{self._vpc_base}/v2.0/vpc/routes",
            result_key="routes",
            params=params or None,
        )

    # ------------------------------------------------------------------
    # OBS – Object Storage (S3-compatible, uses virtual-hosted bucket style)
    # ------------------------------------------------------------------

    def list_buckets(self) -> Optional[List[Dict]]:
        """
        GET / (ListAllMyBuckets) via OBS S3-compatible endpoint.
        Returns a simplified list extracted from the XML response.
        """
        if not self.check_token_validity():
            return None
        try:
            resp = requests.get(
                self._obs_base,
                headers={
                    "X-Auth-Token": self.token or "",
                    "Content-Type": "application/xml",
                },
                timeout=30,
            )
            if resp.status_code == 200:
                # Parse minimal XML – avoid external deps
                text = resp.text
                buckets = []
                import re
                for m in re.finditer(r"<Name>(.*?)</Name>", text):
                    buckets.append({"name": m.group(1)})
                creation_dates = re.findall(r"<CreationDate>(.*?)</CreationDate>", text)
                for i, cd in enumerate(creation_dates):
                    if i < len(buckets):
                        buckets[i]["creation_date"] = cd
                return buckets
            logger.error(f"OBS list_buckets failed: {resp.status_code} – {resp.text[:200]}")
            return None
        except Exception as exc:
            logger.error(f"OBS list_buckets error: {exc}")
            return None

    # ------------------------------------------------------------------
    # ELB – Load Balancers, Listeners, Pools
    # ------------------------------------------------------------------

    def list_loadbalancers(self) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/elb/loadbalancers"""
        return self._get_list(
            f"{self._elb_base}/v3/{self.project_id}/elb/loadbalancers",
            result_key="loadbalancers",
        )

    def list_lb_listeners(self, loadbalancer_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/elb/listeners"""
        params: Dict[str, Any] = {}
        if loadbalancer_id:
            params["loadbalancer_id"] = loadbalancer_id
        return self._get_list(
            f"{self._elb_base}/v3/{self.project_id}/elb/listeners",
            result_key="listeners",
            params=params or None,
        )

    def list_lb_pools(self, loadbalancer_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/elb/pools"""
        params: Dict[str, Any] = {}
        if loadbalancer_id:
            params["loadbalancer_id"] = loadbalancer_id
        return self._get_list(
            f"{self._elb_base}/v3/{self.project_id}/elb/pools",
            result_key="pools",
            params=params or None,
        )

    def list_lb_members(self, pool_id: str) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/elb/pools/{pool_id}/members"""
        return self._get_list(
            f"{self._elb_base}/v3/{self.project_id}/elb/pools/{pool_id}/members",
            result_key="members",
        )

    # ------------------------------------------------------------------
    # DNS – Zones & Record Sets
    # ------------------------------------------------------------------

    def list_dns_zones(self, zone_type: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v2/zones   type: public | private"""
        params: Dict[str, Any] = {}
        if zone_type:
            params["type"] = zone_type
        return self._get_list(
            f"{self._dns_base}/v2/zones",
            result_key="zones",
            params=params or None,
        )

    def list_dns_recordsets(self, zone_id: str) -> Optional[List[Dict]]:
        """GET /v2/zones/{zone_id}/recordsets"""
        return self._get_list(
            f"{self._dns_base}/v2/zones/{zone_id}/recordsets",
            result_key="recordsets",
        )

    # ------------------------------------------------------------------
    # NAT – NAT Gateways, SNAT / DNAT Rules
    # ------------------------------------------------------------------

    def list_nat_gateways(self) -> Optional[List[Dict]]:
        """GET /v2/{project_id}/nat_gateways"""
        return self._get_list(
            f"{self._nat_base}/v2/{self.project_id}/nat_gateways",
            result_key="nat_gateways",
        )

    def list_snat_rules(self, nat_gateway_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v2/{project_id}/snat_rules"""
        params: Dict[str, Any] = {}
        if nat_gateway_id:
            params["nat_gateway_id"] = nat_gateway_id
        return self._get_list(
            f"{self._nat_base}/v2/{self.project_id}/snat_rules",
            result_key="snat_rules",
            params=params or None,
        )

    def list_dnat_rules(self, nat_gateway_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v2/{project_id}/dnat_rules"""
        params: Dict[str, Any] = {}
        if nat_gateway_id:
            params["nat_gateway_id"] = nat_gateway_id
        return self._get_list(
            f"{self._nat_base}/v2/{self.project_id}/dnat_rules",
            result_key="dnat_rules",
            params=params or None,
        )

    # ------------------------------------------------------------------
    # VPN – Services, Endpoints, Connections
    # ------------------------------------------------------------------

    def list_vpn_services(self) -> Optional[List[Dict]]:
        """GET /v5/{project_id}/vpn-gateways"""
        return self._get_list(
            f"{self._vpn_base}/v5/{self.project_id}/vpn-gateways",
            result_key="vpn_gateways",
        )

    def list_vpn_connections(self) -> Optional[List[Dict]]:
        """GET /v5/{project_id}/vpn-connection"""
        return self._get_list(
            f"{self._vpn_base}/v5/{self.project_id}/vpn-connection",
            result_key="vpn_connections",
        )

    def list_vpn_endpoint_groups(self) -> Optional[List[Dict]]:
        """GET /v5/{project_id}/customer-gateways"""
        return self._get_list(
            f"{self._vpn_base}/v5/{self.project_id}/customer-gateways",
            result_key="customer_gateways",
        )

    # ------------------------------------------------------------------
    # RDS – Relational Database Service
    # ------------------------------------------------------------------

    def list_rds_instances(self) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/instances"""
        return self._get_list(
            f"{self._rds_base}/v3/{self.project_id}/instances",
            result_key="instances",
        )

    def list_rds_backups(self, instance_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/backups"""
        params: Dict[str, Any] = {}
        if instance_id:
            params["instance_id"] = instance_id
        return self._get_list(
            f"{self._rds_base}/v3/{self.project_id}/backups",
            result_key="backups",
            params=params or None,
        )

    # ------------------------------------------------------------------
    # CCE – Cloud Container Engine (Kubernetes Clusters & Nodes)
    # ------------------------------------------------------------------

    def list_cce_clusters(self) -> Optional[List[Dict]]:
        """GET /api/v3/projects/{project_id}/clusters"""
        return self._get_list(
            f"{self._cce_base}/api/v3/projects/{self.project_id}/clusters",
            result_key="items",
        )

    def list_cce_nodes(self, cluster_id: str) -> Optional[List[Dict]]:
        """GET /api/v3/projects/{project_id}/clusters/{cluster_id}/nodes"""
        return self._get_list(
            f"{self._cce_base}/api/v3/projects/{self.project_id}/clusters/{cluster_id}/nodes",
            result_key="items",
        )

    def list_cce_node_pools(self, cluster_id: str) -> Optional[List[Dict]]:
        """GET /api/v3/projects/{project_id}/clusters/{cluster_id}/nodepools"""
        return self._get_list(
            f"{self._cce_base}/api/v3/projects/{self.project_id}/clusters/{cluster_id}/nodepools",
            result_key="items",
        )

    # ------------------------------------------------------------------
    # CSS – Cloud Search Service (Elasticsearch Clusters)
    # ------------------------------------------------------------------

    def list_css_clusters(self) -> Optional[List[Dict]]:
        """GET /v1.0/{project_id}/clusters"""
        return self._get_list(
            f"{self._css_base}/v1.0/{self.project_id}/clusters",
            result_key="clusters",
        )

    def get_css_cluster_detail(self, cluster_id: str) -> Optional[Dict]:
        """GET /v1.0/{project_id}/clusters/{cluster_id}"""
        data = self._get(f"{self._css_base}/v1.0/{self.project_id}/clusters/{cluster_id}")
        return data.get("cluster", data) if data else None

    # ------------------------------------------------------------------
    # DCS – Distributed Cache Service (Redis / Memcache)
    # ------------------------------------------------------------------

    def list_dcs_instances(self, status: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v2/{project_id}/instances"""
        params: Dict[str, Any] = {}
        if status:
            params["status"] = status
        return self._get_list(
            f"{self._dcs_base}/v2/{self.project_id}/instances",
            result_key="instances",
            params=params or None,
        )

    # ------------------------------------------------------------------
    # CBR – Cloud Backup and Recovery (Vaults & Backups)
    # ------------------------------------------------------------------

    def list_cbr_vaults(self) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/vaults"""
        return self._get_list(
            f"{self._cbr_base}/v3/{self.project_id}/vaults",
            result_key="vaults",
        )

    def list_cbr_backups(self, vault_id: Optional[str] = None) -> Optional[List[Dict]]:
        """GET /v3/{project_id}/backups"""
        params: Dict[str, Any] = {}
        if vault_id:
            params["vault_id"] = vault_id
        return self._get_list(
            f"{self._cbr_base}/v3/{self.project_id}/backups",
            result_key="backups",
            params=params or None,
        )


# ---------------------------------------------------------------------------
# Global singleton client
# ---------------------------------------------------------------------------

_client: Optional[OTCInventoryClient] = None


def get_client() -> OTCInventoryClient:
    global _client
    if _client:
        return _client

    cloud_profile = os.getenv("OS_CLOUD", "otc")
    config = load_clouds_yaml(cloud_profile)

    required = ["auth_url", "username", "password", "domain_name", "project_name"]
    missing = [f for f in required if not config.get(f)]
    if missing:
        raise ValueError(
            f"Missing required fields in clouds.yaml for profile '{cloud_profile}': {', '.join(missing)}"
        )

    logger.info(
        f"Initialising OTC Inventory Client – project: {config['project_name']} "
        f"(profile: {cloud_profile}, region: {config['region']})"
    )
    client = OTCInventoryClient(
        auth_url=config["auth_url"],
        username=config["username"],
        password=config["password"],
        domain_name=config["domain_name"],
        project_name=config["project_name"],
        region=config["region"],
    )

    if not client.authenticate():
        raise RuntimeError("Initial authentication failed. Check credentials in clouds.yaml.")

    _client = client
    return _client


def _ok(data: Optional[Any], key: Optional[str] = None) -> str:
    """Serialize API result to JSON string with consistent error handling."""
    if data is None:
        return json.dumps({"error": "API call returned no data. Check server logs."})
    return json.dumps(data if key is None else {key: data}, indent=2)


# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("OTC Telekom Cloud – Read-Only Inventory")


# ── Project / IAM ───────────────────────────────────────────────────────────

@mcp.tool()
def list_available_projects() -> str:
    """
    List all OTC projects available to the configured user (domain scope).

    Returns a JSON list of project objects including: id, name, enabled, domain_id.
    """
    try:
        client = get_client()
        return _ok(client.list_projects(), "projects")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def set_active_project(project_name: str) -> str:
    """
    Switch the active project for all subsequent API calls and re-authenticate.

    Parameters
    ----------
    project_name : str
        The exact project name as it appears in IAM (e.g. 'eu-de_myproject').
    """
    try:
        client = get_client()
        if client.set_project(project_name):
            return json.dumps({"status": "ok", "active_project": project_name, "project_id": client.project_id})
        return json.dumps({"status": "error", "message": f"Failed to switch to project '{project_name}'."})
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def get_active_project() -> str:
    """Return the currently active project name and ID."""
    try:
        client = get_client()
        return json.dumps({"project_name": client.project_name, "project_id": client.project_id, "region": client.region})
    except Exception as exc:
        return f"Error: {exc}"


# ── ECS – Compute Instances ─────────────────────────────────────────────────

@mcp.tool()
def list_compute_instances(status: Optional[str] = None) -> str:
    """
    List all ECS compute instances (virtual machines) in the active project.

    Parameters
    ----------
    status : str, optional
        Filter by instance status: ACTIVE, SHUTOFF, ERROR, PAUSED, SHELVED, etc.

    Returns
    -------
    JSON with 'servers' array. Key fields per server: id, name, status, flavor,
    addresses, key_name, availability_zone, created, updated, metadata.
    """
    try:
        client = get_client()
        return _ok(client.list_instances(status=status), "servers")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def get_compute_instance_detail(server_id: str) -> str:
    """
    Retrieve full details of a single ECS instance.

    Parameters
    ----------
    server_id : str
        UUID of the compute instance (from list_compute_instances).
    """
    try:
        client = get_client()
        return _ok(client.get_instance_detail(server_id))
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_compute_flavors() -> str:
    """
    List all available ECS flavors (instance types / machine sizes).

    Returns JSON with 'flavors' array. Key fields: id, name, vcpus, ram, disk, swap.
    """
    try:
        client = get_client()
        return _ok(client.list_flavors(), "flavors")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_availability_zones() -> str:
    """List all availability zones in the current region."""
    try:
        client = get_client()
        return _ok(client.list_availability_zones(), "availability_zones")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_keypairs() -> str:
    """List all SSH key pairs registered in the project."""
    try:
        client = get_client()
        return _ok(client.list_keypairs(), "keypairs")
    except Exception as exc:
        return f"Error: {exc}"


# ── EVS – Volumes (Block Storage / Disks) ───────────────────────────────────

@mcp.tool()
def list_volumes(status: Optional[str] = None) -> str:
    """
    List all EVS block storage volumes (disks) in the project.

    Parameters
    ----------
    status : str, optional
        Filter by volume status: available, in-use, error, creating, deleting, etc.

    Returns
    -------
    JSON with 'volumes' array. Key fields: id, name, status, size, volume_type,
    availability_zone, attachments, bootable, encrypted, created_at.
    """
    try:
        client = get_client()
        return _ok(client.list_volumes(status=status), "volumes")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def get_volume_detail(volume_id: str) -> str:
    """
    Retrieve full details of a single EVS volume.

    Parameters
    ----------
    volume_id : str
        UUID of the volume (from list_volumes).
    """
    try:
        client = get_client()
        return _ok(client.get_volume_detail(volume_id))
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_volume_types() -> str:
    """List all EVS volume types available in the project (e.g. SSD, SAS, SATA)."""
    try:
        client = get_client()
        return _ok(client.list_volume_types(), "volume_types")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_volume_snapshots() -> str:
    """
    List all EVS volume snapshots in the project.

    Returns JSON with 'snapshots' array including: id, name, status, size,
    volume_id, created_at, description.
    """
    try:
        client = get_client()
        return _ok(client.list_snapshots(), "snapshots")
    except Exception as exc:
        return f"Error: {exc}"


# ── VPC – Networking ─────────────────────────────────────────────────────────

@mcp.tool()
def list_vpcs() -> str:
    """
    List all Virtual Private Clouds (VPCs) in the project.

    Returns JSON with 'vpcs' array. Key fields: id, name, cidr, status,
    enable_shared_snat, description.
    """
    try:
        client = get_client()
        return _ok(client.list_vpcs(), "vpcs")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def get_vpc_detail(vpc_id: str) -> str:
    """
    Retrieve details of a specific VPC.

    Parameters
    ----------
    vpc_id : str
        UUID of the VPC (from list_vpcs).
    """
    try:
        client = get_client()
        return _ok(client.get_vpc_detail(vpc_id))
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_subnets(vpc_id: Optional[str] = None) -> str:
    """
    List subnets in the project, optionally filtered by VPC.

    Parameters
    ----------
    vpc_id : str, optional
        UUID of the VPC to filter subnets by.

    Returns
    -------
    JSON with 'subnets' array. Key fields: id, name, cidr, vpc_id, gateway_ip,
    availability_zone, dhcp_enable, dns_list, status.
    """
    try:
        client = get_client()
        return _ok(client.list_subnets(vpc_id=vpc_id), "subnets")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_security_groups() -> str:
    """
    List all security groups in the project.

    Returns JSON with 'security_groups' array. Key fields: id, name, vpc_id,
    description, security_group_rules (summary).
    """
    try:
        client = get_client()
        return _ok(client.list_security_groups(), "security_groups")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_security_group_rules(security_group_id: Optional[str] = None) -> str:
    """
    List security group rules, optionally filtered by security group.

    Parameters
    ----------
    security_group_id : str, optional
        UUID of the security group to filter rules by.
    """
    try:
        client = get_client()
        return _ok(client.list_security_group_rules(security_group_id=security_group_id), "security_group_rules")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_floating_ips() -> str:
    """
    List all floating (public) IP addresses in the project.

    Returns JSON with 'floatingips' array. Key fields: id, floating_ip_address,
    fixed_ip_address, port_id, status, tenant_id.
    """
    try:
        client = get_client()
        return _ok(client.list_floating_ips(), "floatingips")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_vpc_peerings() -> str:
    """
    List all VPC peering connections in the project.

    Returns JSON with 'peerings' array showing cross-VPC or cross-tenant connections.
    """
    try:
        client = get_client()
        return _ok(client.list_vpc_peerings(), "peerings")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_vpc_routes(vpc_id: Optional[str] = None) -> str:
    """
    List VPC custom routes, optionally filtered by VPC.

    Parameters
    ----------
    vpc_id : str, optional
        UUID of the VPC to filter routes by.
    """
    try:
        client = get_client()
        return _ok(client.list_routes(vpc_id=vpc_id), "routes")
    except Exception as exc:
        return f"Error: {exc}"


# ── OBS – Object Storage ─────────────────────────────────────────────────────

@mcp.tool()
def list_obs_buckets() -> str:
    """
    List all OBS (Object Storage Service) buckets owned by the account.

    Returns JSON with 'buckets' array. Each entry includes: name, creation_date.
    Note: OBS uses the S3-compatible API; authentication is via IAM token.
    """
    try:
        client = get_client()
        return _ok(client.list_buckets(), "buckets")
    except Exception as exc:
        return f"Error: {exc}"


# ── ELB – Load Balancers ─────────────────────────────────────────────────────

@mcp.tool()
def list_load_balancers() -> str:
    """
    List all ELB (Elastic Load Balancer) instances in the project.

    Returns JSON with 'loadbalancers' array. Key fields: id, name, description,
    vip_address, vip_subnet_id, provisioning_status, operating_status,
    guaranteed (true = dedicated LB).
    """
    try:
        client = get_client()
        return _ok(client.list_loadbalancers(), "loadbalancers")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_lb_listeners(loadbalancer_id: Optional[str] = None) -> str:
    """
    List ELB listeners, optionally filtered by load balancer.

    Parameters
    ----------
    loadbalancer_id : str, optional
        UUID of the load balancer to filter listeners by.

    Returns
    -------
    JSON with 'listeners' array. Key fields: id, name, protocol, protocol_port,
    default_pool_id, loadbalancers, connection_limit.
    """
    try:
        client = get_client()
        return _ok(client.list_lb_listeners(loadbalancer_id=loadbalancer_id), "listeners")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_lb_pools(loadbalancer_id: Optional[str] = None) -> str:
    """
    List ELB backend server pools, optionally filtered by load balancer.

    Parameters
    ----------
    loadbalancer_id : str, optional
        UUID of the load balancer.

    Returns
    -------
    JSON with 'pools' array. Key fields: id, name, protocol, lb_algorithm,
    healthmonitor_id, members (count), session_persistence.
    """
    try:
        client = get_client()
        return _ok(client.list_lb_pools(loadbalancer_id=loadbalancer_id), "pools")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_lb_pool_members(pool_id: str) -> str:
    """
    List backend members in a specific ELB pool.

    Parameters
    ----------
    pool_id : str
        UUID of the backend pool (from list_lb_pools).

    Returns
    -------
    JSON with 'members' array. Key fields: id, address, protocol_port,
    weight, operating_status, subnet_id.
    """
    try:
        client = get_client()
        return _ok(client.list_lb_members(pool_id), "members")
    except Exception as exc:
        return f"Error: {exc}"


# ── DNS – Zones & Record Sets ────────────────────────────────────────────────

@mcp.tool()
def list_dns_zones(zone_type: Optional[str] = None) -> str:
    """
    List DNS zones managed by OTC DNS service.

    Parameters
    ----------
    zone_type : str, optional
        'public' for public DNS zones, 'private' for private (VPC-internal) zones.
        Leave empty to return both types.

    Returns
    -------
    JSON with 'zones' array. Key fields: id, name, zone_type, status,
    record_num, ttl, description.
    """
    try:
        client = get_client()
        return _ok(client.list_dns_zones(zone_type=zone_type), "zones")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_dns_recordsets(zone_id: str) -> str:
    """
    List all record sets within a DNS zone.

    Parameters
    ----------
    zone_id : str
        UUID of the DNS zone (from list_dns_zones).

    Returns
    -------
    JSON with 'recordsets' array. Key fields: id, name, type, ttl, records, status.
    """
    try:
        client = get_client()
        return _ok(client.list_dns_recordsets(zone_id), "recordsets")
    except Exception as exc:
        return f"Error: {exc}"


# ── NAT – NAT Gateways ───────────────────────────────────────────────────────

@mcp.tool()
def list_nat_gateways() -> str:
    """
    List all NAT gateways in the project.

    Returns JSON with 'nat_gateways' array. Key fields: id, name, description,
    spec, status, admin_state_up, vpc_id, subnet_id.
    """
    try:
        client = get_client()
        return _ok(client.list_nat_gateways(), "nat_gateways")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_snat_rules(nat_gateway_id: Optional[str] = None) -> str:
    """
    List SNAT rules, optionally filtered by NAT gateway.

    Parameters
    ----------
    nat_gateway_id : str, optional
        UUID of the NAT gateway.
    """
    try:
        client = get_client()
        return _ok(client.list_snat_rules(nat_gateway_id=nat_gateway_id), "snat_rules")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_dnat_rules(nat_gateway_id: Optional[str] = None) -> str:
    """
    List DNAT rules, optionally filtered by NAT gateway.

    Parameters
    ----------
    nat_gateway_id : str, optional
        UUID of the NAT gateway.
    """
    try:
        client = get_client()
        return _ok(client.list_dnat_rules(nat_gateway_id=nat_gateway_id), "dnat_rules")
    except Exception as exc:
        return f"Error: {exc}"


# ── VPN ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def list_vpn_gateways() -> str:
    """
    List all VPN gateways in the project.

    Returns JSON with 'vpn_gateways' array. Key fields: id, name, status,
    local_subnets, bgp_asn, vpc_id, connect_subnet.
    """
    try:
        client = get_client()
        return _ok(client.list_vpn_services(), "vpn_gateways")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_vpn_connections() -> str:
    """
    List all VPN connections (IPsec tunnels) in the project.

    Returns JSON with 'vpn_connections' array. Key fields: id, name, status,
    vgw_id, peer_subnets, peer_address, psk (masked by OTC).
    """
    try:
        client = get_client()
        return _ok(client.list_vpn_connections(), "vpn_connections")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_vpn_customer_gateways() -> str:
    """
    List all VPN customer gateways (remote endpoints) in the project.

    Returns JSON with 'customer_gateways' array. Key fields: id, name,
    ip, bgp_asn, created_at.
    """
    try:
        client = get_client()
        return _ok(client.list_vpn_endpoint_groups(), "customer_gateways")
    except Exception as exc:
        return f"Error: {exc}"


# ── RDS – Relational Databases ───────────────────────────────────────────────

@mcp.tool()
def list_rds_instances() -> str:
    """
    List all RDS (Relational Database Service) instances in the project.

    Returns JSON with 'instances' array. Key fields: id, name, status,
    type (Single/Ha/ReadReplica), datastore (engine + version), flavor_ref,
    volume (type + size), backup_strategy, created.
    """
    try:
        client = get_client()
        return _ok(client.list_rds_instances(), "instances")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_rds_backups(instance_id: Optional[str] = None) -> str:
    """
    List RDS automated and manual backups.

    Parameters
    ----------
    instance_id : str, optional
        UUID of the RDS instance to filter backups by.
    """
    try:
        client = get_client()
        return _ok(client.list_rds_backups(instance_id=instance_id), "backups")
    except Exception as exc:
        return f"Error: {exc}"


# ── CCE – Kubernetes Clusters ────────────────────────────────────────────────

@mcp.tool()
def list_cce_clusters() -> str:
    """
    List all CCE (Cloud Container Engine / Kubernetes) clusters in the project.

    Returns JSON with 'items' array. Key fields: metadata.uid, metadata.name,
    spec.type, spec.flavor, spec.version, status.phase, spec.hostNetwork.vpc.
    """
    try:
        client = get_client()
        return _ok(client.list_cce_clusters(), "items")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_cce_nodes(cluster_id: str) -> str:
    """
    List all nodes in a CCE cluster.

    Parameters
    ----------
    cluster_id : str
        UUID of the CCE cluster (from list_cce_clusters → metadata.uid).
    """
    try:
        client = get_client()
        return _ok(client.list_cce_nodes(cluster_id), "items")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_cce_node_pools(cluster_id: str) -> str:
    """
    List all node pools in a CCE cluster.

    Parameters
    ----------
    cluster_id : str
        UUID of the CCE cluster.
    """
    try:
        client = get_client()
        return _ok(client.list_cce_node_pools(cluster_id), "items")
    except Exception as exc:
        return f"Error: {exc}"


# ── CSS – Elasticsearch Clusters ────────────────────────────────────────────

@mcp.tool()
def list_css_clusters() -> str:
    """
    List all CSS (Cloud Search Service / Elasticsearch) clusters in the project.

    Returns JSON with 'clusters' array. Key fields: id, name, status,
    datastore (type + version), instances (count + flavor + volume),
    created, updated.
    """
    try:
        client = get_client()
        return _ok(client.list_css_clusters(), "clusters")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def get_css_cluster_detail(cluster_id: str) -> str:
    """
    Retrieve detailed information about a specific CSS cluster.

    Parameters
    ----------
    cluster_id : str
        UUID of the CSS cluster (from list_css_clusters).
    """
    try:
        client = get_client()
        return _ok(client.get_css_cluster_detail(cluster_id))
    except Exception as exc:
        return f"Error: {exc}"


# ── DCS – Cache (Redis / Memcache) ──────────────────────────────────────────

@mcp.tool()
def list_dcs_instances(status: Optional[str] = None) -> str:
    """
    List all DCS (Distributed Cache Service) instances in the project.

    Parameters
    ----------
    status : str, optional
        Filter by status: RUNNING, CREATING, RESTARTING, FLUSHING, UPGRADING, ERROR.

    Returns
    -------
    JSON with 'instances' array. Key fields: instance_id, name, status,
    engine (Redis/Memcache), engine_version, capacity, used_memory,
    ip, port, subnet_id, available_zones.
    """
    try:
        client = get_client()
        return _ok(client.list_dcs_instances(status=status), "instances")
    except Exception as exc:
        return f"Error: {exc}"


# ── CBR – Backups & Vaults ───────────────────────────────────────────────────

@mcp.tool()
def list_cbr_vaults() -> str:
    """
    List all CBR (Cloud Backup and Recovery) vaults in the project.

    Returns JSON with 'vaults' array. Key fields: id, name, object_type
    (server/disk/turbo), billing.size, billing.used, resources (list of
    protected resources), auto_bind, auto_expand.
    """
    try:
        client = get_client()
        return _ok(client.list_cbr_vaults(), "vaults")
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def list_cbr_backups(vault_id: Optional[str] = None) -> str:
    """
    List CBR backups, optionally filtered by vault.

    Parameters
    ----------
    vault_id : str, optional
        UUID of the CBR vault to filter backups by.

    Returns
    -------
    JSON with 'backups' array. Key fields: id, name, status, resource_id,
    resource_type, resource_name, created_at, checkpoint_id, size.
    """
    try:
        client = get_client()
        return _ok(client.list_cbr_backups(vault_id=vault_id), "backups")
    except Exception as exc:
        return f"Error: {exc}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
