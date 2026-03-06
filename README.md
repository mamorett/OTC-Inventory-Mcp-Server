# OTC Telekom Cloud MCP Server – Read-Only Inventory

A Model Context Protocol (MCP) server that provides a comprehensive, read-only inventory of resources across Open Telekom Cloud (OTC). It allows LLMs to explore and understand your OTC infrastructure including compute, storage, networking, databases, containers, and more.

## Features

- **Multi-Service Coverage**: Support for ECS, EVS, VPC, OBS, ELB, DNS, NAT, VPN, RDS, CCE, CSS, DCS, and CBR.
- **Read-Only**: All operations are GET/list based, ensuring no accidental modifications to your infrastructure.
- **Flexible Authentication**: Uses standard OpenStack `clouds.yaml` configuration.
- **Project Switching**: Easily switch between different projects within your domain.
- **Pagination Support**: Automatically handles paginated API responses.

## Prerequisites

- Python 3.10 or higher.
- A valid OTC account and credentials.

## Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/otc-inventory-mcp-server.git
cd otc-inventory-mcp-server

# Install dependencies
pip install fastmcp requests pyyaml
```

## Configuration

The server relies on a `clouds.yaml` file for authentication. It searches for this file in the following locations (in order):

1. The path specified by the `OS_CLIENT_CONFIG_FILE` environment variable.
2. The current working directory.
3. `~/.config/openstack/clouds.yaml`
4. `/etc/openstack/clouds.yaml`

### Example `clouds.yaml`

```yaml
clouds:
  otc:
    region_name: "eu-de"
    auth:
      auth_url: "https://iam.eu-de.otc.t-systems.com/v3"
      username: "your-username"
      password: "your-password"
      project_name: "eu-de_yourproject"
      user_domain_name: "OTC000000000010000xxxxx"
```

You can specify which cloud profile to use by setting the `OS_CLOUD` environment variable (defaults to `otc`).

## Usage

### Running the server

```bash
python otc_inventory_mcp_server.py
```

### Integration with Claude Desktop

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "otc-inventory": {
      "command": "python",
      "args": ["/path/to/otc_inventory_mcp_server.py"],
      "env": {
        "OS_CLOUD": "otc",
        "OS_CLIENT_CONFIG_FILE": "/path/to/your/clouds.yaml"
      }
    }
  }
}
```

## Available Tools

The server provides the following tools to explore your OTC inventory:

### Project / IAM
- `list_available_projects()`: List all OTC projects available to the configured user.
- `set_active_project(project_name)`: Switch the active project for subsequent API calls.
- `get_active_project()`: Return the currently active project name, ID, and region.

### ECS – Compute
- `list_compute_instances(status)`: List virtual machines (can filter by status: ACTIVE, SHUTOFF, etc.).
- `get_compute_instance_detail(server_id)`: Retrieve full details of a single ECS instance.
- `list_compute_flavors()`: List all available instance types/sizes.
- `list_availability_zones()`: List all availability zones in the current region.
- `list_keypairs()`: List registered SSH key pairs.

### EVS – Block Storage
- `list_volumes(status)`: List block storage volumes/disks.
- `get_volume_detail(volume_id)`: Retrieve full details of a single volume.
- `list_volume_types()`: List available volume types (SSD, SAS, SATA).
- `list_volume_snapshots()`: List all volume snapshots.

### VPC – Networking
- `list_vpcs()`: List Virtual Private Clouds.
- `get_vpc_detail(vpc_id)`: Retrieve details of a specific VPC.
- `list_subnets(vpc_id)`: List subnets, optionally filtered by VPC.
- `list_security_groups()`: List all security groups.
- `list_security_group_rules(security_group_id)`: List rules, optionally filtered by security group.
- `list_floating_ips()`: List all public IP addresses.
- `list_vpc_peerings()`: List all VPC peering connections.
- `list_vpc_routes(vpc_id)`: List custom routes, optionally filtered by VPC.

### OBS – Object Storage
- `list_obs_buckets()`: List all S3-compatible object storage buckets.

### ELB – Load Balancing
- `list_load_balancers()`: List all Elastic Load Balancers.
- `list_lb_listeners(loadbalancer_id)`: List listeners, optionally filtered by LB.
- `list_lb_pools(loadbalancer_id)`: List backend server pools, optionally filtered by LB.
- `list_lb_pool_members(pool_id)`: List backend members in a specific pool.

### DNS
- `list_dns_zones(zone_type)`: List public or private DNS zones.
- `list_dns_recordsets(zone_id)`: List all record sets within a DNS zone.

### NAT Gateway
- `list_nat_gateways()`: List all NAT gateways.
- `list_snat_rules(nat_gateway_id)`: List SNAT rules.
- `list_dnat_rules(nat_gateway_id)`: List DNAT rules.

### VPN
- `list_vpn_gateways()`: List all VPN gateways.
- `list_vpn_connections()`: List all IPsec tunnels.
- `list_vpn_customer_gateways()`: List all remote endpoints (customer gateways).

### RDS – Databases
- `list_rds_instances()`: List all Relational Database Service instances.
- `list_rds_backups(instance_id)`: List automated and manual backups.

### CCE – Kubernetes
- `list_cce_clusters()`: List all Cloud Container Engine clusters.
- `list_cce_nodes(cluster_id)`: List all nodes in a CCE cluster.
- `list_cce_node_pools(cluster_id)`: List all node pools in a CCE cluster.

### CSS – Cloud Search
- `list_css_clusters()`: List all Elasticsearch clusters.
- `get_css_cluster_detail(cluster_id)`: Retrieve detailed information about a CSS cluster.

### DCS – Distributed Cache
- `list_dcs_instances(status)`: List Redis or Memcache instances.

### CBR – Backup & Recovery
- `list_cbr_vaults()`: List all backup vaults.
- `list_cbr_backups(vault_id)`: List backups, optionally filtered by vault.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
