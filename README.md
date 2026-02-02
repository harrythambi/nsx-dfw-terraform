# NSX-T Distributed Firewall Terraform Module

A comprehensive Terraform module for managing VMware NSX-T Distributed Firewall (DFW) components using YAML/JSON configuration files. This module provides a declarative, GitOps-friendly approach to NSX-T microsegmentation.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration Guide](#configuration-guide)
  - [Security Groups](#security-groups)
  - [Services](#services)
  - [Security Policies](#security-policies)
- [YAML Reference](#yaml-reference)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Features

### Security Groups (`nsxt_policy_group`)

**Dynamic Criteria (Membership Criteria tab):**
- **Tag-based criteria** - Match VMs by NSX tags
- **Name-based criteria** - Match VMs by display name
- **OS Name criteria** - Match VMs by operating system
- **Computer Name criteria** - Match VMs by computer/hostname
- **IP Address expressions** - Static IP addresses, CIDR ranges
- **MAC Address expressions** - Static MAC addresses
- **Path expressions** - Reference other NSX objects by path
- **External ID expressions** - Match by external identifiers
- **Segment/SegmentPort criteria** - Match by network segment tags
- **Complex criteria groups** - AND/OR conjunctions between criteria

**Static Members (Members tab):**
- **Virtual Machines** - Select specific VMs by path
- **NSX Segments** - Select specific network segments
- **Segment Ports** - Select specific segment ports
- **Nested Groups** - Include other security groups
- **VIFs** - Select virtual interfaces
- **Physical Servers** - Select physical servers
- **Distributed Port Groups** - Select vSphere port groups
- **Distributed Ports** - Select vSphere distributed ports

### Services (`nsxt_policy_service`)
- **L4 Port Set entries** - TCP/UDP port definitions
- **ICMP entries** - ICMP type/code definitions
- **IP Protocol entries** - Raw IP protocol numbers
- **IGMP entries** - Multicast group membership
- **EtherType entries** - Layer 2 protocol types
- **Algorithm entries** - ALG services (FTP, TFTP, etc.)
- **Nested service entries** - Compose services from other services
- **Predefined service lookup** - Reference built-in NSX services

### Security Policies (`nsxt_policy_security_policy`)
- **ALLOW, DROP, REJECT actions** - Full action support
- **Category-based ordering** - Emergency, Infrastructure, Environment, Application
- **Auto-calculated sequence numbers** - Smart ordering within categories
- **Explicit sequence override** - Manual sequence number control
- **Collision detection** - Warns on duplicate sequence numbers
- **Reference validation** - Clear error messages for invalid references
- **Rule-level scope and tags** - Fine-grained rule configuration
- **"ANY" keyword support** - Explicit any match (case-insensitive)
- **Multitenancy support** - NSX-T project context

## Architecture

```
nsx-dfw-terraform/
├── main.tf                 # Root module - orchestrates submodules
├── variables.tf            # Input variables (NSX credentials, paths, etc.)
├── outputs.tf              # Output values (resource paths)
├── locals.tf               # Data processing and validation logic
├── provider.tf             # NSX-T provider configuration
├── versions.tf             # Terraform version constraints
├── data/                   # YAML configuration files
│   ├── security_groups.yaml
│   ├── services.yaml
│   └── security_policies.yaml
├── modules/
│   ├── security_groups/    # Security group resource module
│   ├── services/           # Service resource module
│   └── security_policies/  # Security policy resource module
└── schemas/                # JSON schemas for validation
```

### Data Flow

```
YAML Files → locals.tf (parsing/validation) → Submodules → NSX-T API
                    ↓
         - Duplicate detection
         - Sequence number calculation
         - Reference resolution
         - Path generation
```

## Prerequisites

- **Terraform** >= 1.0.0
- **VMware NSX-T** >= 3.4.0
- **NSX-T Terraform Provider** >= 3.4.0
- NSX-T Manager credentials with appropriate permissions

## Quick Start

### 1. Clone and Configure

```bash
git clone <repository-url>
cd nsx-dfw-terraform
```

### 2. Create terraform.tfvars

```hcl
# NSX-T Manager Connection
nsx_manager_host         = "nsx-manager.example.com"
nsx_username             = "admin"
nsx_password             = "your-password"
nsx_allow_unverified_ssl = true  # Set to false in production

# Optional: Custom data file paths
security_groups_file     = "data/security_groups.yaml"
services_file            = "data/services.yaml"
security_policies_file   = "data/security_policies.yaml"
```

### 3. Initialize and Apply

```bash
terraform init
terraform plan
terraform apply
```

## Configuration Guide

### Security Groups

Security groups define which workloads are included in firewall rules. Edit `data/security_groups.yaml`:

```yaml
security_groups:
  # Tag-based group
  - name: web-servers
    display_name: "Web Servers"
    description: "All web server VMs"
    criteria:
      - conditions:
          - key: Tag
            member_type: VirtualMachine
            operator: EQUALS
            value: "web|tier"

  # IP Address-based group
  - name: trusted-networks
    display_name: "Trusted Networks"
    criteria:
      - ip_addresses:
          - "10.0.0.0/8"
          - "192.168.1.100-192.168.1.200"

  # Multiple criteria with OR conjunction
  - name: db-servers
    display_name: "Database Servers"
    criteria:
      - conditions:
          - key: Tag
            value: "database|tier"
      - conditions:
          - key: Tag
            value: "production|environment"
    conjunction: "OR"
```

#### Supported Criteria Types

| Type | Description | Example |
|------|-------------|---------|
| `conditions` | Tag, Name, OSName, ComputerName matching | `key: Tag, value: "web\|tier"` |
| `ip_addresses` | IP addresses, CIDR, ranges | `["10.0.0.0/8", "192.168.1.1"]` |
| `mac_addresses` | MAC address matching | `["00:50:56:xx:xx:xx"]` |
| `paths` | Direct NSX object paths | `["/infra/domains/default/groups/existing"]` |
| `external_ids` | External identifier matching | `["vm-123", "vm-456"]` |

#### Condition Keys

| Key | Member Types | Description |
|-----|--------------|-------------|
| `Tag` | VirtualMachine, Segment, SegmentPort | NSX tag matching |
| `Name` | VirtualMachine | VM display name |
| `OSName` | VirtualMachine | Operating system name |
| `ComputerName` | VirtualMachine | Computer/hostname |

#### Operators

- `EQUALS` - Exact match (default)
- `CONTAINS` - Substring match
- `STARTSWITH` - Prefix match
- `ENDSWITH` - Suffix match
- `NOTEQUALS` - Negation

#### Static Members

In addition to dynamic criteria, you can add static members directly by path. This corresponds to the "Members" tab in the NSX UI.

```yaml
security_groups:
  # Static member selection
  - name: selected-resources
    display_name: "Selected Resources"
    description: "Manually selected VMs and segments"
    members:
      # Virtual Machines (from NSX Inventory)
      virtual_machines:
        - "/infra/realized-state/enforcement-points/default/virtual-machines/vm-123"
        - "/infra/realized-state/enforcement-points/default/virtual-machines/vm-456"

      # NSX Segments
      segments:
        - "/infra/segments/web-segment"
        - "/infra/segments/app-segment"

      # Segment Ports
      segment_ports:
        - "/infra/segments/web-segment/ports/port-001"

      # Nested Groups (by name or path)
      groups:
        - web-servers                    # Reference by name
        - "/infra/domains/default/groups/existing-group"  # Or by path

      # Additional member types
      # vifs: []
      # physical_servers: []
      # distributed_port_groups: []
      # distributed_ports: []
```

| Member Type | Description | Path Format |
|-------------|-------------|-------------|
| `virtual_machines` | Virtual machines | `/infra/realized-state/enforcement-points/default/virtual-machines/<vm-id>` |
| `segments` | NSX segments | `/infra/segments/<segment-name>` |
| `segment_ports` | Segment ports | `/infra/segments/<segment>/ports/<port-id>` |
| `groups` | Nested security groups | Name or `/infra/domains/<domain>/groups/<group-name>` |
| `vifs` | Virtual interfaces | VIF paths |
| `physical_servers` | Physical servers | Physical server paths |
| `distributed_port_groups` | vSphere DPGs | DPG paths |
| `distributed_ports` | vSphere distributed ports | Distributed port paths |

**Finding Object Paths:**
- **VMs**: NSX Manager → Inventory → Virtual Machines → Select VM → Copy path from URL/API
- **Segments**: NSX Manager → Networking → Segments → Use segment ID
- **Groups**: NSX Manager → Inventory → Groups → Use group name or path

### Services

Services define the protocols and ports for firewall rules. Edit `data/services.yaml`:

```yaml
services:
  # TCP/UDP ports
  - name: web-services
    display_name: "Web Services"
    l4_port_set_entries:
      - display_name: "HTTP"
        protocol: TCP
        destination_ports: ["80"]
      - display_name: "HTTPS"
        protocol: TCP
        destination_ports: ["443"]

  # ICMP
  - name: icmp-ping
    display_name: "ICMP Ping"
    icmp_entries:
      - display_name: "Echo Request"
        protocol: ICMPv4
        icmp_type: "8"
      - display_name: "Echo Reply"
        protocol: ICMPv4
        icmp_type: "0"

  # Port ranges
  - name: ephemeral-ports
    display_name: "Ephemeral Ports"
    l4_port_set_entries:
      - protocol: TCP
        destination_ports: ["49152-65535"]

  # ALG service
  - name: ftp-service
    display_name: "FTP Service"
    algorithm_entries:
      - algorithm: FTP
        destination_port: "21"

  # IP Protocol
  - name: gre-protocol
    display_name: "GRE Protocol"
    ip_protocol_entries:
      - protocol: 47

  # EtherType
  - name: arp-service
    display_name: "ARP Service"
    ether_type_entries:
      - ether_type: 2054
```

#### Service Entry Types

| Entry Type | Description | Required Fields |
|------------|-------------|-----------------|
| `l4_port_set_entries` | TCP/UDP ports | `protocol`, `destination_ports` |
| `icmp_entries` | ICMP types/codes | `protocol` (ICMPv4/ICMPv6) |
| `ip_protocol_entries` | IP protocol numbers | `protocol` (number) |
| `igmp_entries` | IGMP multicast | (none) |
| `ether_type_entries` | Layer 2 protocols | `ether_type` (number) |
| `algorithm_entries` | ALG services | `algorithm`, `destination_port` |
| `nested_service_entries` | Service composition | `service_name` or `nested_service_path` |

#### Predefined Services

Reference built-in NSX services by name in policies:

- DNS, DNS-UDP, NTP, DHCP-Server, DHCP-Client
- HTTP, HTTPS, SSH, RDP, Telnet
- FTP, TFTP, SCP, SFTP
- SMTP, POP3, IMAP (and TLS variants)
- MySQL, MS-SQL-S, Oracle-SQL
- LDAP, LDAPS, Kerberos, AD-Server
- SMB, WINS, NetBIOS services
- SNMP, Syslog, ICMP-ALL
- VPN services (IKE, IPSEC, L2TP, PPTP)
- vMotion, vSphere-Client

### Security Policies

Security policies contain firewall rules. Edit `data/security_policies.yaml`:

```yaml
security_policies:
  # Emergency policy - highest priority
  - name: emergency-policy
    display_name: "Emergency Policy"
    category: Emergency
    stateful: true
    rules:
      - display_name: "Allow Emergency Admin"
        action: ALLOW
        source_groups:
          - trusted-networks    # Reference by name
        destination_groups: []  # Empty = Any
        services: []            # Empty = Any
        logged: true

  # Application tier policy
  - name: web-tier-policy
    display_name: "Web Tier Policy"
    category: Application
    scope:
      - web-servers           # Policy applies to this group
    rules:
      - display_name: "Allow Inbound Web"
        action: ALLOW
        source_groups: []
        destination_groups:
          - web-servers
        services:
          - web-services      # Custom service reference
          - HTTPS             # Predefined service
        logged: true
        direction: IN

      - display_name: "Allow Web to App"
        action: ALLOW
        source_groups:
          - web-servers
        destination_groups:
          - app-servers
        services:
          - custom-app
        direction: OUT

  # Default deny policy
  - name: default-deny
    display_name: "Default Deny"
    category: Application
    rules:
      - display_name: "Deny All"
        action: DROP
        source_groups: []
        destination_groups: []
        services: []
        logged: true
```

#### Policy Categories and Sequence Numbers

Policies are ordered by category, then by sequence number within category:

| Category | Starting Sequence | Use Case |
|----------|-------------------|----------|
| Emergency | 100 | Break-glass access, critical overrides |
| Infrastructure | 1000 | Core services (DNS, NTP, AD) |
| Environment | 2000 | Environment isolation rules |
| Application | 3000 | Application-specific rules |

Sequence numbers are auto-calculated within each category. Override with explicit `sequence_number`.

#### Rule Actions

| Action | Description |
|--------|-------------|
| `ALLOW` | Permit matching traffic |
| `DROP` | Silently discard traffic |
| `REJECT` | Discard with ICMP unreachable |

#### Rule Direction

| Direction | Description |
|-----------|-------------|
| `IN_OUT` | Both directions (default) |
| `IN` | Inbound only |
| `OUT` | Outbound only |

#### Special Values

- **Empty array `[]`** - Matches "any" (source, destination, or service)
- **`["ANY"]`** - Explicit "any" match (case-insensitive)
- **`null`** - Same as empty array, matches "any"

## YAML Reference

### Security Group Schema

```yaml
- name: string              # Unique identifier (required)
  display_name: string      # NSX display name (required)
  description: string       # Optional description

  # Simple criteria (use OR between criteria blocks)
  criteria:
    - conditions:           # Condition-based criteria
        - key: Tag|Name|OSName|ComputerName
          member_type: VirtualMachine|Segment|SegmentPort
          operator: EQUALS|CONTAINS|STARTSWITH|ENDSWITH|NOTEQUALS
          value: string
      ip_addresses:         # IP-based criteria
        - string            # IP, CIDR, or range
      mac_addresses:        # MAC-based criteria
        - string
      paths:                # Path expression
        - string            # NSX object paths
      external_ids:         # External ID expression
        - string

  conjunction: OR|AND       # Between criteria blocks

  # Complex criteria groups (advanced)
  criteria_groups:
    - criteria:
        - conditions: [...]
      conjunction_with_next: OR|AND

  # Nested groups (legacy - use members.groups instead)
  member_groups:
    - string                # Group name or path

  # Static members (Members tab in NSX UI)
  members:
    virtual_machines:       # VM paths
      - string
    segments:               # Segment paths
      - string
    segment_ports:          # Segment port paths
      - string
    groups:                 # Nested group names or paths
      - string
    vifs:                   # VIF paths
      - string
    physical_servers:       # Physical server paths
      - string
    distributed_port_groups: # vSphere DPG paths
      - string
    distributed_ports:      # vSphere distributed port paths
      - string

  # Identity-based (Active Directory)
  extended_criteria:
    - identity_groups:
        - distinguished_name: string
          domain_base_distinguished_name: string
          sid: string

  # Metadata
  tags:
    - scope: string
      tag: string
```

### Service Schema

```yaml
- name: string              # Unique identifier (required)
  display_name: string      # NSX display name (required)
  description: string       # Optional description

  l4_port_set_entries:
    - display_name: string
      protocol: TCP|UDP
      destination_ports:
        - string            # Port or range (e.g., "80", "8080-8090")
      source_ports:
        - string

  icmp_entries:
    - display_name: string
      protocol: ICMPv4|ICMPv6
      icmp_type: string     # ICMP type number
      icmp_code: string     # ICMP code number

  ip_protocol_entries:
    - display_name: string
      protocol: number      # IP protocol number (e.g., 47 for GRE)

  igmp_entries:
    - display_name: string

  ether_type_entries:
    - display_name: string
      ether_type: number    # EtherType (e.g., 2054 for ARP)

  algorithm_entries:
    - display_name: string
      algorithm: FTP|TFTP|...
      destination_port: string
      source_ports:
        - string

  nested_service_entries:
    - display_name: string
      service_name: string  # Reference by name
      nested_service_path: string  # Or direct path

  tags:
    - scope: string
      tag: string
```

### Security Policy Schema

```yaml
- name: string              # Unique identifier (required)
  display_name: string      # NSX display name (required)
  description: string       # Optional description
  category: Emergency|Infrastructure|Environment|Application
  sequence_number: number   # Override auto-calculation
  stateful: boolean         # Default: true
  tcp_strict: boolean       # Default: false
  locked: boolean           # Default: false

  scope:                    # Policy applies to these groups
    - string                # Group name, path, or "ANY"

  rules:
    - display_name: string  # Required
      description: string
      action: ALLOW|DROP|REJECT  # Required
      direction: IN_OUT|IN|OUT   # Default: IN_OUT
      sequence_number: number    # Override auto-calculation

      source_groups:
        - string            # Group name, path, or "ANY"
      destination_groups:
        - string
      services:
        - string            # Service name, predefined, or path

      sources_excluded: boolean       # Negate sources
      destinations_excluded: boolean  # Negate destinations

      profiles:
        - string            # Context profile paths

      ip_version: IPV4|IPV6|IPV4_IPV6  # Default: IPV4_IPV6
      logged: boolean       # Default: false
      disabled: boolean     # Default: false
      notes: string
      log_label: string

      scope:                # Rule-level scope
        - string

      tags:
        - scope: string
          tag: string

  tags:
    - scope: string
      tag: string
```

## Examples

### Three-Tier Application

```yaml
# security_groups.yaml
security_groups:
  - name: web-tier
    display_name: "Web Tier"
    criteria:
      - conditions:
          - key: Tag
            value: "web|tier"

  - name: app-tier
    display_name: "App Tier"
    criteria:
      - conditions:
          - key: Tag
            value: "app|tier"

  - name: db-tier
    display_name: "Database Tier"
    criteria:
      - conditions:
          - key: Tag
            value: "db|tier"
```

```yaml
# security_policies.yaml
security_policies:
  - name: three-tier-policy
    display_name: "Three-Tier Application Policy"
    category: Application
    rules:
      - display_name: "Internet to Web"
        action: ALLOW
        source_groups: []
        destination_groups: [web-tier]
        services: [HTTPS]
        direction: IN
        logged: true

      - display_name: "Web to App"
        action: ALLOW
        source_groups: [web-tier]
        destination_groups: [app-tier]
        services: [custom-app]
        logged: true

      - display_name: "App to Database"
        action: ALLOW
        source_groups: [app-tier]
        destination_groups: [db-tier]
        services: [MySQL]
        logged: true

      - display_name: "Deny All to DB"
        action: DROP
        source_groups: []
        destination_groups: [db-tier]
        services: []
        logged: true
```

### Environment Isolation

```yaml
# security_groups.yaml
security_groups:
  - name: production
    display_name: "Production VMs"
    criteria:
      - conditions:
          - key: Tag
            value: "production|environment"

  - name: development
    display_name: "Development VMs"
    criteria:
      - conditions:
          - key: Tag
            value: "development|environment"
```

```yaml
# security_policies.yaml
security_policies:
  - name: env-isolation
    display_name: "Environment Isolation"
    category: Environment
    rules:
      - display_name: "Block Prod to Dev"
        action: DROP
        source_groups: [production]
        destination_groups: [development]
        services: []
        logged: true

      - display_name: "Block Dev to Prod"
        action: DROP
        source_groups: [development]
        destination_groups: [production]
        services: []
        logged: true
```

## Troubleshooting

### Common Errors

#### "Referenced group 'xxx' not found"

The group name in your policy doesn't match any group defined in `security_groups.yaml`.

**Solution:** Ensure the group name matches exactly (case-sensitive) or use a full NSX path.

#### "Sequence number collision detected"

Two policies have the same sequence number within the same category.

**Solution:** Either let Terraform auto-calculate sequence numbers or ensure explicit `sequence_number` values are unique.

#### "action is REQUIRED on every rule"

A rule is missing the `action` field.

**Solution:** Add `action: ALLOW`, `action: DROP`, or `action: REJECT` to every rule.

#### "Duplicate security group names found"

Multiple groups have the same `name` value.

**Solution:** Ensure all group names are unique.

### Validation

Run `terraform validate` to check configuration syntax:

```bash
terraform validate
```

Run `terraform plan` to preview changes:

```bash
terraform plan
```

### Debug Logging

Enable Terraform debug logging:

```bash
export TF_LOG=DEBUG
terraform apply
```

## Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `nsx_manager_host` | NSX-T Manager hostname/IP | Required |
| `nsx_username` | NSX-T username | Required |
| `nsx_password` | NSX-T password | Required |
| `nsx_allow_unverified_ssl` | Skip TLS verification | `false` |
| `domain` | NSX-T domain | `"default"` |
| `project_id` | NSX-T project for multitenancy | `null` |
| `security_groups_file` | Path to groups YAML | `"data/security_groups.yaml"` |
| `services_file` | Path to services YAML | `"data/services.yaml"` |
| `security_policies_file` | Path to policies YAML | `"data/security_policies.yaml"` |
| `policy_sequence_increment` | Gap between policy sequences | `10` |
| `rule_sequence_start` | Starting rule sequence | `100` |
| `rule_sequence_increment` | Gap between rule sequences | `10` |
| `default_tags` | Tags applied to all resources | `[]` |

## Outputs

| Output | Description |
|--------|-------------|
| `security_group_paths` | Map of group names to NSX paths |
| `security_policy_paths` | Map of policy names to NSX paths |
| `service_paths` | Map of service names to NSX paths |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `terraform fmt` and `terraform validate`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
