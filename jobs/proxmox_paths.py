"""Explicit read-only Proxmox API surface and query fence (stdlib only).

Paths and parameters are reviewed from official Proxmox GET schemas. The literal
surface below deliberately omits consoles, execution/file reads, stateful probes,
guest user sessions and arbitrary snippets. No server-supplied URL can leave this
surface. Query encoding is canonical; encoded resource traversal is refused.
"""

import re
from urllib.parse import parse_qsl, quote, unquote, urlencode


class ProxmoxPathRefused(ValueError):
    """No request was sent because it was outside the reviewed read surface."""


_SURFACE = {
    "/access": {},
    "/access/acl": {},
    "/access/domains": {},
    "/access/domains/{realm}": {},
    "/access/groups": {},
    "/access/groups/{groupid}": {},
    "/access/permissions": {"path": {"type": "string"}, "userid": {"type": "string"}},
    "/access/roles": {},
    "/access/roles/{roleid}": {},
    "/access/users": {"enabled": {"type": "boolean"}, "full": {"type": "boolean"}},
    "/access/users/{userid}": {},
    "/access/users/{userid}/token": {},
    "/access/users/{userid}/token/{tokenid}": {},
    "/cluster": {},
    "/cluster/backup": {},
    "/cluster/backup-info": {},
    "/cluster/backup-info/not-backed-up": {},
    "/cluster/backup/{id}": {},
    "/cluster/backup/{id}/included_volumes": {},
    "/cluster/ceph": {},
    "/cluster/ceph/flags": {},
    "/cluster/ceph/flags/{flag}": {},
    "/cluster/ceph/health-mute": {},
    "/cluster/ceph/metadata": {"scope": {"type": "string", "enum": ["all", "versions"]}},
    "/cluster/ceph/status": {},
    "/cluster/config": {},
    "/cluster/config/apiversion": {},
    "/cluster/config/nodes": {},
    "/cluster/config/qdevice": {},
    "/cluster/config/totem": {},
    "/cluster/firewall": {},
    "/cluster/firewall/aliases": {},
    "/cluster/firewall/aliases/{name}": {},
    "/cluster/firewall/groups": {},
    "/cluster/firewall/groups/{group}": {},
    "/cluster/firewall/groups/{group}/{pos}": {},
    "/cluster/firewall/ipset": {},
    "/cluster/firewall/ipset/{name}": {},
    "/cluster/firewall/ipset/{name}/{cidr}": {},
    "/cluster/firewall/macros": {},
    "/cluster/firewall/options": {},
    "/cluster/firewall/refs": {"type": {"type": "string", "enum": ["alias", "ipset"]}},
    "/cluster/firewall/rules": {},
    "/cluster/firewall/rules/{pos}": {},
    "/cluster/ha": {},
    "/cluster/ha/groups": {},
    "/cluster/ha/groups/{group}": {},
    "/cluster/ha/resources": {"type": {"type": "string", "enum": ["ct", "vm"]}},
    "/cluster/ha/resources/{sid}": {},
    "/cluster/ha/rules": {
        "resource": {"type": "string"},
        "type": {"type": "string", "enum": ["node-affinity", "resource-affinity"]},
    },
    "/cluster/ha/rules/{rule}": {},
    "/cluster/ha/status": {},
    "/cluster/ha/status/current": {},
    "/cluster/ha/status/manager_status": {},
    "/cluster/jobs": {},
    "/cluster/jobs/realm-sync": {},
    "/cluster/jobs/realm-sync/{id}": {},
    "/cluster/log": {"max": {"type": "integer", "minimum": 1}},
    "/cluster/mapping": {},
    "/cluster/mapping/dir": {"check-node": {"type": "string"}},
    "/cluster/mapping/dir/{id}": {},
    "/cluster/mapping/pci": {"check-node": {"type": "string"}},
    "/cluster/mapping/pci/{id}": {},
    "/cluster/mapping/usb": {"check-node": {"type": "string"}},
    "/cluster/mapping/usb/{id}": {},
    "/cluster/metrics": {},
    "/cluster/metrics/server": {},
    "/cluster/metrics/server/{id}": {},
    "/cluster/notifications": {},
    "/cluster/notifications/endpoints": {},
    "/cluster/notifications/endpoints/gotify": {},
    "/cluster/notifications/endpoints/gotify/{name}": {},
    "/cluster/notifications/endpoints/sendmail": {},
    "/cluster/notifications/endpoints/sendmail/{name}": {},
    "/cluster/notifications/endpoints/smtp": {},
    "/cluster/notifications/endpoints/smtp/{name}": {},
    "/cluster/notifications/endpoints/webhook": {},
    "/cluster/notifications/endpoints/webhook/{name}": {},
    "/cluster/notifications/matcher-field-values": {},
    "/cluster/notifications/matcher-fields": {},
    "/cluster/notifications/matchers": {},
    "/cluster/notifications/matchers/{name}": {},
    "/cluster/notifications/targets": {},
    "/cluster/options": {},
    "/cluster/qemu": {},
    "/cluster/qemu/cpu-flags": {
        "accel": {"type": "string", "enum": ["kvm", "tcg"]},
        "arch": {"type": "string", "enum": ["x86_64", "aarch64"]},
    },
    "/cluster/qemu/custom-cpu-models": {},
    "/cluster/qemu/custom-cpu-models/{cputype}": {},
    "/cluster/replication": {},
    "/cluster/replication/{id}": {},
    "/cluster/resources": {"type": {"type": "string", "enum": ["vm", "storage", "node", "sdn"]}},
    "/cluster/sdn": {},
    "/cluster/sdn/controllers": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
        "type": {"type": "string", "enum": ["bgp", "evpn", "faucet", "isis"]},
    },
    "/cluster/sdn/controllers/{controller}": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
    },
    "/cluster/sdn/dns": {"type": {"type": "string", "enum": ["powerdns"]}},
    "/cluster/sdn/dns/{dns}": {},
    "/cluster/sdn/fabrics": {},
    "/cluster/sdn/fabrics/all": {"pending": {"type": "boolean"}, "running": {"type": "boolean"}},
    "/cluster/sdn/fabrics/fabric": {"pending": {"type": "boolean"}, "running": {"type": "boolean"}},
    "/cluster/sdn/fabrics/fabric/{id}": {},
    "/cluster/sdn/fabrics/node": {"pending": {"type": "boolean"}, "running": {"type": "boolean"}},
    "/cluster/sdn/fabrics/node/{fabric_id}": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
    },
    "/cluster/sdn/fabrics/node/{fabric_id}/{node_id}": {},
    "/cluster/sdn/ipams": {"type": {"type": "string", "enum": ["netbox", "phpipam", "pve"]}},
    "/cluster/sdn/ipams/{ipam}": {},
    "/cluster/sdn/ipams/{ipam}/status": {},
    "/cluster/sdn/prefix-lists": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
        "verbose": {"type": "boolean"},
    },
    "/cluster/sdn/prefix-lists/{id}": {},
    "/cluster/sdn/prefix-lists/{id}/entries": {},
    "/cluster/sdn/prefix-lists/{id}/entries/{url_seq}": {},
    "/cluster/sdn/route-maps": {"running": {"type": "boolean"}},
    "/cluster/sdn/route-maps/entries": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
    },
    "/cluster/sdn/route-maps/entries/{route-map-id}": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
    },
    "/cluster/sdn/route-maps/entries/{route-map-id}/entry/{order}": {},
    "/cluster/sdn/vnets": {"pending": {"type": "boolean"}, "running": {"type": "boolean"}},
    "/cluster/sdn/vnets/{vnet}": {"pending": {"type": "boolean"}, "running": {"type": "boolean"}},
    "/cluster/sdn/vnets/{vnet}/firewall": {},
    "/cluster/sdn/vnets/{vnet}/firewall/options": {},
    "/cluster/sdn/vnets/{vnet}/firewall/rules": {},
    "/cluster/sdn/vnets/{vnet}/firewall/rules/{pos}": {},
    "/cluster/sdn/vnets/{vnet}/subnets": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
    },
    "/cluster/sdn/vnets/{vnet}/subnets/{subnet}": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
    },
    "/cluster/sdn/zones": {
        "pending": {"type": "boolean"},
        "running": {"type": "boolean"},
        "type": {"type": "string", "enum": ["evpn", "faucet", "qinq", "simple", "vlan", "vxlan"]},
    },
    "/cluster/sdn/zones/{zone}": {"pending": {"type": "boolean"}, "running": {"type": "boolean"}},
    "/cluster/status": {},
    "/cluster/tasks": {},
    "/nodes": {},
    "/nodes/{node}": {},
    "/nodes/{node}/apt/repositories": {},
    "/nodes/{node}/apt/update": {},
    "/nodes/{node}/apt/versions": {},
    "/nodes/{node}/capabilities": {},
    "/nodes/{node}/capabilities/qemu": {},
    "/nodes/{node}/capabilities/qemu/cpu": {
        "arch": {"type": "string", "enum": ["x86_64", "aarch64"]}
    },
    "/nodes/{node}/capabilities/qemu/cpu-flags": {
        "accel": {"type": "string", "enum": ["kvm", "tcg"]},
        "arch": {"type": "string", "enum": ["x86_64", "aarch64"]},
    },
    "/nodes/{node}/capabilities/qemu/machines": {
        "arch": {"type": "string", "enum": ["x86_64", "aarch64"]}
    },
    "/nodes/{node}/capabilities/qemu/migration": {},
    "/nodes/{node}/ceph": {},
    "/nodes/{node}/ceph/cfg": {},
    "/nodes/{node}/ceph/cfg/db": {},
    "/nodes/{node}/ceph/cfg/raw": {},
    "/nodes/{node}/ceph/cfg/value": {"config-keys": {"type": "string", "maxLength": 4096}},
    "/nodes/{node}/ceph/crush": {},
    "/nodes/{node}/ceph/fs": {},
    "/nodes/{node}/ceph/log": {
        "limit": {"type": "integer", "minimum": 0},
        "start": {"type": "integer", "minimum": 0},
    },
    "/nodes/{node}/ceph/mds": {},
    "/nodes/{node}/ceph/mgr": {},
    "/nodes/{node}/ceph/mon": {},
    "/nodes/{node}/ceph/osd": {},
    "/nodes/{node}/ceph/osd/{osdid}": {},
    "/nodes/{node}/ceph/osd/{osdid}/lv-info": {
        "type": {"type": "string", "enum": ["block", "db", "wal"]}
    },
    "/nodes/{node}/ceph/osd/{osdid}/metadata": {},
    "/nodes/{node}/ceph/pool": {},
    "/nodes/{node}/ceph/pool/{name}": {},
    "/nodes/{node}/ceph/pool/{name}/status": {"verbose": {"type": "boolean"}},
    "/nodes/{node}/ceph/releases": {},
    "/nodes/{node}/ceph/rules": {},
    "/nodes/{node}/ceph/status": {},
    "/nodes/{node}/certificates/info": {},
    "/nodes/{node}/config": {
        "property": {
            "type": "string",
            "enum": [
                "acme",
                "acmedomain0",
                "acmedomain1",
                "acmedomain2",
                "acmedomain3",
                "acmedomain4",
                "acmedomain5",
                "ballooning-target",
                "description",
                "location",
                "startall-onboot-delay",
                "wakeonlan",
            ],
        }
    },
    "/nodes/{node}/disks": {},
    "/nodes/{node}/disks/directory": {},
    "/nodes/{node}/disks/list": {
        "include-partitions": {"type": "boolean"},
        "skipsmart": {"type": "boolean"},
        "type": {"type": "string", "enum": ["unused", "journal_disks"]},
    },
    "/nodes/{node}/disks/lvm": {},
    "/nodes/{node}/disks/lvmthin": {},
    "/nodes/{node}/disks/smart": {"disk": {"type": "string"}, "healthonly": {"type": "boolean"}},
    "/nodes/{node}/disks/zfs": {},
    "/nodes/{node}/disks/zfs/{name}": {},
    "/nodes/{node}/dns": {},
    "/nodes/{node}/firewall": {},
    "/nodes/{node}/firewall/log": {
        "limit": {"type": "integer", "minimum": 0},
        "since": {"type": "integer", "minimum": 0},
        "start": {"type": "integer", "minimum": 0},
        "until": {"type": "integer", "minimum": 0},
    },
    "/nodes/{node}/firewall/options": {},
    "/nodes/{node}/firewall/rules": {},
    "/nodes/{node}/firewall/rules/{pos}": {},
    "/nodes/{node}/hardware/pci": {
        "pci-class-blacklist": {"type": "string"},
        "verbose": {"type": "boolean"},
    },
    "/nodes/{node}/hardware/pci/{pci-id-or-mapping}": {},
    "/nodes/{node}/hardware/pci/{pci-id-or-mapping}/mdev": {},
    "/nodes/{node}/hosts": {},
    "/nodes/{node}/journal": {
        "since": {"type": "integer", "minimum": 0},
        "structured": {"type": "boolean"},
        "until": {"type": "integer", "minimum": 0},
    },
    "/nodes/{node}/lxc": {},
    "/nodes/{node}/lxc/{vmid}": {},
    "/nodes/{node}/lxc/{vmid}/config": {
        "current": {"type": "boolean"},
        "snapshot": {"type": "string", "maxLength": 40},
    },
    "/nodes/{node}/lxc/{vmid}/firewall": {},
    "/nodes/{node}/lxc/{vmid}/firewall/aliases": {},
    "/nodes/{node}/lxc/{vmid}/firewall/aliases/{name}": {},
    "/nodes/{node}/lxc/{vmid}/firewall/ipset": {},
    "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}": {},
    "/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}": {},
    "/nodes/{node}/lxc/{vmid}/firewall/log": {
        "limit": {"type": "integer", "minimum": 0},
        "since": {"type": "integer", "minimum": 0},
        "start": {"type": "integer", "minimum": 0},
        "until": {"type": "integer", "minimum": 0},
    },
    "/nodes/{node}/lxc/{vmid}/firewall/options": {},
    "/nodes/{node}/lxc/{vmid}/firewall/refs": {
        "type": {"type": "string", "enum": ["alias", "ipset"]}
    },
    "/nodes/{node}/lxc/{vmid}/firewall/rules": {},
    "/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}": {},
    "/nodes/{node}/lxc/{vmid}/interfaces": {},
    "/nodes/{node}/lxc/{vmid}/pending": {},
    "/nodes/{node}/lxc/{vmid}/rrddata": {
        "cf": {"type": "string", "enum": ["AVERAGE", "MAX"]},
        "timeframe": {"type": "string", "enum": ["hour", "day", "week", "month", "year"]},
    },
    "/nodes/{node}/lxc/{vmid}/snapshot": {},
    "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}": {},
    "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/config": {},
    "/nodes/{node}/lxc/{vmid}/status": {},
    "/nodes/{node}/lxc/{vmid}/status/current": {},
    "/nodes/{node}/netstat": {},
    "/nodes/{node}/network": {
        "type": {
            "type": "string",
            "enum": [
                "bridge",
                "bond",
                "eth",
                "alias",
                "vlan",
                "fabric",
                "OVSBridge",
                "OVSBond",
                "OVSPort",
                "OVSIntPort",
                "vnet",
                "any_bridge",
                "any_local_bridge",
                "include_sdn",
            ],
        }
    },
    "/nodes/{node}/network/{iface}": {},
    "/nodes/{node}/qemu": {"full": {"type": "boolean"}},
    "/nodes/{node}/qemu/{vmid}": {},
    "/nodes/{node}/qemu/{vmid}/agent": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-fsinfo": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-host-name": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-memory-block-info": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-memory-blocks": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-osinfo": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-time": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-timezone": {},
    "/nodes/{node}/qemu/{vmid}/agent/get-vcpus": {},
    "/nodes/{node}/qemu/{vmid}/agent/info": {},
    "/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces": {},
    "/nodes/{node}/qemu/{vmid}/cloudinit": {},
    "/nodes/{node}/qemu/{vmid}/cloudinit/dump": {
        "type": {"type": "string", "enum": ["user", "network", "meta"]}
    },
    "/nodes/{node}/qemu/{vmid}/config": {
        "current": {"type": "boolean"},
        "snapshot": {"type": "string", "maxLength": 40},
    },
    "/nodes/{node}/qemu/{vmid}/firewall": {},
    "/nodes/{node}/qemu/{vmid}/firewall/aliases": {},
    "/nodes/{node}/qemu/{vmid}/firewall/aliases/{name}": {},
    "/nodes/{node}/qemu/{vmid}/firewall/ipset": {},
    "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}": {},
    "/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}": {},
    "/nodes/{node}/qemu/{vmid}/firewall/log": {
        "limit": {"type": "integer", "minimum": 0},
        "since": {"type": "integer", "minimum": 0},
        "start": {"type": "integer", "minimum": 0},
        "until": {"type": "integer", "minimum": 0},
    },
    "/nodes/{node}/qemu/{vmid}/firewall/options": {},
    "/nodes/{node}/qemu/{vmid}/firewall/refs": {
        "type": {"type": "string", "enum": ["alias", "ipset"]}
    },
    "/nodes/{node}/qemu/{vmid}/firewall/rules": {},
    "/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}": {},
    "/nodes/{node}/qemu/{vmid}/pending": {},
    "/nodes/{node}/qemu/{vmid}/rrddata": {
        "cf": {"type": "string", "enum": ["AVERAGE", "MAX"]},
        "timeframe": {"type": "string", "enum": ["hour", "day", "week", "month", "year"]},
    },
    "/nodes/{node}/qemu/{vmid}/snapshot": {},
    "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}": {},
    "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/config": {},
    "/nodes/{node}/qemu/{vmid}/status": {},
    "/nodes/{node}/qemu/{vmid}/status/current": {},
    "/nodes/{node}/replication": {
        "guest": {"type": "integer", "minimum": 100, "maximum": 999999999}
    },
    "/nodes/{node}/replication/{id}": {},
    "/nodes/{node}/replication/{id}/log": {
        "limit": {"type": "integer", "minimum": 0},
        "start": {"type": "integer", "minimum": 0},
    },
    "/nodes/{node}/replication/{id}/status": {},
    "/nodes/{node}/rrddata": {
        "cf": {"type": "string", "enum": ["AVERAGE", "MAX"]},
        "timeframe": {"type": "string", "enum": ["hour", "day", "week", "month", "year", "decade"]},
    },
    "/nodes/{node}/sdn": {},
    "/nodes/{node}/sdn/fabrics/{fabric}": {},
    "/nodes/{node}/sdn/fabrics/{fabric}/interfaces": {},
    "/nodes/{node}/sdn/fabrics/{fabric}/neighbors": {},
    "/nodes/{node}/sdn/fabrics/{fabric}/routes": {},
    "/nodes/{node}/sdn/vnets/{vnet}": {},
    "/nodes/{node}/sdn/vnets/{vnet}/mac-vrf": {},
    "/nodes/{node}/sdn/zones": {},
    "/nodes/{node}/sdn/zones/{zone}": {},
    "/nodes/{node}/sdn/zones/{zone}/bridges": {},
    "/nodes/{node}/sdn/zones/{zone}/content": {},
    "/nodes/{node}/sdn/zones/{zone}/ip-vrf": {},
    "/nodes/{node}/services": {},
    "/nodes/{node}/services/{service}": {},
    "/nodes/{node}/services/{service}/state": {},
    "/nodes/{node}/status": {},
    "/nodes/{node}/storage": {
        "content": {"type": "string"},
        "enabled": {"type": "boolean"},
        "format": {"type": "boolean"},
        "storage": {"type": "string"},
        "target": {"type": "string"},
    },
    "/nodes/{node}/storage/{storage}": {},
    "/nodes/{node}/storage/{storage}/content": {
        "content": {"type": "string"},
        "vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
    },
    "/nodes/{node}/storage/{storage}/prunebackups": {
        "prune-backups": {"type": "string"},
        "type": {"type": "string", "enum": ["qemu", "lxc"]},
        "vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
    },
    "/nodes/{node}/storage/{storage}/rrddata": {
        "cf": {"type": "string", "enum": ["AVERAGE", "MAX"]},
        "timeframe": {"type": "string", "enum": ["hour", "day", "week", "month", "year"]},
    },
    "/nodes/{node}/storage/{storage}/status": {},
    "/nodes/{node}/subscription": {},
    "/nodes/{node}/syslog": {
        "limit": {"type": "integer", "minimum": 0},
        "service": {"type": "string", "maxLength": 128},
        "since": {"type": "string"},
        "start": {"type": "integer", "minimum": 0},
        "until": {"type": "string"},
    },
    "/nodes/{node}/tasks": {
        "errors": {"type": "boolean"},
        "limit": {"type": "integer", "minimum": 0},
        "since": {"type": "integer"},
        "source": {"type": "string", "enum": ["archive", "active", "all"]},
        "start": {"type": "integer", "minimum": 0},
        "statusfilter": {"type": "string"},
        "typefilter": {"type": "string"},
        "until": {"type": "integer"},
        "userfilter": {"type": "string"},
        "vmid": {"type": "integer", "minimum": 100, "maximum": 999999999},
    },
    "/nodes/{node}/tasks/{upid}": {},
    "/nodes/{node}/tasks/{upid}/log": {
        "download": {"type": "boolean"},
        "limit": {"type": "integer", "minimum": 0},
        "start": {"type": "integer", "minimum": 0},
    },
    "/nodes/{node}/tasks/{upid}/status": {},
    "/nodes/{node}/time": {},
    "/nodes/{node}/version": {},
    "/nodes/{node}/vzdump/defaults": {"storage": {"type": "string"}},
    "/pools": {
        "poolid": {"type": "string"},
        "type": {"type": "string", "enum": ["qemu", "lxc", "storage"]},
    },
    "/pools/{poolid}": {"type": {"type": "string", "enum": ["qemu", "lxc", "storage"]}},
    "/storage": {
        "type": {
            "type": "string",
            "enum": [
                "btrfs",
                "cephfs",
                "cifs",
                "dir",
                "esxi",
                "iscsi",
                "iscsidirect",
                "lvm",
                "lvmthin",
                "nfs",
                "pbs",
                "rbd",
                "zfs",
                "zfspool",
            ],
        }
    },
    "/storage/{storage}": {},
    "/version": {},
}

_ID = r"[A-Za-z0-9][A-Za-z0-9_.:-]*"
_IDENTIFIERS = {
    "vmid": r"[1-9][0-9]{2,8}",
    "pos": r"[0-9]+",
    "order": r"[0-9]+",
    "url_seq": r"[0-9]+",
    "osdid": r"[0-9]+",
    "poolid": r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,2}",
    "userid": r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+",
    "upid": (
        r"UPID:[A-Za-z0-9_.-]+:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Fa-f0-9]+:"
        r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]*:[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+"
        r"(?:![A-Za-z0-9_.-]+)?:"
    ),
    "cidr": r"[A-Za-z0-9:.]+(?:/[0-9]{1,3})?",
}
_RULES = []
for _template, _parameters in _SURFACE.items():
    _pieces = re.split(r"(\{[^}]+\})", _template)
    _pattern = "".join(
        "(?:" + _IDENTIFIERS.get(piece[1:-1], _ID) + ")"
        if piece.startswith("{")
        else re.escape(piece)
        for piece in _pieces
    )
    _RULES.append((re.compile(_pattern), _parameters))


def volume_path(node, storage, volume):
    """Encode only a verified native volume ID inside its metadata GET suffix."""
    identifier = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
    if not all(isinstance(value, str) for value in (node, storage, volume)):
        raise ProxmoxPathRefused("Invalid Proxmox volume identity type")
    if re.fullmatch(identifier, node) is None or re.fullmatch(identifier, storage) is None:
        raise ProxmoxPathRefused("Invalid Proxmox volume endpoint identity")
    prefix = storage + ":"
    if not volume.startswith(prefix):
        raise ProxmoxPathRefused("Proxmox volume storage prefix does not match its endpoint")
    tail = volume[len(prefix) :]
    if re.fullmatch(r"[A-Za-z0-9_.+@:/-]+", tail) is None or any(
        part in ("", ".", "..") for part in tail.split("/")
    ):
        raise ProxmoxPathRefused("Ambiguous Proxmox volume ID")
    return "/nodes/%s/storage/%s/content/%s" % (node, storage, quote(volume, safe=""))


def _volume_resource(resource):
    match = re.fullmatch(
        r"/nodes/([A-Za-z0-9_.-]+)/storage/([A-Za-z0-9_.-]+)/content/(.+)", resource
    )
    if match is None:
        return None
    node, storage, encoded = match.groups()
    if "%" in re.sub(r"%[A-Fa-f0-9]{2}", "", encoded):
        raise ProxmoxPathRefused("Malformed encoded Proxmox volume ID")
    try:
        return volume_path(node, storage, unquote(encoded, errors="strict"))
    except UnicodeDecodeError:
        raise ProxmoxPathRefused("Invalid encoded Proxmox volume ID") from None


def _query_value(name, value, schema):
    if len(value) > schema.get("maxLength", 4096):
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    if "%" in value or "#" in value or any(part in (".", "..") for part in value.split("/")):
        return False
    kind = schema.get("type")
    if kind in ("integer", "number", "boolean"):
        if re.fullmatch(r"[0-9]+", value) is None:
            return False
        number = int(value)
        if kind == "boolean" and number not in (0, 1):
            return False
        if number < schema.get("minimum", 0) or number > schema.get("maximum", 2**63 - 1):
            return False
    if "enum" in schema and value not in [str(item) for item in schema["enum"]]:
        return False
    if name == "disk" and re.fullmatch(r"/dev/[A-Za-z0-9/]+", value) is None:
        return False
    if name == "path" and re.fullmatch(r"/(?:[A-Za-z0-9_.@!:-]+/?)*", value) is None:
        return False
    return True


def fence_path(path):
    """Return the canonical allowed request path; errors never echo untrusted input."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ProxmoxPathRefused("Proxmox API path must be relative to the selected host")
    if any(ord(char) < 32 or ord(char) == 127 for char in path) or "#" in path:
        raise ProxmoxPathRefused("Control characters or fragments in Proxmox path")
    resource, _, query = path.partition("?")
    if resource.startswith("/api2/json/"):
        resource = resource[len("/api2/json") :]
    volume = _volume_resource(resource)
    if volume is not None:
        if query:
            raise ProxmoxPathRefused("Proxmox volume metadata GET does not accept query parameters")
        return volume
    if "%" in resource or "//" in resource or any(p in (".", "..") for p in resource.split("/")):
        raise ProxmoxPathRefused("Encoded or ambiguous Proxmox resource path")
    matches = [params for pattern, params in _RULES if pattern.fullmatch(resource)]
    if len(matches) != 1:
        raise ProxmoxPathRefused("Proxmox resource is outside the reviewed GET surface")
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True) if query else []
    except ValueError:
        raise ProxmoxPathRefused("Malformed Proxmox query") from None
    schema = matches[0]
    seen = set()
    for name, value in pairs:
        if name in seen or name not in schema or not _query_value(name, value, schema[name]):
            raise ProxmoxPathRefused("Proxmox query is outside the reviewed read shape")
        seen.add(name)
    if re.fullmatch(r"/nodes/[^/]+/journal", resource):
        journal = dict(pairs)
        if set(journal) != {"since", "until", "structured"} or journal["structured"] != "1":
            raise ProxmoxPathRefused("Journal GET requires a complete bounded structured range")
        if int(journal["since"]) >= int(journal["until"]):
            raise ProxmoxPathRefused("Journal GET range is empty or reversed")
    if re.fullmatch(r"/nodes/[^/]+/qemu/[0-9]+/cloudinit/dump", resource) and seen != {"type"}:
        raise ProxmoxPathRefused("Generated cloudinit dump requires its native config type")
    return resource + ("?" + urlencode(sorted(pairs)) if pairs else "")


def path_refusal(path):
    try:
        fence_path(path)
    except ProxmoxPathRefused as exc:
        return str(exc)
    return None


def is_allowed_path(path):
    return path_refusal(path) is None
