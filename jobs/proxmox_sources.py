"""Exact read-only Linux configuration query; native source text inside JSON.

The SSH fence accepts only this complete command. Its fixed script opens
configuration files for reading and follows native include directives within
the named configuration roots. Unsafe includes or read limits are errors,
never quietly omitted evidence. It installs nothing on the selected host.
"""

import shlex

CONFIG_SCRIPT = r"""
import glob
import fnmatch
import json
import os
import re
import shlex

systemd_bases = ["/etc/systemd", "/run/systemd", "/usr/local/lib/systemd", "/usr/lib/systemd"]
systemd_names = {"time": "timesyncd.conf", "logging": "journald.conf"}
systemd_paths = {category: [base + "/" + name for base in systemd_bases]
                 for category, name in systemd_names.items()}

roots = {
    "network": ["/etc/network/interfaces", "/etc/network/interfaces.new"],
    "time": ["/etc/chrony/chrony.conf", "/etc/chrony.conf"] + systemd_paths["time"],
    "logging": ["/etc/rsyslog.conf"] + systemd_paths["logging"],
}
patterns = {
    "time": ["/etc/chrony/conf.d/*.conf", "/etc/chrony/sources.d/*.sources"]
            + [path + ".d/*.conf" for path in systemd_paths["time"]],
    "logging": ["/etc/rsyslog.d/*.conf"]
               + [path + ".d/*.conf" for path in systemd_paths["logging"]],
}
allowed = {
    "network": ["/etc/network"],
    "time": ["/etc/chrony", "/etc/chrony.conf", "/run/chrony-dhcp"],
    "logging": ["/etc/rsyslog.conf", "/etc/rsyslog.d"],
}
for category, paths in systemd_paths.items():
    allowed[category] += paths + [path + ".d" for path in paths]
result = {"files": [], "absent": [], "includes": [], "errors": []}
seen = set()
active = set()
size = 0

def masked(path, category):
    if os.path.realpath(path) != "/dev/null":
        return False
    named_path = os.path.abspath(path)
    return any(named_path == root or named_path.startswith(root + ".d/")
               for root in systemd_paths.get(category, []))

def permitted(path, category):
    if masked(path, category):
        return True
    resolved = os.path.realpath(path)
    return any(resolved == root or resolved.startswith(root + "/")
               for root in allowed[category])

def matches(pattern):
    # glob.glob suppresses directory access errors. Enumerate explicitly so
    # denied directories and dangling/cyclic links cannot become empty success.
    candidates = ["/"]
    for component in pattern.split("/")[1:]:
        following = []
        for parent in candidates:
            if glob.has_magic(component):
                try:
                    with os.scandir(parent) as entries:
                        names = [entry.name for entry in entries]
                except (FileNotFoundError, NotADirectoryError):
                    continue
                if len(names) > 4096:
                    raise ValueError("configuration directory budget exhausted")
                names = [name for name in names
                         if (not name.startswith(".") or component.startswith("."))
                         and fnmatch.fnmatchcase(name, component)]
            else:
                names = [component]
            for name in names:
                candidate = os.path.join(parent, name)
                try:
                    os.stat(candidate)
                except FileNotFoundError:
                    if os.path.lexists(candidate):
                        raise ValueError("dangling configuration source link")
                    continue
                following.append(candidate)
        if len(following) > 4096:
            raise ValueError("configuration include inventory budget exhausted")
        candidates = following
    return sorted(candidates)

def expand(pattern, category, source, required=False):
    if not os.path.isabs(pattern):
        pattern = os.path.join(os.path.dirname(source), pattern)
    # Validate before globbing; returned symlinks are validated again.
    if not permitted(pattern, category):
        raise ValueError("configuration include outside approved roots")
    resolved = matches(pattern)
    result["includes"].append({"source": source, "pattern": pattern, "matches": resolved})
    if required and not resolved:
        raise ValueError("required configuration include matched no files")
    for match in resolved:
        visit(match, category, required=True)

def visit(path, category, required=False):
    global size
    if not permitted(path, category):
        raise ValueError("configuration file outside approved roots")
    # Each masked filename is distinct provenance despite sharing /dev/null.
    is_mask = masked(path, category)
    key = (os.path.abspath(path) if is_mask else os.path.realpath(path), category)
    if key in active:
        raise ValueError("configuration include cycle detected")
    if key in seen:
        return
    seen.add(key)
    if len(seen) > 256:
        raise ValueError("configuration include budget exhausted")
    if is_mask:
        result["files"].append({"path": path, "category": category, "content": "",
                                "masked": True, "resolved_path": "/dev/null"})
        return
    try:
        os.stat(path)
    except FileNotFoundError:
        result["absent"].append(path)
        if path == "/etc/network/interfaces" or required or os.path.lexists(path):
            raise ValueError("required network configuration is absent")
        return
    with open(path, "r", encoding="utf-8", errors="strict") as stream:
        content = stream.read(16777217)
    size += len(content.encode("utf-8"))
    if len(content) > 16777216 or size > 33554432:
        raise ValueError("configuration byte budget exhausted")
    result["files"].append({"path": path, "category": category, "content": content})
    active.add(key)
    try:
        includes(content, path, category)
    finally:
        active.remove(key)

def includes(content, path, category):
    for line in content.splitlines():
        stripped = line.strip()
        if category == "network" and re.match(r"^source(?:-directory)?\s", stripped):
            fields = shlex.split(stripped, comments=True)
            for pattern in fields[1:]:
                if fields[0] == "source-directory":
                    if not os.path.isabs(pattern):
                        pattern = os.path.join(os.path.dirname(path), pattern)
                    if not permitted(pattern, category):
                        raise ValueError("configuration directory outside approved roots")
                    names = matches(os.path.join(pattern, "*"))
                    names = [name for name in names
                             if re.fullmatch(r"[A-Za-z0-9_-]+", os.path.basename(name))]
                    result["includes"].append({"source": path, "pattern": pattern,
                                               "matches": names})
                    for name in names:
                        visit(name, category, required=True)
                else:
                    expand(pattern, category, path)
        elif category == "time" and re.match(r"^(include|confdir|sourcedir)\s", stripped,
                                             re.IGNORECASE):
            fields = shlex.split(stripped, comments=True)
            directive = fields[0].lower()
            for pattern in fields[1:]:
                if directive in ("confdir", "sourcedir"):
                    pattern = os.path.join(pattern, "*.conf" if directive == "confdir"
                                           else "*.sources")
                expand(pattern, category, path, required=directive == "include")
        elif category == "logging":
            if re.match(r"^\$IncludeConfig\s", stripped):
                fields = shlex.split(stripped, comments=True)
                if len(fields) != 2:
                    raise ValueError("unrecognized logging include syntax")
                expand(fields[1], category, path)
            elif re.match(r"^include\s*\(", stripped):
                match = re.search(r'file\s*=\s*"([^"\n]+)"', stripped)
                if not match:
                    raise ValueError("unrecognized logging include syntax")
                expand(match.group(1), category, path)

try:
    for category, paths in roots.items():
        for path in paths:
            visit(path, category)
    for category, entries in patterns.items():
        for pattern in entries:
            expand(pattern, category, roots[category][0])
except Exception as error:
    result["errors"].append(type(error).__name__ + ": " + str(error))
print(json.dumps(result, sort_keys=True))
"""

CONFIG_COMMAND = "python3 -c " + shlex.quote(CONFIG_SCRIPT)

# Named Linux kernel attributes are a structured source, unlike parsed lspci,
# ip/ethtool tables or dmidecode display output. All paths and fields are fixed.
HARDWARE_SCRIPT = r"""
import errno
import json
import os
import re
from pathlib import Path

out = {"pci": [], "iommu_groups": [], "net": [], "cpu": {},
       "numa": [], "hugepages": [], "sysctl": {}, "kvm": {}, "errors": [],
       "unavailable": []}

def read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as stream:
            value = stream.read(1048577)
        if len(value) > 1048576:
            raise ValueError("kernel attribute byte budget exhausted")
        return value.strip()
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ENODATA, errno.ENODEV, errno.EINVAL):
            out["unavailable"].append({"path": str(path), "errno": error.errno})
        else:
            out["errors"].append({"path": str(path), "error": type(error).__name__})
        return None

def directories(pattern):
    import glob
    values = sorted(glob.glob(pattern))
    if len(values) > 4096:
        raise ValueError("kernel attribute inventory budget exhausted")
    return values

def link(path):
    try:
        return os.path.realpath(path) if os.path.islink(path) else None
    except OSError as error:
        out["errors"].append({"path": str(path), "error": type(error).__name__})
        return None

try:
    for name in ("online", "present", "isolated", "nohz_full"):
        out["cpu"][name] = read("/sys/devices/system/cpu/" + name)
    for path in directories("/sys/bus/pci/devices/*"):
        name = os.path.basename(path)
        if not re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", name):
            raise ValueError("unrecognized PCI resource identifier")
        row = {"id": name, "driver": link(path + "/driver"),
               "iommu_group": link(path + "/iommu_group"),
               "physical_function": link(path + "/physfn"),
               "virtual_functions": [link(p) for p in directories(path + "/virtfn*")]}
        for field in ("vendor", "device", "class", "subsystem_vendor", "subsystem_device",
                      "numa_node", "sriov_numvfs", "sriov_totalvfs", "enable"):
            row[field] = read(path + "/" + field)
        out["pci"].append(row)
    for path in directories("/sys/kernel/iommu_groups/[0-9]*"):
        out["iommu_groups"].append({"id": os.path.basename(path),
            "devices": [os.path.basename(p) for p in directories(path + "/devices/*")]})
    for path in directories("/sys/class/net/*"):
        row = {"name": os.path.basename(path), "device": link(path + "/device"),
               "driver": link(path + "/device/driver")}
        for field in ("address", "speed", "duplex", "operstate", "carrier", "mtu",
                      "flags", "type", "phys_port_name", "phys_switch_id"):
            row[field] = read(path + "/" + field)
        out["net"].append(row)
    for path in directories("/sys/devices/system/node/node[0-9]*"):
        out["numa"].append({"id": os.path.basename(path),
                            "cpulist": read(path + "/cpulist"),
                            "distance": read(path + "/distance")})
    page_paths = directories("/sys/kernel/mm/hugepages/hugepages-*kB")
    page_paths += directories("/sys/devices/system/node/node[0-9]*/hugepages/hugepages-*kB")
    for path in page_paths:
        row = {"path": path, "size_kb": os.path.basename(path)[10:-2],
               "node": next((part for part in path.split("/")
                             if re.fullmatch(r"node[0-9]+", part)), None)}
        for field in ("nr_hugepages", "free_hugepages", "surplus_hugepages", "resv_hugepages"):
            row[field] = read(path + "/" + field)
        out["hugepages"].append(row)
    for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
                "net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables",
                "vm.nr_hugepages", "vm.hugetlb_shm_group", "vm.swappiness",
                "vm.overcommit_memory", "vm.zone_reclaim_mode", "kernel.numa_balancing"):
        out["sysctl"][key] = read("/proc/sys/" + key.replace(".", "/"))
    for path in directories("/sys/module/kvm*/parameters/*"):
        out["kvm"][path] = read(path)
    out["boot_cmdline"] = read("/proc/cmdline")
except Exception as error:
    out["errors"].append({"error": type(error).__name__ + ": " + str(error)})
print(json.dumps(out, sort_keys=True))
"""

HARDWARE_COMMAND = "python3 -c " + shlex.quote(HARDWARE_SCRIPT)

# Proxmox's own config parsers provide an authoritative structured inventory
# even when an API token's ACL filters list results. These fixed library reads
# create no session, task or configuration object. Filesystem read permission
# is required; private token/password stores are never queried.
ACCESS_SCRIPT = r"""
use strict;
use warnings;
use PVE::AccessControl;
use PVE::Cluster;
use PVE::Storage;
use JSON::PP;

my @specs = (
    ['mapping_pci', 'PVE::Mapping::PCI', 'mapping/pci.cfg', 'config'],
    ['mapping_usb', 'PVE::Mapping::USB', 'mapping/usb.cfg', 'config'],
    ['mapping_dir', 'PVE::Mapping::Dir', 'mapping/directory.cfg', 'config'],
    ['replication', 'PVE::ReplicationConfig', 'replication.cfg', 'cfs'],
    ['sdn_zones', 'PVE::Network::SDN::Zones', 'sdn/zones.cfg', 'config'],
    ['sdn_vnets', 'PVE::Network::SDN::Vnets', 'sdn/vnets.cfg', 'config'],
    ['sdn_controllers', 'PVE::Network::SDN::Controllers', 'sdn/controllers.cfg', 'config'],
    ['sdn_dns', 'PVE::Network::SDN::Dns', 'sdn/dns.cfg', 'config'],
    ['sdn_ipams', 'PVE::Network::SDN::Ipams', 'sdn/ipams.cfg', 'config'],
    ['sdn_subnets', 'PVE::Network::SDN::Subnets', 'sdn/subnets.cfg', 'config'],
    ['sdn_fabrics', 'PVE::Network::SDN::Fabrics', 'sdn/fabrics.cfg', 'fabrics'],
    ['sdn_prefix_lists', 'PVE::Network::SDN::PrefixLists', 'sdn/prefix-lists.cfg', 'list'],
    ['sdn_route_maps', 'PVE::Network::SDN::RouteMaps', 'sdn/route-maps.cfg', 'list'],
    ['sdn_running', 'PVE::Network::SDN', 'sdn/.running-config', 'running_config'],
);

sub parser_installed {
    my ($module) = @_;
    (my $file = $module) =~ s!::!/!g;
    $file .= '.pm';
    my $found = exists $INC{$file};
    for my $directory (@INC) {
        $found = 1 if !ref($directory) && -f "$directory/$file";
    }
    return 0 if !$found;
    eval { require $file; 1 } or die "installed native inventory parser could not be loaded\n";
    return 1;
}

sub absent_source {
    my ($module, $source, $reason) = @_;
    return { outcome => 'not-present', module => $module, source => $source,
             unavailable_reason => $reason };
}

sub complete_source {
    my ($module, $source, $config, $require_ids) = @_;
    die "native inventory parser returned an invalid object\n" if ref($config) ne 'HASH';
    my $result = { outcome => 'complete', module => $module, source => $source,
                   config => $config };
    if ($require_ids || exists($config->{ids})) {
        die "native inventory parser returned an invalid ids map\n"
            if ref($config->{ids}) ne 'HASH';
        my @ids = sort keys %{$config->{ids}};
        my @entries;
        for my $id (@ids) {
            die "native inventory parser returned an invalid resource object\n"
                if ref($config->{ids}->{$id}) ne 'HASH';
            push @entries, { identity => $id, config => $config->{ids}->{$id} };
        }
        $result->{identities} = \@ids;
        $result->{entries} = \@entries;
    }
    return $result;
}

my %installed;
for my $spec (@specs) {
    $installed{$spec->[1]} = parser_installed($spec->[1])
        if !exists($installed{$spec->[1]});
}
PVE::Cluster::cfs_update(1);
my $nodes = PVE::Cluster::get_nodelist();
die "native cluster membership reader returned an invalid node list\n"
    if ref($nodes) ne 'ARRAY' || grep { ref($_) || !defined($_) || $_ eq '' } @$nodes;
my $data = { access => PVE::Cluster::cfs_read_file('user.cfg'),
             guests => PVE::Cluster::get_vmlist(), storage => PVE::Storage::config(),
             nodes => [sort @$nodes], inventories => {} };

for my $spec (@specs) {
    my ($key, $module, $source, $kind) = @$spec;
    if (!$installed{$module}) {
        $data->{inventories}->{$key} = absent_source($module, $source, 'module-not-installed');
        next;
    }
    my $reader = $module->can($kind eq 'cfs' ? 'parse_config' :
                             $kind eq 'running_config' ? 'running_config' : 'config');
    if (!$reader) {
        $data->{inventories}->{$key} = absent_source($module, $source, 'method-not-installed');
        next;
    }
    my $config;
    if ($kind eq 'cfs') {
        $config = PVE::Cluster::cfs_read_file($source);
    } elsif ($kind eq 'fabrics') {
        my $object = $reader->();
        die "native fabric parser has no list_all reader\n" if !$object->can('list_all');
        my ($fabrics, $nodes) = $object->list_all();
        $config = { ids => $fabrics, nodes => { ids => $nodes }, digest => $object->digest() };
    } elsif ($kind eq 'list') {
        my $object = $reader->();
        die "native SDN parser has no list reader\n" if !$object->can('list');
        $config = { ids => $object->list(), digest => $object->digest() };
    } else {
        $config = $reader->();
    }
    my $result = complete_source($module, $source, $config, $kind ne 'running_config');
    if ($kind eq 'fabrics') {
        $result->{nodes} = complete_source($module, $source, $config->{nodes}, 1);
    }
    if ($kind eq 'running_config') {
        $result->{families} = {};
        for my $family (sort keys %$config) {
            next if ref($config->{$family}) ne 'HASH' || !exists($config->{$family}->{ids});
            next if $family eq 'fabrics' || $family eq 'prefix-lists' || $family eq 'route-maps';
            $result->{families}->{$family} = complete_source(
                $module, $source, $config->{$family}, 1);
        }
    }
    $data->{inventories}->{$key} = $result;
}

my $sdn = 'PVE::Network::SDN';
my $running = $data->{inventories}->{sdn_running};
my $configured_fabrics = $data->{inventories}->{sdn_fabrics};
$data->{inventories}->{sdn_fabric_nodes} = $configured_fabrics->{outcome} eq 'complete'
    ? $configured_fabrics->{nodes} : $configured_fabrics;
if ($running->{outcome} eq 'complete') {
    # Rust-backed readers expose native plain list models, not blessed objects
    # or guessed raw snapshot internals. The API uses these exact read methods.
    for my $spec (['fabrics', 'sdn_fabrics', 'PVE::Network::SDN::Fabrics', 'fabrics'],
                  ['prefix-lists', 'sdn_prefix_lists', 'PVE::Network::SDN::PrefixLists', 'list'],
                  ['route-maps', 'sdn_route_maps', 'PVE::Network::SDN::RouteMaps', 'list']) {
        my ($family, $key, $module, $kind) = @$spec;
        my $configured = $data->{inventories}->{$key};
        if ($configured->{outcome} ne 'complete') {
            $running->{families}->{$family} = $configured;
            next;
        }
        my $reader = $module->can('config');
        my $object = $reader->(1);
        if ($kind eq 'fabrics') {
            my ($fabrics, $nodes) = $object->list_all();
            $running->{families}->{fabrics} = complete_source(
                $module, 'sdn/.running-config', { ids => $fabrics }, 1);
            $running->{families}->{nodes} = complete_source(
                $module, 'sdn/.running-config', { ids => $nodes }, 1);
        } else {
            $running->{families}->{$family} = complete_source(
                $module, 'sdn/.running-config', { ids => $object->list() }, 1);
        }
    }
}
my $pending_reader = $installed{$sdn} ? $sdn->can('pending_config') : undef;
if (!$pending_reader || $running->{outcome} ne 'complete') {
    $data->{inventories}->{sdn_pending} = absent_source(
        $sdn, 'sdn/.running-config + configured native parsers',
        !$installed{$sdn} ? 'module-not-installed' : 'method-not-installed');
} else {
    my $pending = { outcome => 'complete', module => $sdn,
                    source => 'native pending_config', families => {} };
    for my $pair (['zones', 'sdn_zones'], ['vnets', 'sdn_vnets'],
                  ['controllers', 'sdn_controllers'], ['subnets', 'sdn_subnets'],
                  ['fabrics', 'sdn_fabrics'], ['prefix-lists', 'sdn_prefix_lists'],
                  ['route-maps', 'sdn_route_maps']) {
        my ($family, $key) = @$pair;
        my $configured = $data->{inventories}->{$key};
        if ($configured->{outcome} ne 'complete') {
            $pending->{families}->{$family} = $configured;
            next;
        }
        # The native helper can autovivify absent objects; preserve the captured
        # source snapshots by giving it private plain-JSON copies.
        my $encoder = JSON::PP->new;
        my $family_running = $running->{families}->{$family};
        my $running_config = $family_running && $family_running->{outcome} eq 'complete'
            ? $family_running->{config} : { ids => {} };
        my $running_copy = $encoder->decode($encoder->encode({ $family => $running_config }));
        my $configured_copy = $encoder->decode($encoder->encode($configured->{config}));
        my $config = $pending_reader->($running_copy, $configured_copy, $family);
        $pending->{families}->{$family} = complete_source(
            $sdn, 'native pending_config', $config, 1);
        if ($family eq 'fabrics') {
            my $running_nodes = $running->{families}->{nodes}->{config};
            my $running_nodes_copy = $encoder->decode(
                $encoder->encode({ nodes => $running_nodes }));
            my $configured_nodes_copy = $encoder->decode(
                $encoder->encode($configured->{config}->{nodes}));
            my $node_config = $pending_reader->(
                $running_nodes_copy, $configured_nodes_copy, 'nodes');
            $pending->{families}->{nodes} = complete_source(
                $sdn, 'native pending_config', $node_config, 1);
        }
    }
    $data->{inventories}->{sdn_pending} = $pending;
}
print JSON::PP->new->canonical->encode($data);
"""
ACCESS_COMMAND = "perl -e " + shlex.quote(ACCESS_SCRIPT)

# dpkg's explicit output template is machine JSON, never its display table.
# Debian package/version/architecture/status grammars contain no JSON quoting
# characters. Each JSON record is parsed before returning the complete array.
PACKAGES_SCRIPT = r"""
import json
import subprocess
format = '{"package":"${binary:Package}","version":"${Version}",' + \
         '"architecture":"${Architecture}","status":"${db:Status-Status}"}\n'
reply = subprocess.run(["dpkg-query", "--show", "--showformat=" + format],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, encoding="utf-8")
print(json.dumps([json.loads(line) for line in reply.stdout.splitlines()], sort_keys=True))
"""
PACKAGES_COMMAND = "python3 -c " + shlex.quote(PACKAGES_SCRIPT)
