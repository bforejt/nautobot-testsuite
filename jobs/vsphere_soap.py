"""vim25 SOAP envelopes and response parsing for standalone ESXi. Pure: stdlib only.

This module is the read-only guarantee for the vmware platform, stated as
code: ``build_envelope`` forms bytes for exactly the six operations in
``OPERATIONS`` and refuses everything else — and refuses any value that is
not inside its fence — before a single byte exists. The transport
(``transport_vsphere``) sends what this module builds and nothing else; CI
asserts the ``OPERATIONS = frozenset`` line and greps a mutating-name
blocklist over both files, so the refusal corpus lives in ``tests/`` where
those names may be spelled.

Fences:

- managed-object ids fullmatch ``[A-Za-z0-9._-]{1,160}`` (Task ids such as
  ``haTask-ha-host-vim.host.StorageSystem.refreshStorageSystem-123456789``
  exceed 64 characters, so the cap is generous on purpose);
- property paths must be members of ``PROPERTY_PATHS[type]`` — bare dotted
  paths only, which is all PropertyCollector grammar allows (``foo[]`` and
  ``service[key='ntpd']`` are not paths and would fault ``InvalidProperty``
  on hostd even if let through);
- pnic device names for QueryNetworkHint fullmatch ``vmnic\\d+``, and the
  ``<device>`` element is omitted entirely (never emitted empty) when the
  call means "every pnic".

Parsing converts the wire shapes the collectors read: xsi-typed leaves
(``xsd:int``/``long``/``short``/``boolean``/``string``) become Python values,
``ManagedObjectReference`` becomes ``{"type", "moid"}``, data objects become
dicts carrying their ``xsi:type`` under ``_type``, ``ArrayOf*`` values become
lists. Untyped leaves inside data objects stay strings — hostd does not type
them on the wire — so ``to_int``/``to_bool``/``to_unsigned_short`` are here for
the normalizers. Timestamps stay verbatim strings (py3.9 ``fromisoformat``
rejects ``Z`` with microseconds).
"""

import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

# The only operations this suite will ever put on the wire. CI asserts this
# line exists; the transport imports the set and refuses anything else too.
OPERATIONS = frozenset(
    {
        "RetrieveServiceContent",
        "Login",
        "Logout",
        "RetrievePropertiesEx",
        "ContinueRetrievePropertiesEx",
        "QueryNetworkHint",
    }
)

NAMESPACE = "urn:vim25"
# SOAPAction version used when vimServiceVersions.xml cannot be read: the
# oldest vim25 version whose property set covers everything the catalog
# reads (hostd accepts older versions than it serves).
FALLBACK_VERSION = "6.5"

_SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
_XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
_XSI_TYPE = "{%s}type" % (_XSI_NS,)

_MOID_RE = re.compile(r"[A-Za-z0-9._-]{1,160}")
_DEVICE_RE = re.compile(r"vmnic[0-9]{1,4}")
_LOCALE_RE = re.compile(r"[A-Za-z][A-Za-z_-]{0,15}")
_NAMESPACE_RE = re.compile(r"urn:vim25(/[0-9][0-9A-Za-z.]{0,15})?")
_PATH_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)*")

# Per managed-object type, every property path the catalog may request. A
# path outside its type's set is refused before the envelope exists. Parent
# paths (``config.network``) are listed so collectors can share one fetch
# and select fields client-side, per the shared-fetch rule.
PROPERTY_PATHS = {
    "HostSystem": frozenset(
        {
            "name",
            "summary",
            "summary.config.name",
            "summary.config.product",
            "summary.hardware",
            "summary.rebootRequired",
            "summary.managementServerIp",
            "summary.runtime",
            "hardware",
            "hardware.systemInfo",
            "hardware.biosInfo",
            "hardware.memorySize",
            "hardware.cpuInfo",
            "hardware.cpuPkg",
            "hardware.numaInfo",
            "hardware.pciDevice",
            "config.product",
            "config.hyperThread",
            "config.pciPassthruInfo",
            "config.network",
            "config.network.pnic",
            "config.network.vswitch",
            "config.network.proxySwitch",
            "config.network.portgroup",
            "config.network.vnic",
            "config.network.consoleVnic",
            "config.network.routeTableInfo",
            "config.network.ipRouteConfig",
            "config.network.netStackInstance",
            "config.network.dnsConfig",
            "config.network.ipV6Enabled",
            "config.network.atBootIpV6Enabled",
            "config.virtualNicManagerInfo",
            "config.dateTimeInfo",
            "config.service",
            "config.service.service",
            "config.option",
            "config.lockdownMode",
            "config.adminDisabled",
            "config.firewall",
            "config.fileSystemVolume",
            "config.fileSystemVolume.mountInfo",
            "config.storageDevice",
            "config.storageDevice.hostBusAdapter",
            "config.storageDevice.scsiLun",
            "config.storageDevice.plugStoreTopology",
            "config.storageDevice.multipathInfo",
            "config.autoStart",
            "config.certificate",
            "config.powerSystemInfo",
            "config.powerSystemCapability",
            "config.host",
            "config.systemResources",
            "config.ipmi",
            "config.sslThumbprintInfo",
            "config.hostOperationCleanupNeeded",
            "configManager.networkSystem",
            "configManager.storageSystem",
            "configManager.autoStartManager",
            "configManager.dateTimeSystem",
            "configManager.firewallSystem",
            "configManager.serviceSystem",
            "configManager.advancedOption",
            "configManager.healthStatusSystem",
            "runtime",
            "runtime.bootTime",
            "runtime.connectionState",
            "runtime.powerState",
            "runtime.inMaintenanceMode",
            "runtime.inQuarantineMode",
            "runtime.standbyMode",
            "runtime.healthSystemRuntime",
            "runtime.hostMaxVirtualDiskCapacity",
            "runtime.tpmPcrValues",
            "datastore",
            "network",
            "vm",
            "capability",
            "overallStatus",
            "licensableResource",
        }
    ),
    "VirtualMachine": frozenset(
        {
            "name",
            "summary",
            "summary.config",
            "summary.runtime",
            "summary.guest",
            "summary.storage",
            "config",
            "config.name",
            "config.uuid",
            "config.instanceUuid",
            "config.version",
            "config.guestId",
            "config.guestFullName",
            "config.template",
            "config.annotation",
            "config.changeVersion",
            "config.modified",
            "config.createDate",
            "config.firmware",
            "config.files",
            "config.files.vmPathName",
            "config.hardware",
            "config.hardware.numCPU",
            "config.hardware.numCoresPerSocket",
            "config.hardware.autoCoresPerSocket",
            "config.hardware.memoryMB",
            "config.hardware.device",
            "config.cpuAllocation",
            "config.memoryAllocation",
            "config.memoryReservationLockedToMax",
            "config.memoryHotAddEnabled",
            "config.cpuHotAddEnabled",
            "config.latencySensitivity",
            "config.cpuAffinity",
            "config.extraConfig",
            "config.bootOptions",
            "config.flags",
            "config.tools",
            "config.nestedHVEnabled",
            "config.vPMCEnabled",
            "config.managedBy",
            "config.ftInfo",
            "config.swapPlacement",
            "config.datastoreUrl",
            "config.sgxInfo",
            "config.vmxConfigChecksum",
            "runtime",
            "runtime.powerState",
            "runtime.connectionState",
            "runtime.bootTime",
            "runtime.question",
            "runtime.host",
            "runtime.maxCpuUsage",
            "runtime.maxMemoryUsage",
            "runtime.consolidationNeeded",
            "runtime.faultToleranceState",
            "guest",
            "guest.guestState",
            "guest.toolsStatus",
            "guest.toolsRunningStatus",
            "guest.toolsVersionStatus2",
            "guest.toolsVersion",
            "guest.hostName",
            "guest.ipAddress",
            "guest.guestId",
            "guest.guestFullName",
            "guest.net",
            "snapshot",
            "datastore",
            "network",
            "resourceConfig",
            "overallStatus",
        }
    ),
    "Datastore": frozenset(
        {
            "name",
            "summary",
            "summary.name",
            "summary.type",
            "summary.url",
            "summary.capacity",
            "summary.freeSpace",
            "summary.accessible",
            "summary.maintenanceMode",
            "summary.multipleHostAccess",
            "summary.uncommitted",
            "info",
            "info.vmfs",
            "info.nas",
            "info.url",
            "capability",
            "host",
            "vm",
            "overallStatus",
        }
    ),
    "TaskManager": frozenset({"recentTask", "maxCollector", "description"}),
    "Task": frozenset(
        {
            "info",
            "info.key",
            "info.task",
            "info.name",
            "info.descriptionId",
            "info.description",
            "info.entity",
            "info.entityName",
            "info.state",
            "info.cancelled",
            "info.cancelable",
            "info.error",
            "info.result",
            "info.progress",
            "info.reason",
            "info.queueTime",
            "info.startTime",
            "info.completeTime",
            "info.eventChainId",
            "info.changeTag",
            "info.parentTaskKey",
            "info.rootTaskKey",
        }
    ),
    "EventManager": frozenset({"latestEvent", "maxCollector", "description"}),
    "LicenseManager": frozenset(
        {
            "licenses",
            "licensedEdition",
            "evaluation",
            "featureInfo",
            "source",
            "sourceAvailable",
            "diagnostics",
            "licenseAssignmentManager",
        }
    ),
    "HostNetworkSystem": frozenset(
        {
            "networkInfo",
            "networkConfig",
            "capabilities",
            "dnsConfig",
            "ipRouteConfig",
            "consoleIpRouteConfig",
            "offloadCapabilities",
        }
    ),
    # Singleton managers reachable from HostSystem.configManager; listed so a
    # collector may read them directly when the host-level path is absent.
    "HostAutoStartManager": frozenset({"config"}),
    "HostDateTimeSystem": frozenset({"dateTimeInfo"}),
    "HostFirewallSystem": frozenset({"firewallInfo"}),
    "HostServiceSystem": frozenset({"serviceInfo"}),
    "OptionManager": frozenset({"setting", "supportedOption"}),
    "HostStorageSystem": frozenset(
        {"storageDeviceInfo", "fileSystemVolumeInfo", "systemFile", "multipathStateInfo"}
    ),
    "HostHealthStatusSystem": frozenset({"runtime"}),
}

# Fixed _this targets: the service instance is a well-known singleton.
SERVICE_INSTANCE = ("ServiceInstance", "ServiceInstance")


class SoapRefused(ValueError):
    """Operation or value outside the fence; no envelope was formed."""


class SoapParseError(ValueError):
    """The response is not the vim25 shape the caller expected."""


# --- fences ------------------------------------------------------------------


def check_moid(value, label="moid"):
    if not isinstance(value, str) or _MOID_RE.fullmatch(value) is None:
        raise SoapRefused("%s %r is outside [A-Za-z0-9._-]{1,160}" % (label, value))
    return value


def check_type(mo_type):
    if mo_type not in PROPERTY_PATHS:
        raise SoapRefused(
            "managed-object type %r has no property allowlist (known: %s)"
            % (mo_type, ", ".join(sorted(PROPERTY_PATHS)))
        )
    return mo_type


def check_path(mo_type, path):
    check_type(mo_type)
    if not isinstance(path, str) or _PATH_RE.fullmatch(path) is None:
        raise SoapRefused("property path %r is not a bare dotted path" % (path,))
    if path not in PROPERTY_PATHS[mo_type]:
        raise SoapRefused("property path %r is not allowlisted for %s" % (path, mo_type))
    return path


def _sequence(value, label):
    """A list/tuple of strings (a bare string is refused: it is not a list of ids)."""
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise SoapRefused("%s must be a list or tuple, got %s" % (label, type(value).__name__))
    return list(value)


def _check_namespace(namespace):
    if not isinstance(namespace, str) or _NAMESPACE_RE.fullmatch(namespace) is None:
        raise SoapRefused("namespace %r is not a vim25 namespace" % (namespace,))
    return namespace


def _take(params, name, required=True):
    if name not in params:
        if required:
            raise SoapRefused("missing required parameter %r" % (name,))
        return None
    return params.pop(name)


def _no_leftovers(operation, params):
    if params:
        raise SoapRefused(
            "%s does not take parameter(s): %s" % (operation, ", ".join(sorted(params)))
        )


# --- envelope builders -------------------------------------------------------


def _this(mo_type, moid):
    return '<_this type="%s">%s</_this>' % (mo_type, moid)


def _prop_spec(mo_type, paths):
    body = "".join("<pathSet>%s</pathSet>" % (path,) for path in paths)
    return "<propSet><type>%s</type><all>false</all>%s</propSet>" % (mo_type, body)


def _build_retrieve_properties(params):
    collector = check_moid(_take(params, "property_collector"), "property_collector")
    mo_type = check_type(_take(params, "type"))
    moids = [check_moid(moid) for moid in _sequence(_take(params, "moids"), "moids")]
    if not moids:
        raise SoapRefused("moids must name at least one object")
    paths = [check_path(mo_type, path) for path in _sequence(_take(params, "paths"), "paths")]
    traverse = _take(params, "traverse", required=False)
    max_objects = _take(params, "max_objects", required=False)
    _no_leftovers("RetrievePropertiesEx", params)
    if not paths and traverse is None:
        raise SoapRefused("paths must name at least one property (never 'all')")
    if max_objects is not None and (
        isinstance(max_objects, bool) or not isinstance(max_objects, int) or max_objects < 1
    ):
        raise SoapRefused("max_objects must be a positive int, got %r" % (max_objects,))

    prop_specs = []
    select = ""
    if paths:
        prop_specs.append(_prop_spec(mo_type, sorted(set(paths))))
    if traverse is not None:
        # One TraversalSpec: from the root objects, through one property that
        # holds references, to objects of one type with their own path set.
        if not isinstance(traverse, dict):
            raise SoapRefused("traverse must be a dict {path, type, paths}")
        extra = set(traverse) - {"path", "type", "paths"}
        if extra:
            raise SoapRefused("traverse does not take: %s" % (", ".join(sorted(extra)),))
        via = check_path(mo_type, traverse.get("path"))
        target_type = check_type(traverse.get("type"))
        target_paths = [
            check_path(target_type, path)
            for path in _sequence(traverse.get("paths"), "traverse.paths")
        ]
        if not target_paths:
            raise SoapRefused("traverse.paths must name at least one property")
        prop_specs.append(_prop_spec(target_type, sorted(set(target_paths))))
        select = (
            '<selectSet xsi:type="TraversalSpec"><name>traverse</name><type>%s</type>'
            "<path>%s</path><skip>false</skip></selectSet>" % (mo_type, via)
        )
    object_specs = "".join(
        '<objectSet><obj type="%s">%s</obj><skip>%s</skip>%s</objectSet>'
        % (mo_type, moid, "false" if paths else "true", select)
        for moid in moids
    )
    options = "<options/>"
    if max_objects is not None:
        options = "<options><maxObjects>%d</maxObjects></options>" % (max_objects,)
    return "%s<specSet>%s%s</specSet>%s" % (
        _this("PropertyCollector", collector),
        "".join(prop_specs),
        object_specs,
        options,
    )


def _build_continue(params):
    collector = check_moid(_take(params, "property_collector"), "property_collector")
    token = check_moid(_take(params, "token"), "token")
    _no_leftovers("ContinueRetrievePropertiesEx", params)
    return "%s<token>%s</token>" % (_this("PropertyCollector", collector), token)


def _build_query_network_hint(params):
    network_system = check_moid(_take(params, "network_system"), "network_system")
    devices = _take(params, "devices", required=False)
    _no_leftovers("QueryNetworkHint", params)
    body = ""
    if devices is not None:
        for device in _sequence(devices, "devices"):
            if not isinstance(device, str) or _DEVICE_RE.fullmatch(device) is None:
                raise SoapRefused("device %r is not a vmnicN name" % (device,))
            body += "<device>%s</device>" % (device,)
    return _this("HostNetworkSystem", network_system) + body


def _build_login(params):
    session_manager = check_moid(_take(params, "session_manager"), "session_manager")
    username = _take(params, "username")
    password = _take(params, "password")
    locale = _take(params, "locale")
    _no_leftovers("Login", params)
    if not isinstance(username, str) or not username:
        raise SoapRefused("username must be a non-empty string")
    if not isinstance(password, str):
        raise SoapRefused("password must be a string")
    if not isinstance(locale, str) or _LOCALE_RE.fullmatch(locale) is None:
        raise SoapRefused("locale %r is not a locale tag" % (locale,))
    return "%s<userName>%s</userName><password>%s</password><locale>%s</locale>" % (
        _this("SessionManager", session_manager),
        escape(username),
        escape(password),
        locale,
    )


def _build_logout(params):
    session_manager = check_moid(_take(params, "session_manager"), "session_manager")
    _no_leftovers("Logout", params)
    return _this("SessionManager", session_manager)


def _build_service_content(params):
    _no_leftovers("RetrieveServiceContent", params)
    return _this(*SERVICE_INSTANCE)


_BUILDERS = {
    "RetrieveServiceContent": _build_service_content,
    "Login": _build_login,
    "Logout": _build_logout,
    "RetrievePropertiesEx": _build_retrieve_properties,
    "ContinueRetrievePropertiesEx": _build_continue,
    "QueryNetworkHint": _build_query_network_hint,
}


def build_envelope(operation, namespace, **params):
    """SOAP envelope bytes for one allowlisted operation, or SoapRefused.

    Parameters per operation (every value fenced, unknown names refused):

    - RetrieveServiceContent: none.
    - Login: session_manager, username, password, locale.
    - Logout: session_manager.
    - RetrievePropertiesEx: property_collector, type, moids, paths,
      optional traverse={"path", "type", "paths"}, optional max_objects.
    - ContinueRetrievePropertiesEx: property_collector, token.
    - QueryNetworkHint: network_system, optional devices (omitted = all pnics).
    """
    if operation not in OPERATIONS:
        raise SoapRefused("operation %r is not one of the six read-only operations" % (operation,))
    _check_namespace(namespace)
    body = _BUILDERS[operation](dict(params))
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="%s" xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:xsi="%s"><soapenv:Body><%s xmlns="%s">%s</%s></soapenv:Body></soapenv:Envelope>'
        % (_SOAP_NS, _XSI_NS, operation, namespace, body, operation)
    )
    return envelope.encode("utf-8")


# --- response parsing --------------------------------------------------------


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _root(xml):
    if isinstance(xml, ET.Element):
        return xml
    try:
        return ET.fromstring(xml)
    except ET.ParseError as exc:
        raise SoapParseError("response is not well-formed XML: %s" % (exc,)) from exc


def _body_child(xml):
    """The single element inside soapenv:Body, or None when the shape is off."""
    root = _root(xml)
    for body in root:
        if _local(body.tag) == "Body":
            for child in body:
                return child
    return None


def _xsi_type(element):
    value = element.get(_XSI_TYPE)
    if value is None:
        return None
    return value.rsplit(":", 1)[-1]


def _xsd_typed(element):
    """True when the xsi:type is an XML Schema leaf type (xsd:string ...), not a vim25 one."""
    value = element.get(_XSI_TYPE) or ""
    return value.startswith(("xsd:", "xs:"))


def to_int(value):
    """int() that tolerates None and junk; untyped vim25 leaves arrive as strings."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return None


def to_bool(value):
    """'true'/'false' leaves (untyped on the wire) -> bool; None when unreadable."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower() if value is not None else ""
    if text in ("true", "1"):
        return True
    if text in ("false", "0"):
        return False
    return None


def to_unsigned_short(value):
    """xsd:short rendered as an unsigned 16-bit int: 0x8086 arrives as -32122."""
    number = to_int(value)
    if number is None:
        return None
    return number & 0xFFFF


def _leaf(element, xsi_type, mask_short):
    text = element.text
    if xsi_type in ("int", "long", "byte"):
        return to_int(text)
    if xsi_type == "short":
        number = to_int(text)
        if number is not None and mask_short:
            return number & 0xFFFF
        return number
    if xsi_type == "boolean":
        return to_bool(text)
    if xsi_type is not None:
        # string, dateTime, anyURI, ...: verbatim text ("" for an empty typed leaf)
        return text or ""
    if text is None:
        return None
    return text


def convert(element, mask_short=False, item_type=None):
    """One vim25 element -> Python value (see module docstring for the mapping)."""
    xsi_type = _xsi_type(element)
    mo_type = element.get("type")
    children = list(element)
    if xsi_type == "ManagedObjectReference" or (mo_type is not None and not children):
        return {"type": mo_type, "moid": (element.text or "").strip()}
    if xsi_type is not None and xsi_type.startswith("ArrayOf"):
        member = xsi_type[len("ArrayOf") :]
        return [convert(child, mask_short, member) for child in children]
    if not children:
        if xsi_type is not None and not _xsd_typed(element) and not (element.text or "").strip():
            # An EMPTY data object whose only content is its type
            # (<bootOrder xsi:type="VirtualMachineBootOptionsBootableCdromDevice"/>):
            # the type is the value, so keep it instead of reading "".
            return {"_type": xsi_type}
        return _leaf(element, xsi_type if xsi_type is not None else item_type, mask_short)
    # Data object: children by local name; a name that repeats (an array-valued
    # field on the wire) becomes a list, a single one stays a value — hence
    # aslist() for the normalizers. The xsi:type (or the enclosing ArrayOf
    # item type) rides along as "_type" so polymorphic dispatch
    # (HostSriovInfo vs HostPciPassthruInfo, HostVmfsVolume vs NAS) is possible.
    data = {}
    repeated = set()
    type_name = xsi_type or item_type
    if type_name is not None:
        data["_type"] = type_name
    for child in children:
        name = _local(child.tag)
        value = convert(child, mask_short)
        if name in data:
            if name not in repeated:
                data[name] = [data[name]]
                repeated.add(name)
            data[name].append(value)
        else:
            data[name] = value
    return data


def aslist(value):
    """A repeated child arrives as a list, a single one as its value, absent as None."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_fault(xml):
    """(fault_type, message) from a SOAP Fault, or (None, None) when there is none.

    fault_type is the detail element's name as hostd spells it
    (``InvalidLoginFault``, ``NoPermissionFault``, ``NotAuthenticatedFault``),
    falling back to its xsi:type, then to the faultcode.
    """
    child = _body_child(xml)
    if child is None or _local(child.tag) != "Fault":
        return None, None
    code = message = None
    fault_type = None
    for part in child:
        name = _local(part.tag)
        if name == "faultcode":
            code = (part.text or "").strip() or None
        elif name == "faultstring":
            message = (part.text or "").strip() or None
        elif name == "detail":
            for detail in part:
                fault_type = _local(detail.tag) or _xsi_type(detail)
                break
    return fault_type or code, message


def parse_returnval(xml, mask_short=False):
    """Every <returnval> of a *Response, converted, as a list (empty when none)."""
    child = _body_child(xml)
    if child is None:
        raise SoapParseError("no soapenv:Body element in response")
    name = _local(child.tag)
    if name == "Fault":
        fault_type, message = parse_fault(xml)
        raise SoapParseError("SOAP fault %s: %s" % (fault_type, message))
    if not name.endswith("Response"):
        raise SoapParseError("unexpected body element %r" % (name,))
    return [convert(part, mask_short) for part in child if _local(part.tag) == "returnval"]


def parse_service_content(xml):
    """RetrieveServiceContent -> dict of MORs plus ``about`` (apiType, version, build...)."""
    values = parse_returnval(xml)
    if len(values) != 1 or not isinstance(values[0], dict):
        raise SoapParseError("RetrieveServiceContent returned no service content")
    content = values[0]
    about = content.get("about")
    if not isinstance(about, dict):
        raise SoapParseError("service content carries no <about> block")
    for key in ("sessionManager", "propertyCollector", "rootFolder"):
        if not isinstance(content.get(key), dict) or not content[key].get("moid"):
            raise SoapParseError("service content lacks %s" % (key,))
    return content


def parse_retrieve_result(xml, mask_short=False):
    """RetrievePropertiesEx / ContinueRetrievePropertiesEx ->
    {"objects": [{"obj": {type, moid}, "props": {path: value}, "missing": [...]}], "token"}.

    ``missing`` entries are ``{"path", "fault", "message"}`` from missingSet —
    a property the server would not or could not return (InvalidProperty,
    NotAuthenticated, ...); the caller decides whether that is a skip or a
    failure. An empty RetrieveResult (hostd omits returnval) parses to
    ``{"objects": [], "token": None}``.
    """
    child = _body_child(xml)
    if child is None:
        raise SoapParseError("no soapenv:Body element in response")
    name = _local(child.tag)
    if name == "Fault":
        fault_type, message = parse_fault(xml)
        raise SoapParseError("SOAP fault %s: %s" % (fault_type, message))
    if name not in ("RetrievePropertiesExResponse", "ContinueRetrievePropertiesExResponse"):
        raise SoapParseError("unexpected body element %r" % (name,))
    result = {"objects": [], "token": None}
    for returnval in child:
        if _local(returnval.tag) != "returnval":
            continue
        for part in returnval:
            part_name = _local(part.tag)
            if part_name == "token":
                result["token"] = (part.text or "").strip() or None
            elif part_name == "objects":
                result["objects"].append(_object_content(part, mask_short))
    return result


def _object_content(element, mask_short):
    obj = None
    props = {}
    missing = []
    for part in element:
        name = _local(part.tag)
        if name == "obj":
            obj = convert(part)
        elif name == "propSet":
            path = value = None
            for field in part:
                if _local(field.tag) == "name":
                    path = (field.text or "").strip()
                elif _local(field.tag) == "val":
                    value = convert(field, mask_short)
            if path:
                props[path] = value
        elif name == "missingSet":
            entry = {"path": None, "fault": None, "message": None}
            for field in part:
                if _local(field.tag) == "path":
                    entry["path"] = (field.text or "").strip()
                elif _local(field.tag) == "fault":
                    entry["fault"], entry["message"] = _localized_fault(field)
            missing.append(entry)
    if obj is None:
        raise SoapParseError("RetrieveResult object without <obj>")
    return {"obj": obj, "props": props, "missing": missing}


def _localized_fault(element):
    """LocalizedMethodFault {fault (xsi-typed MethodFault), localizedMessage} -> (type, message).

    The wire nests the typed fault one level down; an older/flatter shape
    with the xsi:type on the outer element is read the same way.
    """
    fault_type = _xsi_type(element)
    message = None
    for child in element:
        local = _local(child.tag)
        if local == "fault" and fault_type is None:
            fault_type = _xsi_type(child)
        elif local == "localizedMessage":
            message = (child.text or "").strip() or None
    return fault_type, message


def parse_service_versions(xml):
    """vimServiceVersions.xml -> {"namespace", "version", "prior_versions"} for
    the vim25 namespace, or None when the document lists no vim25 entry."""
    root = _root(xml)
    for namespace in root.iter():
        if _local(namespace.tag) != "namespace":
            continue
        name = version = None
        prior = []
        for part in namespace:
            local = _local(part.tag)
            if local == "name":
                name = (part.text or "").strip()
            elif local == "version":
                version = (part.text or "").strip()
            elif local == "priorVersions":
                prior = [
                    (item.text or "").strip() for item in part if _local(item.tag) == "version"
                ]
        if name == NAMESPACE and version:
            return {"namespace": name, "version": version, "prior_versions": prior}
    return None


def action_namespace(version):
    """SOAPAction value for a vim25 version string (``urn:vim25/8.0.3.0``)."""
    if not isinstance(version, str) or re.fullmatch(r"[0-9][0-9A-Za-z.]{0,15}", version) is None:
        raise SoapRefused("version %r is not a vim25 version string" % (version,))
    return "%s/%s" % (NAMESPACE, version)
