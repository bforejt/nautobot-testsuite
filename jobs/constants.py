"""Shared knobs for the Network Validation jobs.

Every tunable lives here, documented in place (nautobot-upgrades convention).
JOB_VERSION is logged at the start of every run so each JobResult records
which code produced it. Keep the ``-dev`` suffix on main; release trains drop
it (see the sister repo's RELEASING.md model).
"""

JOB_VERSION = "0.1.0-dev"

# Jobs-UI grouping header. Each job module sets ``name = C.UI_GROUP``.
UI_GROUP = "Network Validation"

# --- snapshot envelope ------------------------------------------------------
SCHEMA_VERSION = "1.0"
FRAMEWORK_NAME = "nautobot-testsuite"

# Artifact filenames attached to the JobResult, one set per device.
# change_id and device are sanitized (alnum, dash, underscore, dot) before use.
SNAPSHOT_FILENAME = "snapshot_{device}_{change_id}.json"
RAW_FILENAME = "raw_{device}_{change_id}.json"
REPORT_FILENAME = "report_{device}.json"
DEBUG_FILENAME = "debug_{device}_{change_id}.json"
SHAKEDOWN_FILENAME = "shakedown_{device}.json"
SHAKEDOWN_TRACE_FILENAME = "shakedown-trace_{device}.json"

# --- RESTCONF (Catalyst 9500 / IOS-XE 17.12) --------------------------------
RESTCONF_PORT = 443
VERIFY_TLS = False  # self-signed device certs are the norm today; flip when PKI lands
CONNECT_TIMEOUT = 10  # seconds to establish TCP/TLS
GET_TIMEOUT = 120  # read timeout for normal scoped GETs
BIG_GET_TIMEOUT = 300  # full-RIB class fetches; anything needing more is mis-scoped
# Cheap existence probe target used by ping(): must return 2xx on a healthy DMI.
# NOTE the /device-hardware level between the top container and
# device-system-data — omitting it 404s on every real device (found on a live
# 17.12.06 switch; path verified against the nautobot-upgrades production path).
DATA_DEVICE_SYSTEM = (
    "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
    "/device-hardware/device-system-data"
)
# Fallback probe: RFC 8040 makes ietf-yang-library mandatory on every RESTCONF
# server, so a 404 here (and on DATA_DEVICE_SYSTEM) means the DMI is not
# serving data at all — not a single quirky model.
DATA_YANG_LIBRARY = "/data/ietf-yang-library:modules-state?depth=1"

# --- SSH --------------------------------------------------------------------
SSH_CONNECT_TIMEOUT = 15
SSH_READ_TIMEOUT = 90  # several PAN-OS shows run long
SSH_BIG_READ_TIMEOUT = 300  # session-matrix sweeps, route dumps

# --- comparison defaults (overridable per check / per run) ------------------
SESSION_TOLERANCE_PCT = 30  # active session count post vs pre
ROUTE_COUNT_TOLERANCE_PCT = 10  # full-table route counts
ROUTE_ROLLUP_TOLERANCE_ABS = 3  # per-protocol/per-type counts: "within just a couple"
PEER_PREFIX_TOLERANCE_ABS = 3  # BGP per-peer installed/received prefixes
CAPABILITY_FLOOR_PRE = 5  # session-matrix pairs at/above this pre-count are gating
CAPABILITY_MIN_POST = 1  # ...and must show at least this many sessions post
SESSION_MATRIX_MAX_ZONES = 12  # refuse to sweep an absurd pair count; log and truncate

# --- compare-job guardrails -------------------------------------------------
BASELINE_MAX_AGE_H = 24  # warn when the pre snapshot is older than this
