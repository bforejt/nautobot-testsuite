"""iosxe_config: redaction, header stripping, running-vs-startup and the text_diff mode.

The configuration text is the most secret-dense thing the suite captures, so
every secret in the fixtures and in the rule table below is a unique canary
(CANARY01, CANARY02, ...) and the battery asserts that none survives anywhere
a capture stores or traces text: normalized, context, raw, error messages and
the debug trace the Collector Shakedown attaches.
"""

import difflib
import importlib.util
import io
import json
import pathlib
import random
import re
import tempfile
import unittest
from contextlib import redirect_stderr

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

checks = _loader.checks_iosxe
context = _loader.context
diffcore = _loader.diffcore
envelope = _loader.envelope
registry = _loader.registry

RUNNING = _loader.fixture_text("iosxe_show_running_config.txt")
STARTUP = _loader.fixture_text("iosxe_show_startup_config.txt")
PRIVILEGE_15 = "Current privilege level is 15\n"
MARK = "***scrubbed***"
REJECTED = "              ^\n% Invalid input detected at '^' marker.\n"
IN_SYNC = {"in_sync": True, "verbatim_in_sync": True}
OUT_OF_SYNC = {"in_sync": False, "verbatim_in_sync": False}
UNKNOWN_SYNC = {"in_sync": None, "verbatim_in_sync": None}


class SoftTimeLimitExceeded(Exception):
    """Stand-in for Celery's abort signal, which is matched by class name."""


class _FakeSsh:
    """SSH-slot stand-in: canned output per command; records every call's kwargs."""

    def __init__(self, outputs, errors=None):
        self.outputs = dict(outputs)
        self.errors = errors or {}
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append((command, dict(kwargs)))
        if command in self.errors:
            raise self.errors[command]
        return self.outputs[command]

    def close(self):
        pass


class _FakeRestconf:
    """Restconf-slot stand-in: payload per path (None = path absent), or one error for all."""

    def __init__(self, payloads=None, error=None):
        self.payloads = payloads or {}
        self.error = error
        self.calls = []

    def get(self, path, **kwargs):
        self.calls.append((path, kwargs))
        if self.error is not None:
            raise self.error
        return self.payloads.get(path)

    def close(self):
        pass


def _outputs(running=RUNNING, startup=STARTUP, privilege=PRIVILEGE_15):
    return {
        "show running-config": running,
        "show startup-config": startup,
        "show privilege": privilege,
    }


def _context(outputs=None, hardware=None, errors=None, restconf_error=None, debug=True):
    payloads = {} if hardware is None else {checks._HW_PATH: hardware}
    return context.CollectorContext(
        "lab-9300-stk1",
        "iosxe",
        restconf=_FakeRestconf(payloads, restconf_error),
        ssh=_FakeSsh(_outputs() if outputs is None else outputs, errors),
        debug=debug,
    )


def _collect(**kwargs):
    ctx = _context(**kwargs)
    return checks._collect_config(ctx), ctx


def _hardware(system):
    return {
        "Cisco-IOS-XE-device-hardware-oper:device-hardware-data": {
            "device-hardware": {"device-system-data": system}
        }
    }


def _as_running(startup_text, current_bytes=19655):
    """A startup-config's body reprinted with running-config framing."""
    body = startup_text.splitlines()[1:]  # drop 'Using N out of M bytes'
    header = [
        "Building configuration...",
        "",
        "Current configuration : %d bytes" % (current_bytes,),
    ]
    return "\n".join(header + body) + "\n"


def _config_text(lines):
    """A running-config output around the given body lines."""
    header = ["Building configuration...", "", "Current configuration : 4242 bytes", "!"]
    return "\n".join(header + ["version 17.12"] + list(lines) + ["end"]) + "\n"


# (input, expected) in config order — a top-level line is the parent of the
# indented lines that follow it. None means "unchanged".
_CASES = (
    # global secrets: the keyword and a type digit stay
    ("enable secret 9 $9$CANARY40abc", "enable secret 9 " + MARK),
    ("enable secret 5", "enable secret " + MARK),  # a lone trailing digit IS the secret
    ("enable password level 5 7 CANARY41", "enable password " + MARK),
    ("username legacy password CANARY42", "username legacy password " + MARK),
    (
        "username ops privilege 15 secret 9 $9$CANARY43",
        "username ops privilege 15 secret 9 " + MARK,
    ),
    ("username viewer nopassword", None),
    ("key config-key password-encrypt CANARY44", "key " + MARK),
    # lines with a secret-looking word and, by grammar, no secret
    ("service password-encryption", None),
    ("no service password-recovery", None),
    ("password encryption aes", None),
    ("security passwords min-length 8", None),
    ("ip ssh server algorithm authentication password keyboard publickey", None),
    ("ntp trusted-key 1 - 3", None),
    ("ntp server 192.0.2.123 key 5 prefer", None),
    ("ip community-list standard CL-CORE permit 65000:100", None),
    ("ip extcommunity-list standard EXT permit rt 65000:1", None),
    ("ip bgp-community new-format", None),
    ("crypto key pubkey-chain rsa", None),
    # key chains: key numbers stay, key-strings go
    ("key chain KC-TEST macsec", None),
    (" key 0A1B", None),
    ("  key-string 7 CANARY45", "  key-string 7 " + MARK),
    ("  cryptographic-algorithm aes-256-cmac", None),
    # AAA
    ("tacacs server TAC9", None),
    (" key 6 CANARY46", " key 6 " + MARK),
    (" key 12345", " key " + MARK),  # outside a key chain a numeric key is a secret
    ("radius server ISE9", None),
    (" pac key 7 CANARY47", " pac key 7 " + MARK),
    ("tacacs-server host 192.0.2.47 key 7 CANARY48", "tacacs-server host 192.0.2.47 key 7 " + MARK),
    ("tacacs-server key 7 CANARY49", "tacacs-server key 7 " + MARK),
    (
        "radius-server host 192.0.2.46 auth-port 1812 acct-port 1813 key 7 CANARY50",
        "radius-server host 192.0.2.46 auth-port 1812 acct-port 1813 key 7 " + MARK,
    ),
    ("radius-server key 0 CANARY51", "radius-server key 0 " + MARK),
    ("aaa group server tacacs+ TGRP", None),
    (" server-private 192.0.2.43 key 7 CANARY52", " server-private 192.0.2.43 key 7 " + MARK),
    ("aaa server radius dynamic-author", None),
    (
        " client 192.0.2.60 vrf Mgmt-vrf server-key 0 CANARY53",
        " client 192.0.2.60 vrf Mgmt-vrf server-key 0 " + MARK,
    ),
    (" server-key 7 CANARY54", " server-key 7 " + MARK),
    ("dot1x credentials PROFILE", None),
    (" password 0 CANARY55", " password 0 " + MARK),
    ("ldap server LDAP1", None),
    (
        " bind authenticate root-dn cn=svc,dc=example,dc=net password 7 CANARY56",
        " bind authenticate root-dn cn=svc,dc=example,dc=net password 7 " + MARK,
    ),
    ("cts sxp default password 7 CANARY57", "cts sxp default password 7 " + MARK),
    # SNMP
    (
        "snmp-server community CANARY58 view V1 RO 10",
        "snmp-server community %s view V1 RO 10" % MARK,
    ),
    ("snmp-server community 7 CANARY59 RW", "snmp-server community %s RW" % MARK),
    ("snmp-server host 192.0.2.52 CANARY60", "snmp-server host 192.0.2.52 " + MARK),
    (
        "snmp-server host 192.0.2.53 traps version 2c CANARY61 bgp",
        "snmp-server host 192.0.2.53 traps version 2c " + MARK,
    ),
    (
        "snmp-server host 192.0.2.54 version 3 priv CANARY62",
        "snmp-server host 192.0.2.54 version 3 priv " + MARK,
    ),
    (
        "snmp-server user U3 G3 v3 auth md5 CANARY63 priv des CANARY64",
        "snmp-server user U3 G3 v3 auth md5 " + MARK,
    ),
    (
        "snmp-server user U4 G4 v3 priv aes 256 CANARYC5",
        "snmp-server user U4 G4 v3 priv aes 256 " + MARK,
    ),
    ("snmp mib community-map CANARY65 context CTX", "snmp mib community-map " + MARK),
    # routing-protocol authentication
    ("interface Vlan930", None),
    (" ip ospf authentication-key CANARY66", " ip ospf authentication-key " + MARK),
    (" ip ospf message-digest-key 3 md5 CANARY67", " ip ospf message-digest-key 3 md5 " + MARK),
    (" ip ospf authentication key-chain OSPF-KC", None),
    (
        " ipv6 ospf authentication ipsec spi 256 md5 7 CANARY69",
        " ipv6 ospf authentication ipsec spi 256 " + MARK,
    ),
    (
        " ospfv3 encryption ipsec spi 257 esp aes-cbc 128 7 CANARY70 sha1 7 CANARY71",
        " ospfv3 encryption ipsec spi 257 " + MARK,
    ),
    (" isis password CANARY74", " isis password " + MARK),
    ("router ospf 2", None),
    (
        " area 1 sham-link 10.0.0.1 10.0.0.2 authentication-key 7 CANARY68",
        " area 1 sham-link 10.0.0.1 10.0.0.2 authentication-key 7 " + MARK,
    ),
    ("router eigrp NAMED", None),
    (
        "   authentication mode hmac-sha-256 7 CANARY72",
        "   authentication mode hmac-sha-256 7 " + MARK,
    ),
    ("   authentication mode md5", None),
    ("router bgp 65010", None),
    (" neighbor 192.0.2.9 password CANARY73", " neighbor 192.0.2.9 password " + MARK),
    (" neighbor 192.0.2.9 send-community both", None),
    ("route-map RM-TEST permit 10", None),
    (" set community 65000:200 additive", None),
    (" match community CL-CORE", None),
    ("router isis", None),
    (" area-password CANARY75 authenticate snp validate", " area-password " + MARK),
    (" domain-password CANARY76", " domain-password " + MARK),
    ("ip msdp password peer 192.0.2.42 7 CANARY77", "ip msdp password " + MARK),
    # first-hop redundancy
    ("interface Vlan931", None),
    (
        " standby 7 authentication md5 key-string 7 CANARY78 timeout 30",
        " standby 7 authentication md5 key-string 7 " + MARK,
    ),
    (" standby 7 authentication md5 key-chain HSRP-KC", None),
    (" standby authentication CANARY79", " standby authentication " + MARK),
    (" vrrp 8 authentication text CANARY80", " vrrp 8 authentication text " + MARK),
    (
        " vrrp 8 authentication md5 key-string CANARY81",
        " vrrp 8 authentication md5 key-string " + MARK,
    ),
    (" glbp 9 authentication text CANARY82", " glbp 9 authentication text " + MARK),
    (
        " glbp 9 authentication md5 key-string 7 CANARY83",
        " glbp 9 authentication md5 key-string 7 " + MARK,
    ),
    # NTP: the type digit TRAILS the value
    (
        "ntp authentication-key 2 hmac-sha2-256 CANARY84 7",
        "ntp authentication-key 2 hmac-sha2-256 %s 7" % MARK,
    ),
    ("ntp authentication-key 3 md5 CANARY85", "ntp authentication-key 3 md5 " + MARK),
    # no known algorithm after the id: the whole tail goes, never the wrong token
    ("ntp authentication-key 4 CANARYC6 7", "ntp authentication-key 4 " + MARK),
    # IKE / IPsec / DMVPN
    (
        "crypto isakmp key 6 CANARY86 address 198.51.100.7",
        "crypto isakmp key 6 %s address 198.51.100.7" % MARK,
    ),
    (
        "crypto isakmp key CANARY87 address 0.0.0.0 0.0.0.0 no-xauth",
        "crypto isakmp key %s address 0.0.0.0 0.0.0.0 no-xauth" % MARK,
    ),
    (
        "crypto isakmp key CANARY88 hostname peer.example.net",
        "crypto isakmp key %s hostname peer.example.net" % MARK,
    ),
    ("crypto keyring KR", None),
    (
        " pre-shared-key address 198.51.100.8 key CANARY89",
        " pre-shared-key address 198.51.100.8 key " + MARK,
    ),
    ("crypto ikev2 keyring IKR", None),
    (" peer P1", None),
    ("  address 198.51.100.9", None),
    ("  pre-shared-key local 6 CANARY90", "  pre-shared-key local 6 " + MARK),
    ("  pre-shared-key remote CANARY91", "  pre-shared-key remote " + MARK),
    ("crypto ikev2 profile IKP", None),
    (
        " authentication local pre-share key 6 CANARY92",
        " authentication local pre-share key 6 " + MARK,
    ),
    (" authentication remote pre-share", None),
    ("crypto isakmp client configuration group REMOTE", None),
    (" key CANARY93", " key " + MARK),
    ("crypto map CM 10 ipsec-manual", None),
    (
        " set session-key inbound esp 256 cipher CANARY94 authenticator CANARY95",
        " set session-key " + MARK,
    ),
    ("interface Tunnel0", None),
    (" ip nhrp authentication CANARY96", " ip nhrp authentication " + MARK),
    (" tunnel key 4242", " tunnel key " + MARK),
    ("interface Serial0/1/0", None),
    (" ppp chap password 7 CANARY98", " ppp chap password 7 " + MARK),
    (" ppp pap sent-username U password 0 CANARY99", " ppp pap sent-username U password 0 " + MARK),
    ("ip ftp password 7 CANARYA0", "ip ftp password 7 " + MARK),
    # MACsec and wireless
    ("interface TenGigabitEthernet1/1/2", None),
    (" mka pre-shared-key key-chain MKA-KC fallback key-chain MKA-FB", None),
    (" cak 7 CANARYA1", " cak 7 " + MARK),
    ("wlan CORP 1 CORP", None),
    (" security wpa akm psk", None),
    (" security wpa psk set-key ascii 0 CANARYA2", " security wpa psk set-key ascii 0 " + MARK),
    (" security wpa wpa2 mpsk", None),
    ("  priority 0 set-key hex 8 CANARYA3", "  priority 0 set-key hex 8 " + MARK),
    (" wpa-psk ascii 7 CANARYA4", " wpa-psk ascii 7 " + MARK),
    (
        " security static-wep-key encryption 104 ascii 0 CANARYA5 1",
        " security static-wep-key " + MARK,
    ),
    ("ap profile default-ap-profile", None),
    (
        " mgmtuser username apadmin password 0 CANARYA6 secret 0 CANARYA7",
        " mgmtuser username apadmin password 0 " + MARK,
    ),
    ("wireless fabric control-plane default-control-plane", None),
    (" ip address 192.0.2.45 key 7 CANARYA8", " ip address 192.0.2.45 key 7 " + MARK),
    ("router lisp", None),
    ("  etr map-server 192.0.2.44 key 7 CANARYA9", "  etr map-server 192.0.2.44 key 7 " + MARK),
    ("  authentication-key 6 CANARYB0", "  authentication-key 6 " + MARK),
    ("parameter-map type umbrella global", None),
    (" token CANARYB1", " token " + MARK),
    (" api-key CANARYB2", " api-key " + MARK),
    ("crypto pki token default user-pin 0 CANARYB3", "crypto pki token default user-pin 0 " + MARK),
    ("crypto pki trustpoint TP-SCEP", None),
    (" password 7 CANARYB4", " password 7 " + MARK),
    ("vtp password CANARYB5", "vtp password " + MARK),
    # credentials inside URLs: everything up to the LAST '@' goes
    ("archive", None),
    (" path ftp://cfg:CANARYB6@192.0.2.39/$h", " path ftp://%s@192.0.2.39/$h" % MARK),
    (" path scp://cfg:p@CANARYB7@192.0.2.39/$h", " path scp://%s@192.0.2.39/$h" % MARK),
    ("kron policy-list SAVE", None),
    (" cli copy running-config tftp://192.0.2.38/sw.cfg", None),
    (
        "alias exec backup copy run scp://ops:CANARYC2@192.0.2.37/x",
        "alias exec backup copy run scp://%s@192.0.2.37/x" % MARK,
    ),
    # an EEM applet answering a password prompt: the answer has no keyword
    ("event manager applet BACKUP", None),
    (
        ' action 1.0 cli command "copy run scp://cfg@192.0.2.40/b.cfg" pattern "[Pp]assword"',
        ' action 1.0 cli command "copy run scp://%s@192.0.2.40/b.cfg" pattern "[Pp]assword"' % MARK,
    ),
    (" action 1.1 wait 2", None),
    (' action 1.2 cli command "CANARYB8"', " action 1.2 cli command " + MARK),
    (' action 1.3 cli command "show clock"', None),
    # free text: a secret-looking word masks the rest of its line
    ("banner motd ^C", None),
    ("Password: CANARYB9 (ask the NOC)", "Password: " + MARK),
    ("^C", None),
    ("interface GigabitEthernet1/0/9", None),
    (" description secret lab CANARYC0", " description secret " + MARK),
    (" description key CANARYC1", " description key " + MARK),
    (" description Key West uplink", None),
    (" description password=CANARYC4", " description password " + MARK),
    (" description secret-CANARYC7 lab", " description secret " + MARK),  # glued, hyphenated
    (" description api-key: CANARYC8", " description api-key: " + MARK),
    (" description server-key=CANARYC9", " description server-key " + MARK),
    (" description door PIN CANARYD6", " description door PIN " + MARK),
    (" security wpa akm psk-sha256", None),  # an IOS compound keyword, nothing after it
    (
        "aaa authentication password-prompt Enter-code:",
        "aaa authentication password-prompt " + MARK,
    ),
    (
        "event manager environment _email_password CANARYC3",
        "event manager environment _email_password " + MARK,
    ),
    # user:password@host with no scheme (call-home SMTP login, EEM mail)
    ("call-home", None),
    (" contact-email-addr noc@example.net", None),
    (
        " mail-server alice:CANARYE2@192.0.2.26 priority 1 secure tls",
        " mail-server %s@192.0.2.26 priority 1 secure tls" % MARK,
    ),
    (
        " mail-server :CANARYE3@192.0.2.27 priority 2",
        " mail-server %s@192.0.2.27 priority 2" % MARK,
    ),
    (
        "event manager environment _email_server ops:CANARYE4@smtp.example.net",
        "event manager environment _email_server %s@smtp.example.net" % MARK,
    ),
    # EEM variables named for a secret; other variables stay readable
    ("event manager environment _email_to noc@example.net", None),
    ("event manager environment _api_key CANARYF3", "event manager environment _api_key " + MARK),
    (
        "event manager environment _webex_token CANARYF4",
        "event manager environment _webex_token " + MARK,
    ),
    (
        "event manager environment _smtp_pass CANARYF5",
        "event manager environment _smtp_pass " + MARK,
    ),
    (
        "event manager environment _backup_pw CANARYF6",
        "event manager environment _backup_pw " + MARK,
    ),
    ("event manager environment _apikey CANARYF7", "event manager environment _apikey " + MARK),
    ("event manager environment _bearer CANARYF8", "event manager environment _bearer " + MARK),
    ("event manager applet MAILER", None),
    (' event syslog pattern "LINK-3-UPDOWN"', None),
    (
        ' action 1.0 mail server "ops:CANARYE5@192.0.2.25" to "noc@example.net" subject "s"',
        ' action 1.0 mail server "%s@192.0.2.25" to "noc@example.net" subject "s"' % MARK,
    ),
    # any prompt a `cli command ... pattern` waits for is answered by the next
    # `cli command`: masked, however the prompt is spelled; "" (Enter) stays
    ("event manager applet SCP-BACKUP", None),
    (
        ' action 2.0 cli command "copy run scp://ops@192.0.2.19/x" pattern "word:"',
        ' action 2.0 cli command "copy run scp://%s@192.0.2.19/x" pattern "word:"' % MARK,
    ),
    (' action 3.0 cli command "CANARYG6"', " action 3.0 cli command " + MARK),
    (' action 4.0 cli command "copy run flash:bk" pattern ":"', None),
    (' action 5.0 cli command ""', None),
    (' action 6.0 cli command "show clock"', None),
    # TrustSec SAP pre-master keys
    ("interface TenGigabitEthernet1/1/3", None),
    (" cts manual", None),
    ("  policy static sgt 2 trusted", None),
    ("  sap pmk 0123ABCDCANARYE6 mode-list gcm-encrypt null", "  sap pmk " + MARK),
    ("cts critical-authentication", None),
    (" default pmk 6 CANARYE7", " default pmk 6 " + MARK),
    # ThousandEyes agent (app-hosting docker options) and 9800 tokens
    ("app-hosting appid te-agent", None),
    (" app-resource docker", None),
    (
        '  run-opts 1 "-e TEAGENT_ACCOUNT_TOKEN=CANARYE8"',
        '  run-opts 1 "-e TEAGENT_ACCOUNT_TOKEN ' + MARK,
    ),
    (
        '  run-opts 2 "--hostname te-9300 -e TEAGENT_PROXY_PASS=CANARYE9"',
        '  run-opts 2 "--hostname te-9300 -e TEAGENT_PROXY_PASS ' + MARK,
    ),
    (
        '  run-opts 3 "-e TEAGENT_PROXY_USER=netops --env API_KEY=CANARYF0"',
        '  run-opts 3 "-e TEAGENT_PROXY_USER=netops --env API_KEY ' + MARK,
    ),
    ("nmsp cloud-services server token CANARYF1", "nmsp cloud-services server token " + MARK),
    (
        "wireless management certificate ssc auth-token 0 CANARYF2",
        "wireless management certificate ssc auth-token 0 " + MARK,
    ),
    ("license smart trust idtoken CANARYI2", "license smart trust idtoken " + MARK),
    # HTTP credentials in an IP SLA raw request
    ("ip sla 7", None),
    (" http raw http://192.0.2.21/status", None),
    ("  http-raw-request", None),
    ("   Authorization: Basic CANARYF9", "   Authorization: " + MARK),
    ("   Cookie: session=CANARYG0", "   Cookie: " + MARK),
    ("   Accept: text/html", None),
    # SNMPv3 key lengths are the model's enumerations, kept only before a password
    (
        "snmp-server user U5 G5 v3 auth sha-2 20242024 priv aes 128 CANARYG7",
        "snmp-server user U5 G5 v3 auth sha-2 " + MARK,
    ),
    (
        "snmp-server user U6 G6 v3 auth sha-2 256 CANARYG8 priv aes 256 CANARYG9",
        "snmp-server user U6 G6 v3 auth sha-2 256 " + MARK,
    ),
    ("snmp-server user U7 G7 v3 auth sha-2 256", "snmp-server user U7 G7 v3 auth sha-2 " + MARK),
    # free-text shorthand for a secret
    ("interface GigabitEthernet1/0/10", None),
    (" description pw CANARYH1", " description pw " + MARK),
    (" description pass: CANARYH2", " description pass: " + MARK),
    (" description creds admin/CANARYH3", " description creds " + MARK),
    (" description Key: CANARYH4", " description Key: " + MARK),
    (" description KEY=CANARYH5", " description KEY " + MARK),
    (" description passive tap port", None),
    # a name position is grammar, never free text: in a description, a BGP
    # neighbor's description or a banner the same words still mask
    (
        " description route-map SET-COMMUNITY then CANARYH6",
        " description route-map SET-COMMUNITY " + MARK,
    ),
    ("banner exec ^C", None),
    ("route-map GUEST-PSK then CANARYH7", "route-map GUEST-PSK " + MARK),
    ("^C", None),
    # ...and only an identifier is a name: a glued word=value never is
    ("route-map password:CANARYI3 permit 10", "route-map password " + MARK),
    ("wireless mobility group keyhash 0a1bCANARYI4", "wireless mobility group keyhash " + MARK),
    ("router bgp 65011", None),
    (
        " neighbor 192.0.2.3 description route-map GUEST-PSK then CANARYH8",
        " neighbor 192.0.2.3 description route-map GUEST-PSK " + MARK,
    ),
    (
        "username pskadmin privilege 15 secret 9 $9$CANARYH9",
        "username pskadmin privilege 15 secret 9 " + MARK,
    ),
)
_CASES = tuple((line, line if expected is None else expected) for line, expected in _CASES)


class TestRedactionRules(unittest.TestCase):
    def test_every_rule_line_by_line(self):
        inputs = [line for line, _expected in _CASES]
        got = checks._redact_config_lines(inputs)
        for line, expected, actual in zip(inputs, (e for _l, e in _CASES), got):
            self.assertEqual(actual, expected, line)

    def test_the_rule_table_plants_a_canary_in_every_secret(self):
        # Sanity of the table itself: every expected line is canary-free, so a
        # canary in the output is a leak, never a fixture mistake.
        planted = sum(line.count("CANARY") for line, _expected in _CASES)
        self.assertGreater(planted, 70)
        for _line, expected in _CASES:
            self.assertNotIn("CANARY", expected)

    def test_output_aligns_one_to_one(self):
        lines = ["!", "", "enable secret 9 $9$CANARYD0", "  ", "end"]
        redacted = checks._redact_config_lines(lines)
        self.assertEqual(len(redacted), len(lines))
        self.assertEqual(redacted[:2] + redacted[3:], ["!", "", "  ", "end"])

    def test_key_numbers_are_secret_only_outside_key_chains(self):
        self.assertEqual(checks._redact_config_line(" key 1", "key chain OSPF-KC"), " key 1")
        self.assertEqual(checks._redact_config_line(" key 1", "tacacs server T"), " key " + MARK)
        self.assertEqual(
            checks._redact_config_line(" key 1 CANARYD1", "key chain OSPF-KC"), " key " + MARK
        )

    def test_eem_answer_pending_ends_with_the_applet(self):
        lines = [
            "event manager applet A",
            ' action 1.0 cli command "enable" pattern "Password"',
            "event manager applet B",
            ' action 1.0 cli command "show version"',
        ]
        self.assertEqual(checks._redact_config_lines(lines), lines)

    def test_text_form_matches_the_line_form(self):
        text = "enable secret 9 $9$CANARYD2\nhostname sw\n"
        self.assertEqual(checks._redact_config_text(text), "enable secret 9 %s\nhostname sw" % MARK)


class TestNamesAreNotSecrets(unittest.TestCase):
    """A secret-looking word inside a name at a grammar-fixed position masks nothing."""

    NAMED = (
        "route-map SET-COMMUNITY permit 10",
        "router bgp 65010",
        " neighbor 192.0.2.1 route-map SET-COMMUNITY out",
        " neighbor PG-PSK peer-group",
        " neighbor 192.0.2.2 peer-group PG-PSK",
        " redistribute static route-map RM-COMMUNITY-TAG",
        "ip prefix-list PL-KEY-SERVERS seq 5 permit 10.1.0.0/16",
        "vlan 931",
        " name PIN-PAD",
        "interface Vlan931",
        " vrf forwarding COMMUNITY-WIFI",
        " ip access-group ACL-SECRET-SERVERS in",
        " service-policy input PM-COMMUNITY",
        "ip access-list extended ACL-SECRET-SERVERS",
        "class-map match-any CM-PSK-VOICE",
        "policy-map PM-COMMUNITY",
        " class CM-PSK-VOICE",
        "key chain PSK-KEYS macsec",
        "aaa group server radius ISE-PSK",
        "wlan CORP-PSK 5 CORP-PSK",
        "wireless tag policy PT-PSK",
        " wlan CORP-PSK policy PP-PSK",
    )

    def test_named_lines_stay_verbatim(self):
        self.assertEqual(checks._redact_config_lines(list(self.NAMED)), list(self.NAMED))

    def test_an_edit_inside_a_named_line_diffs_and_breaks_sync(self):
        # Masked from the name on, permit→deny and out→in would redact to the
        # same text: no hunk, and in_sync true for an unsaved edit.
        saved = _config_text(
            [
                "route-map SET-COMMUNITY permit 10",
                " set community 65000:100",
                "router bgp 65010",
                " neighbor 192.0.2.1 remote-as 65000",
                " neighbor 192.0.2.1 route-map SET-COMMUNITY out",
            ]
        )
        edited = saved.replace("permit 10", "deny 10").replace("COMMUNITY out", "COMMUNITY in")
        pre, _ctx = _collect(outputs=_outputs(running=saved, startup=saved))
        post, _ctx = _collect(outputs=_outputs(running=edited, startup=saved))
        self.assertEqual(pre["normalized"]["running-vs-startup"], IN_SYNC)
        self.assertEqual(post["normalized"]["running-vs-startup"], OUT_OF_SYNC)
        diff = diffcore.diff_check(pre["normalized"], post["normalized"], {"mode": "text_diff"})
        self.assertEqual(
            [(e["old"], e["new"]) for e in diff["changed"] if e["key"] == "running-config"],
            [
                (["route-map SET-COMMUNITY permit 10"], ["route-map SET-COMMUNITY deny 10"]),
                (
                    [" neighbor 192.0.2.1 route-map SET-COMMUNITY out"],
                    [" neighbor 192.0.2.1 route-map SET-COMMUNITY in"],
                ),
            ],
        )


class TestNoSecretLeavesTheCollector(unittest.TestCase):
    def assertNoCanary(self, *blobs):
        for blob in blobs:
            text = blob if isinstance(blob, str) else json.dumps(blob)
            self.assertNotIn("CANARY", text)

    def test_the_fixtures_actually_hold_canaries(self):
        # 36 distinct secrets, each planted once (CANARY01 .. CANARY36) — the
        # call-home SMTP login, the ThousandEyes agent token and proxy
        # password and the TrustSec SAP PMK among them.
        self.assertEqual(len(set(re.findall(r"CANARY\d\d", RUNNING))), 36)
        self.assertEqual(
            set(re.findall(r"CANARY\d\d", STARTUP)), set(re.findall(r"CANARY\d\d", RUNNING))
        )

    def test_fixture_capture_and_debug_trace_hold_no_secret(self):
        result, ctx = _collect()
        self.assertNoCanary(result, ctx.trace)
        # The trace kept every SSH output — redacted, never dropped.
        outputs = [entry for entry in ctx.trace if entry["transport"] == "ssh"]
        self.assertEqual(
            [entry["target"] for entry in outputs],
            ["show running-config", "show startup-config", "show privilege"],
        )
        for entry in outputs[:2]:
            self.assertIn(MARK, entry["output"])
            self.assertEqual(entry["outcome"], "ok")
        # ...and the redact hook never reached the transport.
        for _command, kwargs in ctx.ssh.calls:
            self.assertNotIn("redact", kwargs)
        self.assertEqual(ctx.ssh.calls[0][1], {"timeout": 300})

    def test_every_rule_shape_through_the_collector(self):
        config = _config_text(line for line, _expected in _CASES)
        result, ctx = _collect(outputs=_outputs(running=config, startup=config))
        self.assertNoCanary(result, ctx.trace)
        self.assertIs(result["normalized"]["running-vs-startup"]["in_sync"], True)

    def test_a_failed_read_never_echoes_output(self):
        errors = {"show running-config": RuntimeError("stream died at: enable secret 9 CANARYD3")}
        ctx = _context(errors=errors)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_config(ctx)
        self.assertNoCanary(str(caught.exception), ctx.trace)
        self.assertIn("'show running-config' failed: RuntimeError", str(caught.exception))

    def test_a_refusal_message_is_redacted_too(self):
        refusal = "% Permission denied for password CANARYD4\n"
        result, ctx = _collect(outputs=_outputs(startup=refusal))
        self.assertNoCanary(result, ctx.trace)
        self.assertIn("rejected", result["context"]["startup-config"]["error"])

    def test_non_debug_trace_keeps_no_output(self):
        result, ctx = _collect(debug=False)
        self.assertNoCanary(result, ctx.trace)
        self.assertTrue(all("output" not in entry for entry in ctx.trace))


class TestHeaderStripping(unittest.TestCase):
    def setUp(self):
        self.result, _ctx = _collect()
        self.running = self.result["normalized"]["running-config"]["lines"]
        self.startup = self.result["normalized"]["startup-config"]["lines"]

    def test_framing_and_volatile_lines_are_gone(self):
        self.assertEqual(self.running[:3], ["!", "!", "version 17.12"])
        self.assertEqual(self.startup[:3], ["!", "!", "version 17.12"])
        self.assertEqual(self.running[-1], "end")
        for lines in (self.running, self.startup):
            joined = "\n".join(lines)
            for framing in (
                "Building configuration",
                "Current configuration",
                "Using ",
                "! Last configuration change",
                "! NVRAM config last updated",
                "ntp clock-period",
            ):
                self.assertNotIn(framing, joined)

    def test_everything_else_is_verbatim(self):
        lines = RUNNING.splitlines()
        # The body minus the one volatile line is the output, line for line
        # (the redacted lines aside).
        body = [line for line in lines[7:] if not line.startswith("ntp clock-period")]
        self.assertEqual(len(self.running), len(body) + 2)
        for got, want in zip(self.running[2:], body):
            if MARK not in got:
                self.assertEqual(got, want)
        for line in (
            "!",
            "  \tquit",
            " certificate ca 01",
            "lab-9300-stk1 - property of Example Corp",
        ):
            self.assertIn(line, self.running)
        self.assertIn(
            "  30820321 30820209 A0030201 02020101 300D0609 2A864886 F70D0101 0B050030",
            self.running,
        )

    def test_header_facts_are_lifted_into_context(self):
        running = self.result["context"]["running-config"]
        self.assertEqual(
            running,
            {
                "bytes": 19873,
                "last_change_at": "14:02:11 EDT Thu Sep 24 2026",
                "last_change_by": "netops",
                "nvram_updated_at": "09:13:02 EDT Tue Sep 22 2026",
                "nvram_updated_by": "netops",
                "line_count": len(self.running),
                "volatile_lines_stripped": 1,
            },
        )
        startup = self.result["context"]["startup-config"]
        self.assertEqual(startup["bytes"], 19655)
        self.assertEqual(startup["nvram_bytes_total"], 2097152)
        self.assertEqual(startup["last_change_at"], "09:12:40 EDT Tue Sep 22 2026")
        self.assertEqual(startup["line_count"], len(self.startup))

    def test_no_change_since_restart_and_compressed_startup(self):
        running = RUNNING.replace(
            "! Last configuration change at 14:02:11 EDT Thu Sep 24 2026 by netops",
            "! No configuration change since last restart",
        )
        startup = STARTUP.replace(
            "Using 19655 out of 2097152 bytes",
            "Using 6120 out of 2097152 bytes, uncompressed size = 19655 bytes\n"
            "Uncompressed configuration from 6120 bytes to 19655 bytes",
        )
        result, _ctx = _collect(outputs=_outputs(running=running, startup=startup))
        self.assertIs(result["context"]["running-config"]["no_change_since_restart"], True)
        self.assertNotIn("last_change_at", result["context"]["running-config"])
        self.assertEqual(result["context"]["startup-config"]["uncompressed_bytes"], 19655)
        self.assertEqual(result["normalized"]["running-config"]["lines"], self.running)
        self.assertEqual(result["normalized"]["startup-config"]["lines"], self.startup)

    def test_two_healthy_captures_diff_to_nothing(self):
        later = RUNNING.replace("19873 bytes", "19874 bytes").replace(
            "ntp clock-period 17179938", "ntp clock-period 17179001"
        )
        later = later.replace("14:02:11 EDT Thu Sep 24 2026", "08:00:00 EDT Fri Sep 25 2026")
        second, _ctx = _collect(outputs=_outputs(running=later))
        diff = diffcore.diff_check(
            self.result["normalized"], second["normalized"], {"mode": "text_diff"}
        )
        self.assertEqual(diff["result"], "pass")

    def test_a_leftover_prompt_or_command_echo_is_framing(self):
        echoed = "show running-config\n" + RUNNING + "lab-9300-stk1#\n"
        result, _ctx = _collect(outputs=_outputs(running=echoed))
        self.assertEqual(result["normalized"]["running-config"]["lines"], self.running)

    def test_exec_prompt_timestamp_lines_are_framing(self):
        # `exec prompt timestamp` prefixes every show output with the load
        # and the clock; left in, running would never equal startup.
        stamp = (
            "Load for five secs: %d%%/0%%; one minute: 6%%; five minutes: 5%%\n"
            "Time source is NTP, 14:%02d:11.123 EDT Thu Sep 24 2026\n"
        )
        running = stamp % (7, 2) + _as_running(STARTUP)
        startup = stamp % (4, 3) + STARTUP
        result, _ctx = _collect(outputs=_outputs(running=running, startup=startup))
        self.assertEqual(result["normalized"]["running-vs-startup"], IN_SYNC)
        self.assertEqual(result["normalized"]["startup-config"]["lines"], self.startup)
        no_source = "No time source, *14:02:11.123 UTC Thu Sep 24 2026\n" + RUNNING
        result, _ctx = _collect(outputs=_outputs(running=no_source))
        self.assertEqual(result["normalized"]["running-config"]["lines"], self.running)


class TestRunningVsStartup(unittest.TestCase):
    def test_fixture_is_out_of_sync_by_three_lines(self):
        result, _ctx = _collect()
        self.assertEqual(result["normalized"]["running-vs-startup"], OUT_OF_SYNC)
        sync = result["context"]["running-vs-startup"]
        self.assertEqual(sync["only_in_running"], 2)
        self.assertEqual(sync["only_in_startup"], 1)
        diff = result["raw"]["startup-vs-running diff"]
        self.assertEqual(diff[:2], ["--- startup-config", "+++ running-config"])
        self.assertIn("+ip route 10.9.0.0 255.255.0.0 192.0.2.137", diff)
        self.assertIn("- description printer", diff)
        self.assertIn("+ description printer 3rd floor", diff)

    def test_in_sync_when_only_the_framing_differs(self):
        result, _ctx = _collect(outputs=_outputs(running=_as_running(STARTUP)))
        self.assertEqual(result["normalized"]["running-vs-startup"], IN_SYNC)
        sync = result["context"]["running-vs-startup"]
        self.assertEqual((sync["only_in_running"], sync["only_in_startup"]), (0, 0))
        self.assertNotIn("startup-vs-running diff", result["raw"])

    def test_a_secret_changed_and_not_saved(self):
        # A rotated TACACS key that was never written to NVRAM: the redacted
        # texts are identical (no hunk can show it), so only the verbatim
        # comparison — one bit, never the value — says a reload would undo it.
        saved, _ctx = _collect(outputs=_outputs(running=_as_running(STARTUP)))
        running = _as_running(STARTUP).replace(" key 7 CANARY22", " key 7 CANARYD5")
        rotated, ctx = _collect(outputs=_outputs(running=running))
        self.assertEqual(
            rotated["normalized"]["running-vs-startup"],
            {"in_sync": True, "verbatim_in_sync": False},
        )
        self.assertNotIn("CANARY", json.dumps(rotated) + json.dumps(ctx.trace))
        diff = diffcore.diff_check(
            saved["normalized"], rotated["normalized"], {"mode": "text_diff"}
        )
        self.assertEqual(
            diff["changed"],
            [{"key": "running-vs-startup", "field": "verbatim_in_sync", "old": True, "new": False}],
        )

    def test_startup_config_not_present(self):
        result, _ctx = _collect(outputs=_outputs(startup="startup-config is not present\n"))
        self.assertNotIn("startup-config", result["normalized"])
        self.assertEqual(result["normalized"]["running-vs-startup"], OUT_OF_SYNC)
        self.assertEqual(
            result["context"]["startup-config"],
            {"present": False, "device_says": "startup-config is not present"},
        )
        self.assertEqual(result["context"]["running-vs-startup"], {})
        # A platform without an NVRAM file says so in its own words.
        for answer in (
            "% Non-volatile configuration memory is not present\n",
            "%Error opening nvram:/startup-config (No such file or directory)\n",
        ):
            result, _ctx = _collect(outputs=_outputs(startup=answer))
            self.assertIs(result["context"]["startup-config"]["present"], False)
            self.assertEqual(result["normalized"]["running-vs-startup"], OUT_OF_SYNC)

    def test_unsaved_config_leaf_when_served(self):
        for value, expected in ((True, True), ("false", False)):
            result, _ctx = _collect(hardware=_hardware({"unsaved-config": value}))
            self.assertIs(result["context"]["running-vs-startup"]["unsaved_config_leaf"], expected)

    def test_unsaved_config_leaf_absent_on_the_17_12_04_capture(self):
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        result, _ctx = _collect(hardware=hardware)
        self.assertNotIn("unsaved_config_leaf", result["context"]["running-vs-startup"])
        self.assertNotIn("notes", result["context"])

    def test_unsaved_config_leaf_read_failure_is_a_note(self):
        result, _ctx = _collect(restconf_error=RuntimeError("HTTP 500"))
        self.assertIn("unsaved-config", " ".join(result["context"]["notes"]))
        self.assertEqual(result["normalized"]["running-vs-startup"], OUT_OF_SYNC)

    def test_the_leaf_rides_the_platform_health_get(self):
        ctx = _context(hardware=_hardware({"boot-time": "2026-07-11T03:12:44+00:00"}))
        checks._collect_platform_health(ctx)
        checks._collect_config(ctx)
        hardware_gets = [path for path, _kw in ctx.restconf.calls if path == checks._HW_PATH]
        self.assertEqual(hardware_gets, [checks._HW_PATH])
        self.assertIn(
            {"transport": "restconf", "target": checks._HW_PATH, "outcome": "cache-hit"},
            ctx.trace,
        )


class TestFailureHandling(unittest.TestCase):
    def test_truncated_output_is_a_failed_read(self):
        cut = "\n".join(RUNNING.splitlines()[:250]) + "\n"
        with self.assertRaises(checks.CollectError) as caught:
            _collect(outputs=_outputs(running=cut))
        self.assertIn("final 'end'", str(caught.exception))
        self.assertIn("250 lines", str(caught.exception))
        self.assertNotIn("CANARY", str(caught.exception))

    def test_empty_output_is_a_failed_read(self):
        with self.assertRaises(checks.CollectError):
            _collect(outputs=_outputs(startup="\n"))

    def test_a_short_device_error_is_a_failed_read_that_names_it(self):
        with self.assertRaises(checks.CollectError) as caught:
            _collect(outputs=_outputs(running="% Configuration buffer full, can't add command\n"))
        self.assertIn("Configuration buffer full", str(caught.exception))
        self.assertIn("nothing stored", str(caught.exception))

    def test_both_commands_rejected_is_a_failed_read(self):
        with self.assertRaises(checks.CollectError) as caught:
            _collect(outputs=_outputs(running=REJECTED, startup=REJECTED))
        message = str(caught.exception)
        self.assertIn("'show running-config' rejected: % Invalid input", message)
        self.assertIn("'show startup-config' rejected: % Invalid input", message)
        self.assertIn("privilege", message)

    def test_command_authorization_failure_is_a_refusal(self):
        refusal = "Command authorization failed.\n"
        with self.assertRaises(checks.CollectError) as caught:
            _collect(outputs=_outputs(running=refusal, startup=refusal))
        self.assertIn("authorization failed", str(caught.exception))

    def test_running_refused_and_nothing_saved(self):
        outputs = _outputs(running=REJECTED, startup="startup-config is not present\n")
        with self.assertRaises(checks.CollectError) as caught:
            _collect(outputs=outputs)
        self.assertIn("startup-config is not present", str(caught.exception))

    def test_one_side_refused_keeps_the_other(self):
        result, _ctx = _collect(outputs=_outputs(startup=REJECTED))
        self.assertEqual(sorted(result["normalized"]), ["running-config", "running-vs-startup"])
        self.assertEqual(result["normalized"]["running-vs-startup"], UNKNOWN_SYNC)
        self.assertIn(
            "'show startup-config' rejected", result["context"]["startup-config"]["error"]
        )
        result, _ctx = _collect(outputs=_outputs(running=REJECTED))
        self.assertEqual(sorted(result["normalized"]), ["running-vs-startup", "startup-config"])
        self.assertEqual(result["normalized"]["running-vs-startup"], UNKNOWN_SYNC)

    def test_a_never_saved_startup_behind_framing_is_still_absent(self):
        # exec prompt timestamp lines (or a leftover echo) ahead of the
        # answer must not turn "never saved" into a failed read that also
        # throws the running-config away.
        stamp = (
            "Load for five secs: 7%/0%; one minute: 6%; five minutes: 5%\n"
            "Time source is NTP, 14:02:11.123 EDT Thu Sep 24 2026\n"
        )
        for startup in (
            stamp + "startup-config is not present\n",
            "show startup-config\nstartup-config is not present\n",
        ):
            result, _ctx = _collect(outputs=_outputs(running=stamp + RUNNING, startup=startup))
            self.assertIs(result["context"]["startup-config"]["present"], False)
            self.assertEqual(result["normalized"]["running-vs-startup"], OUT_OF_SYNC)
            self.assertIn("running-config", result["normalized"])

    def test_a_startup_side_device_error_keeps_the_running_text(self):
        # NVRAM busy during a save, or unreadable: the saved side is unknown,
        # the running text still good.
        for answer in (
            "%Error opening nvram:/startup-config (Device or resource busy)\n",
            "%Non-volatile configuration memory has not been set up or has bad checksum\n",
        ):
            result, _ctx = _collect(outputs=_outputs(startup=answer))
            self.assertEqual(sorted(result["normalized"]), ["running-config", "running-vs-startup"])
            self.assertEqual(result["normalized"]["running-vs-startup"], UNKNOWN_SYNC)
            self.assertIn(
                "'show startup-config' answered with a device error: %",
                result["context"]["startup-config"]["error"],
            )

    def test_only_framing_is_no_answer(self):
        stamp = "Load for five secs: 7%/0%; one minute: 6%; five minutes: 5%\n"
        with self.assertRaises(checks.CollectError) as caught:
            _collect(outputs=_outputs(startup=stamp))
        self.assertIn("returned no output", str(caught.exception))

    def test_refusal_words_inside_a_config_do_not_reject_it(self):
        running = RUNNING.replace(
            " description printer 3rd floor", " description % Invalid input seen here"
        )
        result, _ctx = _collect(outputs=_outputs(running=running))
        self.assertIn(
            " description % Invalid input seen here",
            result["normalized"]["running-config"]["lines"],
        )

    def test_abort_signal_is_never_wrapped(self):
        errors = {"show startup-config": SoftTimeLimitExceeded()}
        with self.assertRaises(SoftTimeLimitExceeded):
            _collect(errors=errors)

    def test_no_ssh_transport(self):
        ctx = context.CollectorContext("sw", "iosxe", restconf=_FakeRestconf())
        with self.assertRaises(checks.SkipCheck):
            checks._collect_config(ctx)


class TestPartialViewNotes(unittest.TestCase):
    def test_privilege_below_15(self):
        result, _ctx = _collect(outputs=_outputs(privilege="Current privilege level is 7\n"))
        self.assertEqual(result["context"]["session_privilege"], 7)
        self.assertIn("below 15", " ".join(result["context"]["notes"]))

    def test_no_header_and_no_version_line(self):
        partial = "!\ninterface Vlan10\n ip address 10.10.0.2 255.255.255.0\n!\nend\n"
        result, _ctx = _collect(outputs=_outputs(running=partial))
        notes = " ".join(result["context"]["notes"])
        self.assertIn("'Current configuration' header", notes)
        self.assertIn("no 'version' line", notes)

    def test_show_privilege_failing_is_only_a_note(self):
        errors = {"show privilege": RuntimeError("timed out")}
        result, _ctx = _collect(errors=errors)
        self.assertNotIn("session_privilege", result["context"])
        self.assertIn("'show privilege' failed", " ".join(result["context"]["notes"]))
        self.assertIn("running-config", result["normalized"])
        # Refused under command authorization: answered, but no level.
        refused = _outputs(privilege="Command authorization failed.\n")
        result, _ctx = _collect(outputs=refused)
        self.assertNotIn("session_privilege", result["context"])
        self.assertIn(
            "reported no privilege level: Command authorization failed.",
            " ".join(result["context"]["notes"]),
        )


class TestTextDiffMode(unittest.TestCase):
    PRE = [
        "hostname sw",
        "!",
        "interface Vlan10",
        " description users",
        " ip address 10.10.0.2 255.255.255.0",
        "!",
        "router bgp 65010",
        " address-family ipv4",
        "  neighbor 192.0.2.1 activate",
        " exit-address-family",
        "end",
    ]
    POST = [
        "hostname sw",
        "!",
        "interface Vlan10",
        " description users floor 3",
        " ip address 10.10.0.2 255.255.255.0",
        " shutdown",
        "!",
        "router bgp 65010",
        " address-family ipv4",
        " exit-address-family",
        "end",
    ]

    def _diff(self, pre, post):
        return diffcore.diff_check(pre, post, {"mode": "text_diff"})

    def test_mode_is_registered(self):
        self.assertIn("text_diff", diffcore.MODES)

    def test_identical_texts_pass(self):
        view = {"running-config": {"lines": self.PRE}, "running-vs-startup": {"in_sync": True}}
        diff = self._diff(view, json.loads(json.dumps(view)))
        self.assertEqual(diff, {"result": "pass", "added": [], "removed": [], "changed": []})

    def test_one_changed_entry_per_hunk(self):
        diff = self._diff({"cfg": {"lines": self.PRE}}, {"cfg": {"lines": self.POST}})
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(
            diff["changed"],
            [
                {
                    "key": "cfg",
                    "field": "@@ -4 +4 @@",
                    "old": [" description users"],
                    "new": [" description users floor 3"],
                    "section": ["interface Vlan10"],
                },
                {
                    "key": "cfg",
                    "field": "@@ -5,0 +6 @@",
                    "old": [],
                    "new": [" shutdown"],
                    "section": ["interface Vlan10"],
                },
                {
                    "key": "cfg",
                    "field": "@@ -9 +9,0 @@",
                    "old": ["  neighbor 192.0.2.1 activate"],
                    "new": [],
                    "section": ["router bgp 65010", "address-family ipv4"],
                },
            ],
        )

    def test_hunk_headers_are_difflibs_own(self):
        headers = [
            line
            for line in difflib.unified_diff(self.PRE, self.POST, n=0, lineterm="")
            if line.startswith("@@")
        ]
        diff = self._diff({"cfg": {"lines": self.PRE}}, {"cfg": {"lines": self.POST}})
        self.assertEqual([entry["field"] for entry in diff["changed"]], headers)
        top = self._diff({"cfg": {"lines": ["a", "b"]}}, {"cfg": {"lines": ["z", "a", "b", "c"]}})
        self.assertEqual(
            [entry["field"] for entry in top["changed"]], ["@@ -0,0 +1 @@", "@@ -2,0 +4 @@"]
        )
        self.assertNotIn("section", top["changed"][0])

    def test_added_and_removed_texts_are_bounded(self):
        view = {"running-config": {"lines": self.PRE}, "startup-config": {"lines": self.POST}}
        removed = self._diff(view, {"running-config": {"lines": self.PRE}})
        self.assertEqual(
            removed["removed"], [{"key": "startup-config", "value": {"line_count": 11}}]
        )
        added = self._diff({"running-config": {"lines": self.PRE}}, view)
        self.assertEqual(added["added"], [{"key": "startup-config", "value": {"line_count": 11}}])
        self.assertEqual(added["result"], "diffs")

    def test_other_values_compare_like_equality_set(self):
        pre = {"running-vs-startup": {"in_sync": True}, "scalar": 1, "gone": {"a": 1}}
        post = {"running-vs-startup": {"in_sync": False}, "scalar": 2, "new": [1, 2]}
        self.assertEqual(
            self._diff(pre, post), diffcore.diff_check(pre, post, {"mode": "equality_set"})
        )
        compare = {"mode": "text_diff", "fields": {"n": {"tolerance": {"abs": 3}}}}
        within = diffcore.diff_check({"k": {"n": 10}}, {"k": {"n": 12}}, compare)
        self.assertEqual(within["result"], "pass")

    def test_a_text_that_stops_being_text_stays_bounded(self):
        diff = self._diff({"cfg": {"lines": self.PRE}}, {"cfg": "unreadable"})
        self.assertEqual(
            diff["changed"],
            [{"key": "cfg", "field": None, "old": {"line_count": 11}, "new": "unreadable"}],
        )

    def test_expectations_match_hunks_and_the_report_counts_them(self):
        exps, problems = diffcore.normalize_expectations(
            [
                {
                    "id": "e-desc",
                    "check": "iosxe_config",
                    "key": "running-config",
                    "op": "changed",
                    "to_contains": "floor 3",
                }
            ]
        )
        self.assertEqual(problems, [])
        diff = self._diff(
            {"running-config": {"lines": self.PRE}}, {"running-config": {"lines": self.POST}}
        )
        matched = set()
        counts = diffcore.classify_diff("iosxe_config", diff, exps, matched)
        self.assertEqual(counts, (1, 2))
        self.assertEqual(matched, {"e-desc"})
        self.assertEqual(diff["changed"][0]["classification"], "expected")
        report = {"checks": {"iosxe_config": diff}, "expectations": {}}
        envelope.summarize_report(report, exps, matched)
        self.assertEqual(report["summary"]["diffs_total"], 3)
        self.assertEqual(report["summary"]["expected"], 1)
        self.assertEqual(report["summary"]["unexpected"], 2)
        self.assertEqual(report["summary"]["checks_with_diffs"], 1)

    def test_collected_views_diff_as_hunks(self):
        pre, _ctx = _collect(outputs=_outputs(running=_as_running(STARTUP)))
        post, _ctx = _collect()
        diff = diffcore.diff_check(pre["normalized"], post["normalized"], {"mode": "text_diff"})
        by_key = {}
        for entry in diff["changed"]:
            by_key.setdefault(entry["key"], []).append(entry)
        self.assertEqual(sorted(by_key), ["running-config", "running-vs-startup"])
        self.assertEqual(
            [(entry["old"], entry["new"]) for entry in by_key["running-config"]],
            [
                ([" description printer"], [" description printer 3rd floor"]),
                ([], ["ip route 10.9.0.0 255.255.0.0 192.0.2.137"]),
            ],
        )
        self.assertEqual(by_key["running-config"][0]["section"], ["interface GigabitEthernet1/0/2"])
        self.assertEqual(
            by_key["running-vs-startup"],
            [
                {"key": "running-vs-startup", "field": "in_sync", "old": True, "new": False},
                {
                    "key": "running-vs-startup",
                    "field": "verbatim_in_sync",
                    "old": True,
                    "new": False,
                },
            ],
        )


class TestTextDiffAlignment(unittest.TestCase):
    """Hunks line up with stanzas, and a line repeated all over the text never merges edits."""

    PORT_CHANNEL_2 = [
        "interface Port-channel2",
        " description Downlink to IDF-2",
        " switchport mode trunk",
        " switchport trunk allowed vlan 10,20,30,100,925,926",
        "!",
    ]

    def _hunks(self, pre, post):
        diff = diffcore.diff_check(
            {"cfg": {"lines": pre}}, {"cfg": {"lines": post}}, {"mode": "text_diff"}
        )
        return diff["changed"]

    def test_a_stanza_added_after_a_look_alike_sibling_starts_at_its_own_head(self):
        # Port-channel1 ends with the same trunk lines and '!': difflib alone
        # starts the hunk inside Port-channel1 and names it as the section.
        body = RUNNING.splitlines()
        at = body.index("interface GigabitEthernet0/0")
        post = body[:at] + self.PORT_CHANNEL_2 + body[at:]
        (added,) = self._hunks(body, post)
        self.assertEqual((added["old"], added["new"]), ([], self.PORT_CHANNEL_2))
        self.assertNotIn("section", added)
        (removed,) = self._hunks(post, body)
        self.assertEqual((removed["old"], removed["new"]), (self.PORT_CHANNEL_2, []))
        self.assertNotIn("section", removed)

    def test_an_ap_entry_added_among_identical_siblings(self):
        def aps(numbers):
            lines = []
            for number in numbers:
                lines += [
                    "ap 0000.5e00.53%02x" % (number,),
                    " policy-tag PT-FLOOR3",
                    " rf-tag RF-TYPICAL",
                    " site-tag ST-BLDG1",
                ]
            return lines + ["end"]

        numbers = list(range(0, 120, 2))
        (added,) = self._hunks(aps(numbers), aps(sorted(numbers + [21])))
        self.assertEqual(added["new"], aps([21])[:-1])

    def test_equally_good_positions_keep_the_topmost(self):
        # A repeated line added next to its twin could be either one: always
        # the first, so two captures of the same edit give the same header.
        (added,) = self._hunks(
            ["interface A", " shutdown", "!"], ["interface A", " shutdown", " shutdown", "!"]
        )
        self.assertEqual(added["field"], "@@ -1,0 +2 @@")
        self.assertEqual(added["section"], ["interface A"])

    def test_two_edits_either_side_of_a_repeated_line_stay_two_hunks(self):
        # 48 identical access ports: ' switchport mode access' repeats in more
        # than 1% of the text, which difflib's autojunk never anchors on.
        pre = ["hostname sw", "!"]
        for port in range(1, 49):
            pre += [
                "interface GigabitEthernet1/0/%d" % (port,),
                " switchport access vlan 10",
                " switchport mode access",
                " switchport voice vlan 20",
                " spanning-tree portfast",
                "!",
            ]
        pre.append("end")
        post = list(pre)
        at = post.index("interface GigabitEthernet1/0/17")
        post[at + 1] = " switchport access vlan 11"
        post[at + 3] = " switchport voice vlan 21"
        hunks = self._hunks(pre, post)
        self.assertEqual(
            [(hunk["old"], hunk["new"]) for hunk in hunks],
            [
                ([" switchport access vlan 10"], [" switchport access vlan 11"]),
                ([" switchport voice vlan 20"], [" switchport voice vlan 21"]),
            ],
        )
        for hunk in hunks:
            self.assertEqual(hunk["section"], ["interface GigabitEthernet1/0/17"])

    def test_hunks_always_rebuild_the_post_text(self):
        # Refining and sliding never change what the hunks add up to, and the
        # lines between two hunks are always unchanged, one for one.
        vocab = ["!", "interface A", "interface B", " switchport mode access", " shutdown", "end"]
        rng = random.Random(7)
        for _ in range(500):
            old = [rng.choice(vocab) for _ in range(rng.randint(0, 30))]
            new = list(old)
            for _ in range(rng.randint(1, 5)):
                at = rng.randint(0, len(new))
                if rng.random() < 0.5:
                    new[at:at] = [rng.choice(vocab) for _ in range(rng.randint(1, 4))]
                else:
                    del new[at : at + rng.randint(1, 4)]
            rebuilt, old_at, new_at = [], 0, 0
            for _tag, i1, i2, j1, j2 in diffcore._text_opcodes(old, new):
                self.assertEqual(old[old_at:i1], new[new_at:j1], (old, new))
                rebuilt += old[old_at:i1] + new[j1:j2]
                old_at, new_at = i2, j2
            self.assertEqual(rebuilt + old[old_at:], new, (old, new))


class TestDiffSnapshotsTool(unittest.TestCase):
    """tools/diff_snapshots.py end to end on two synthetic snapshot files."""

    def _tool(self):
        path = _loader.ROOT / "tools" / "diff_snapshots.py"
        spec = importlib.util.spec_from_file_location("_diff_snapshots_under_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _snapshot(self, directory, kind, result):
        check = registry.CHECKS["iosxe_config"]
        env = envelope.new_envelope(
            {"name": "lab-9300-stk1"}, "CHG0000001", kind, "full", [check.id], {"user": "test"}
        )
        describe = {
            "description": check.description,
            "semantics": registry.SEMANTICS[check.id],
            "miss_meaning": check.miss_meaning,
        }
        envelope.record_check(
            env,
            check,
            "success",
            normalized=result["normalized"],
            describe=describe,
            context=result["context"],
        )
        path = pathlib.Path(directory) / ("snapshot_lab-9300-stk1_%s.json" % (kind,))
        path.write_text(json.dumps(env, indent=1, sort_keys=True))
        return str(path)

    def test_the_index_carries_hunks(self):
        tool = self._tool()
        pre, _ctx = _collect(outputs=_outputs(running=_as_running(STARTUP)))
        post, _ctx = _collect()
        with tempfile.TemporaryDirectory() as directory:
            args = [
                "--pre",
                self._snapshot(directory, "pre", pre),
                "--post",
                self._snapshot(directory, "post", post),
                "-o",
                str(pathlib.Path(directory) / "index.json"),
            ]
            with redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(tool.main(args), 0)
            index = json.loads((pathlib.Path(directory) / "index.json").read_text())
        body = index["pairs"]["lab-9300-stk1"]["checks"]["iosxe_config"]
        self.assertEqual(body["result"], "diffs")
        hunks = [entry for entry in body["changed"] if entry["key"] == "running-config"]
        self.assertEqual([entry["field"][:2] for entry in hunks], ["@@", "@@"])
        self.assertIn("semantics", body["describe"])
        summary = index["pairs"]["lab-9300-stk1"]["summary"]
        # two running-config hunks, in_sync and verbatim_in_sync
        self.assertEqual(summary["diffs_total"], 4)
        self.assertIn("1 with diffs (4 entries)", stderr.getvalue())
        self.assertNotIn("CANARY", json.dumps(index))


class TestRegistration(unittest.TestCase):
    def test_registered_as_a_tier_2_config_check(self):
        check = registry.CHECKS["iosxe_config"]
        self.assertEqual(check.platform, "iosxe")
        self.assertEqual(check.tier, 2)
        self.assertEqual(check.tags, ("config",))
        self.assertEqual(check.compare, {"mode": "text_diff"})
        self.assertIs(check.collector, checks._collect_config)
        self.assertIn("iosxe_config", registry.SEMANTICS)

    def test_every_command_rides_the_show_prefix(self):
        # The allowlist itself is locked in by test_transport_allowlist (the
        # one test module sanctioned to load a transport); this check only
        # needs the fact that every command here uses its `show ` prefix.
        _result, ctx = _collect()
        commands = [command for command, _kwargs in ctx.ssh.calls]
        self.assertEqual(commands, ["show running-config", "show startup-config", "show privilege"])
        for command in commands:
            self.assertTrue(command.startswith("show "), command)


if __name__ == "__main__":
    unittest.main()
