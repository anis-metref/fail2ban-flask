import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Dict, Tuple, Optional

LINE_PARSER = re.compile(r"(?P<ts>^[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+[^:]+:\s+(?P<msg>.+)$")
IP_REGEX = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})")

PATTERNS = [
    ("accepted", re.compile(r"Accepted\s+(?P<method>\w+)\s+for\s+(?P<user>[\w.-]+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)")),
    ("failed", re.compile(r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>[\w.-]+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)")),
    ("invalid", re.compile(r"Invalid\s+user\s+(?P<user>[\w.-]+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)")),
    ("disconnect", re.compile(r"Disconnect\s+from\s+(?:(?:invalid\s+)?user\s+)?(?P<user>[\w.-]+)?\s*(?P<ip>\S+)\s+port\s+(?P<port>\d+)")),
    ("maxauth", re.compile(r"maximum\s+authentication\s+attempts\s+exceeded\s+for\s+(?:(?:invalid\s+)?user\s+)?(?P<user>[\w.-]+)\s+from\s+(?P<ip>\S+)")),
]

class SshAnalysisService:
    def __init__(self, use_sudo: bool = False, source: Optional[str] = None, log_file: Optional[str] = None):
        self.use_sudo = use_sudo
        self.source = (source or os.getenv("SSH_SOURCE", "journalctl")).lower()
        self.log_file = log_file or os.getenv("SSH_LOG_FILE", "/var/log/auth.log")

    def _run(self, args: List[str]) -> Tuple[bool, str, str, int]:
        full_cmd = []
        if self.use_sudo:
            full_cmd.extend(["sudo", "-n"])
        full_cmd.extend(args)
        try:
            proc = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            return proc.returncode == 0, proc.stdout, proc.stderr, proc.returncode
        except FileNotFoundError as e:
            return False, "", str(e), 127

    def fetch_raw_lines(self, since: str = "24 hours ago", max_lines: int = 5000) -> Tuple[bool, List[str], str]:
        if self.source == "journalctl":
            args = [
                "journalctl", "-u", "sshd", "-u", "ssh", "--since", since, "--no-pager", "-o", "short-iso",
            ]
            ok, out, err, code = self._run(args)
            if ok:
                lines = out.splitlines()
                return True, lines[-max_lines:], ""
            file_error = None
            try:
                with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                return True, lines[-max_lines:], ""
            except Exception as e:
                file_error = e
            try:
                alt_path = "/var/log/secure"
                if self.log_file != alt_path:
                    with open(alt_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    return True, lines[-max_lines:], ""
            except Exception as e2:
                pass
            return False, [], f"journalctl error: {err or out}. File errors: {file_error}"
        try:
            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            return True, lines[-max_lines:], ""
        except Exception as e:
            try:
                alt_path = "/var/log/secure"
                if self.log_file != alt_path:
                    with open(alt_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    return True, lines[-max_lines:], ""
            except Exception:
                pass
            return False, [], str(e)

    def parse_event(self, line: str) -> Optional[Dict]:
        m = LINE_PARSER.search(line.strip())
        if not m:
            return None
        ts_raw = m.group("ts").strip()
        msg = m.group("msg").strip()
        for typ, rx in PATTERNS:
            mm = rx.search(msg)
            if mm:
                d = {"type": typ, "message": msg}
                if mm.groupdict().get("user"):
                    d["user"] = mm.group("user")
                if mm.groupdict().get("ip"):
                    d["ip"] = mm.group("ip")
                if mm.groupdict().get("method"):
                    d["method"] = mm.group("method")
                d["ts"] = ts_raw
                return d
        ipm = IP_REGEX.search(msg)
        if ipm:
            return {"type": "other", "message": msg, "ip": ipm.group("ip"), "ts": ts_raw}
        return None

    def parse_events(self, lines: List[str]) -> List[Dict]:
        events: List[Dict] = []
        for ln in lines:
            ev = self.parse_event(ln)
            if ev:
                events.append(ev)
        return events

    def analyze(self, events: List[Dict]) -> Dict:
        totals = Counter()
        by_ip_fail = Counter()
        by_ip_ok = Counter()
        by_user_fail = Counter()
        by_user_ok = Counter()
        for ev in events:
            typ = ev.get("type")
            if typ:
                totals[typ] += 1
            ip = ev.get("ip")
            user = ev.get("user")
            if typ == "failed":
                if ip:
                    by_ip_fail[ip] += 1
                if user:
                    by_user_fail[user] += 1
            elif typ == "accepted":
                if ip:
                    by_ip_ok[ip] += 1
                if user:
                    by_user_ok[user] += 1
        return {
            "totals": dict(totals),
            "top_failed_ips": by_ip_fail.most_common(10),
            "top_accepted_ips": by_ip_ok.most_common(10),
            "top_failed_users": by_user_fail.most_common(10),
            "top_accepted_users": by_user_ok.most_common(10),
            "events": events[-200:],
        }

    def fetch_and_analyze(self, since: str = "24 hours ago", max_lines: int = 5000) -> Tuple[bool, Dict, str]:
        ok, lines, err = self.fetch_raw_lines(since=since, max_lines=max_lines)
        if not ok:
            return False, {}, err
        evs = self.parse_events(lines)
        return True, self.analyze(evs), ""
