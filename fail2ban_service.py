import os
import subprocess
import configparser
from typing import Dict, Tuple, List

import re
from datetime import datetime, timedelta

class Fail2banService:

    def __init__(self, cmd: str = "fail2ban-client", use_sudo: bool = False):
        self.cmd = cmd
        self.use_sudo = use_sudo

    def _run(self, args: List[str], input_str: str | None = None) -> Tuple[bool, str, str, int]:
        full_cmd = []
        if self.use_sudo:
            full_cmd.extend(["sudo", "-n"])
        full_cmd.append(self.cmd)
        full_cmd.extend(args)
        try:
            proc = subprocess.run(full_cmd, input=input_str, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            ok = proc.returncode == 0
            return ok, proc.stdout, proc.stderr, proc.returncode
        except FileNotFoundError as e:
            return False, "", str(e), 127

    def status(self, jail: str | None = None):
        args = ["status"]
        if jail:
            args.append(jail)
        return self._run(args)

    def read_config_file(self, path: str):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return True, f.read(), "", 0
        except Exception as e:
            return False, "", str(e), 1

    def write_config_file(self, path: str, content: str, backup: bool = True):
        import datetime, shutil
        try:
            if backup and os.path.exists(path):
                ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                try:
                    shutil.copy2(path, f"{path}.bak.{ts}")
                except PermissionError:
                    if self.use_sudo:
                        subprocess.run(["sudo", "-n", "cp", "-a", path, f"{path}.bak.{ts}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                    else:
                        raise
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                return True, "", "", 0
            except PermissionError as pe:
                if self.use_sudo:
                    proc = subprocess.run(["sudo", "-n", "tee", path], input=content, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                    if proc.returncode == 0:
                        return True, "", "", 0
                    return False, "", proc.stderr, proc.returncode
                return False, "", str(pe), 1
        except Exception as e:
            return False, "", str(e), 1

    def ban(self, jail: str, ip: str):
        return self._run(["set", jail, "banip", ip])

    def unban(self, jail: str, ip: str):
        return self._run(["set", jail, "unbanip", ip])

    def reload(self, jail: str | None = None):
        if jail:
            return self._run(["reload", jail])
        return self._run(["reload"]) 

    def restart(self, jail: str | None = None):
        if jail:
            return self._run(["restart", jail])
        return self._run(["restart"])

    def get_banned_with_times(self, jail: str):
        """
        Best-effort: try to get banned IPs with timestamps if Fail2ban supports it.
        Returns (ok, mapping, err, code) where mapping is {ip: 'YYYY-MM-DD HH:MM:SS'} when known.
        """
        candidates = [
            ["get", jail, "banip", "--with-time"],
            ["banned", jail, "--with-time"],
            ["get", jail, "banip", "--with-timestamp"],
        ]
        ip_ts: Dict[str, str] = {}
        last_err = ""
        last_code = 0
        ip_rx = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})")
        ts_rx = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
        for args in candidates:
            ok, out, err, code = self._run(args)
            if not ok:
                last_err, last_code = (err or out), code
                continue
            # Parse output lines; associate nearest timestamp appearing after IP
            for line in (out or "").splitlines():
                ips = list(ip_rx.finditer(line))
                tss = list(ts_rx.finditer(line))
                if not ips:
                    continue
                if tss:
                    # assign closest timestamp to each ip (fallback: first ts)
                    ts_str = tss[0].group("ts")
                    for m in ips:
                        ip = m.group("ip")
                        ip_ts[ip] = ts_str.replace("T", " ")
                else:
                    # if no timestamp found on line, keep parsing other lines; may have format ip ts on separate tokens
                    pass
            if ip_ts:
                return True, ip_ts, "", 0
        return False, {}, last_err, last_code

    def get_option(self, jail: str, option: str):
        return self._run(["get", jail, option])

    def set_option(self, jail: str, option: str, value: str | int):
        return self._run(["set", jail, option, str(value)])

    def get_jail_options(self, jail: str, options: list[str]):
        values: Dict[str, str] = {}
        for opt in options:
            ok, out, err, code = self.get_option(jail, opt)
            if not ok:
                return False, {}, f"Erreur get {opt}: {err or out}", code
            values[opt] = (out or "").strip()
        return True, values, "", 0

    def set_jail_options(self, jail: str, options: Dict[str, str | int]):
        for opt, val in options.items():
            ok, out, err, code = self.set_option(jail, opt, val)
            if not ok:
                return False, f"Erreur set {opt}={val}: {err or out}", code
        return True, "", 0

    def read_jail_conf(self, path: str):
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                cp.read_file(f)
            return True, cp, "", 0
        except Exception as e:
            return False, None, str(e), 1

    def write_jail_conf(self, path: str, cp: configparser.ConfigParser, backup: bool = True):
        import io, datetime, shutil
        content_io = io.StringIO()
        cp.write(content_io)
        content = content_io.getvalue()
        ok, _out, err, code = self.write_config_file(path, content, backup=backup)
        if ok:
            return True, "", 0
        return False, err, code

def parse_global_status(output: str) -> Dict:
    jails: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("`- jail list:") or line.lower().startswith("- jail list:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                raw = parts[1].strip()
                raw = raw.replace(",", " ")
                jails = [x.strip() for x in raw.split() if x.strip()]
    return {"jails": jails}

def parse_jail_status(output: str) -> Dict:
    result: Dict[str, int | List[str]] = {
        "currently_failed": 0,
        "total_failed": 0,
        "currently_banned": 0,
        "total_banned": 0,
        "banned_list": [],
    }
    for line in output.splitlines():
        s = line.strip()
        low = s.lower()
        if "currently failed:" in low:
            try:
                result["currently_failed"] = int(s.split(":", 1)[1].strip())
            except Exception:
                pass
        elif "total failed:" in low:
            try:
                result["total_failed"] = int(s.split(":", 1)[1].strip())
            except Exception:
                pass
        elif "currently banned:" in low:
            try:
                result["currently_banned"] = int(s.split(":", 1)[1].strip())
            except Exception:
                pass
        elif "total banned:" in low:
            try:
                result["total_banned"] = int(s.split(":", 1)[1].strip())
            except Exception:
                pass
        elif "banned ip list:" in low:
            raw = s.split(":", 1)[1].strip()
            ips = [x.strip() for x in raw.split() if x.strip()]
            result["banned_list"] = ips
    return result
