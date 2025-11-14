#!/usr/bin/env python3
"""
SynthicSoft ProcGuard v4.0 (Hybrid EDR Sentinel)
-----------------------------------------------
Windows 10/11 Home compatible • psutil-only dependency • Fully active out-of-box.

Features:
- Hybrid ML-style scoring (No sklearn/numpy needed)
- Baseline deviation scoring (optional, works without it)
- Heuristics (LOLBins, ports, parents, entropy, cmdline patterns)
- Auto-mitigation (Kill + Block IP)
- JSONL logging with rotation
- No dry-run • Firewall actions REAL

Dependency:
    pip install psutil
"""

import argparse
import json
import math
import os
import platform
import signal
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, UTC
from typing import Dict, List, Optional, Tuple

import psutil

BANNER = r"""
███████╗██╗   ██╗███╗   ██╗████████╗██╗███╗   ██╗ ██████╗███████╗██████╗ ██╗     
██╔════╝██║   ██║████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██╔════╝██╔══██╗██║     
███████╗██║   ██║██╔██╗ ██║   ██║   ██║██╔██╗ ██║██║     █████╗  ██████╔╝██║     
╚════██║██║   ██║██║╚██╗██║   ██║   ██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗██║     
███████║╚██████╔╝██║ ╚████║   ██║   ██║██║ ╚████║╚██████╗███████╗██║  ██║███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝

        SynthicSoft ProcGuard v4.0 - HYBRID SENTINEL
 [ Auto-Kill | Auto-Block | Hybrid ML + Heuristics | No Dry Run | UTC Safe ]
"""

DEFAULT_CONFIG_PATH = "procguard_config.json"
DEFAULT_EVENT_LOG = "procguard_events.jsonl"
DEFAULT_BASELINE_PATH = "procguard_baseline.json"

DEFAULT_CONFIG = {
    "threshold": 0.70,
    "auto_kill": True,
    "auto_block": True,
    "firewall_dry_run": False,
    "scan_interval": 5.0,
    "baseline_duration": 180,
    "max_events_per_minute": 500,
    "event_log_path": DEFAULT_EVENT_LOG,
    "baseline_path": DEFAULT_BASELINE_PATH,
    "whitelist_process_names": [
        "system", "csrss.exe", "services.exe", "lsass.exe", "wininit.exe", "winlogon.exe"
    ],
    "whitelist_users": [
        "system", "root", "local service", "network service"
    ],
    "blacklist_process_names": [
        "mimikatz.exe", "procdump.exe", "netcat.exe", "nc.exe",
        "cobaltstrike.exe", "svch0st.exe", "svchosts.exe"
    ],
    "alert_on_listen_ports": True,
    "alert_on_remote_connections": True,
    "escalation_score_boost": 0.10,
    "max_log_size_mb": 5,
    "rotation_backups": 3,
}

KNOWN_BAD_NAMES = {
    "mimikatz.exe", "procdump.exe", "cobaltstrike.exe", "nc.exe",
    "netcat.exe", "svch0st.exe", "svchosts.exe",
    "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"
}

SUSPICIOUS_PORTS = {4444, 1337, 8080, 9050, 3389, 23, 22, 1433}


# ---------------- CONFIG ----------------

class ConfigManager:
    def __init__(self, path: str = DEFAULT_CONFIG_PATH):
        self.path = path
        self.config = DEFAULT_CONFIG.copy()
        self._load_or_create()

    def _load_or_create(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.config.update(data)
                print(f"[Config] Loaded {self.path}")
            except Exception as e:
                print(f"[Config] Load error: {e} — using defaults.")
        else:
            try:
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.config, f, indent=2)
                print(f"[Config] Created default config at {self.path}")
            except Exception as e:
                print(f"[Config] Creation failed: {e}")

    def apply_cli_overrides(self, args: argparse.Namespace):
        if args.threshold is not None:
            self.config["threshold"] = args.threshold
        if args.interval is not None:
            self.config["scan_interval"] = args.interval
        if args.event_log is not None:
            self.config["event_log_path"] = args.event_log
        if args.baseline_path is not None:
            self.config["baseline_path"] = args.baseline_path
        if args.auto_kill:
            self.config["auto_kill"] = True
        if args.auto_block:
            self.config["auto_block"] = True
        if args.no_firewall_dry_run:
            self.config["firewall_dry_run"] = False


# ---------------- LOGGING ----------------

@dataclass
class SuspiciousEvent:
    timestamp: str
    host: str
    pid: int
    ppid: int
    name: str
    username: str
    score: float
    reason: str
    cpu_percent: float
    mem_percent: float
    num_threads: int
    connections: List[Dict]
    action_taken: Optional[str] = None
    ancestry: Optional[str] = None
    exe_path: Optional[str] = None
    entropy: Optional[float] = None
    cmdline: Optional[str] = None


class EventLogger:
    def __init__(self, path: str, max_size_mb: int, backups: int):
        self.path = path
        self.max_bytes = max_size_mb * 1024 * 1024
        self.backups = backups

    def _rotate_if_needed(self):
        if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
            for i in range(self.backups, 0, -1):
                src = f"{self.path}.{i}"
                dst = f"{self.path}.{i+1}"
                if os.path.exists(src):
                    if i == self.backups:
                        os.remove(src)
                    else:
                        os.rename(src, dst)
            os.rename(self.path, f"{self.path}.1")

    def log(self, event: SuspiciousEvent):
        self._rotate_if_needed()
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception as e:
            print(f"[EventLogger] Failed to write event: {e}")


# ---------------- FIREWALL ----------------

class FirewallManager:
    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self.system = platform.system().lower()

    def block_ip(self, ip: str):
        if not self.system.startswith("win"):
            print(f"[Firewall] Non-Windows OS: would block {ip}")
            return

        cmd = (
            'netsh advfirewall firewall add rule '
            f'name=\"ProcGuard_{ip}\" dir=out action=block remoteip={ip}'
        )

        if self.dry_run:
            print(f"[Firewall] (DRY-RUN) Would block {ip}: {cmd}")
            return

        print(f"[Firewall] BLOCKING IP: {ip}")
        os.system(cmd)


# ---------------- BASELINE ----------------

class BaselineManager:
    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Dict[str, float]] = {}

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                print(f"[Baseline] Loaded from {self.path}")
            except:
                print("[Baseline] Failed to load baseline.")
        else:
            print("[Baseline] No baseline file found.")

    def update(self, info: Dict[str, float]):
        for k, v in info.items():
            if k not in self.data:
                self.data[k] = {"min": v, "max": v, "sum": v, "count": 1}
            else:
                d = self.data[k]
                d["min"] = min(d["min"], v)
                d["max"] = max(d["max"], v)
                d["sum"] += v
                d["count"] += 1

    def save(self):
        try:
            for k, d in self.data.items():
                d["avg"] = d["sum"] / max(1, d["count"])
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            print(f"[Baseline] Saved to {self.path}")
        except Exception as e:
            print(f"[Baseline] Save failed: {e}")

    def deviation_score(self, info: Dict[str, float]) -> float:
        if not self.data:
            return 0.0
        total = 0.0
        count = 0
        for k, v in info.items():
            if k not in self.data:
                continue
            d = self.data[k]
            if d["max"] == d["min"]:
                continue
            dist = abs(v - d["avg"]) / (d["max"] - d["min"])
            total += dist
            count += 1
        if count == 0:
            return 0.0
        return min(total / count, 1.0)


# ---------------- STATE TRACKING ----------------

class ProcessStateTracker:
    def __init__(self):
        self.state: Dict[int, Dict] = {}

    def update(self, pid: int, score: float) -> Dict:
        now = time.time()
        if pid not in self.state:
            self.state[pid] = {
                "first_seen": now,
                "last_seen": now,
                "last_score": score,
                "alert_count": 0,
            }
        else:
            self.state[pid]["last_seen"] = now
            self.state[pid]["last_score"] = score
        return self.state[pid]

    def increment_alert(self, pid: int) -> Dict:
        if pid not in self.state:
            self.update(pid, 0)
        self.state[pid]["alert_count"] += 1
        return self.state[pid]


class RateLimiter:
    def __init__(self, max_per_min: int):
        self.max = max_per_min
        self.window_start = time.time()
        self.count = 0

    def allow(self) -> bool:
        now = time.time()
        if now - self.window_start >= 60:
            self.window_start = now
            self.count = 0
        if self.count >= self.max:
            return False
        self.count += 1
        return True


# ---------------- HYBRID MODEL ----------------

class HybridModel:
    """
    Hybrid scoring (ML-style + DT-style rules + heuristics)
    """

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        length = len(data)
        ent = 0.0
        for count in freq.values():
            p = count / length
            ent -= p * math.log2(p)
        return ent

    def _approx_entropy_for_exe(self, path: str) -> float:
        if not path or not os.path.isfile(path):
            return 0.0
        try:
            with open(path, "rb") as f:
                chunk = f.read(65536)
            return round(self._shannon_entropy(chunk), 3)
        except:
            return 0.0

    def extract_features(
        self, proc: psutil.Process, conns: List[psutil._common.sconn]
    ) -> Tuple[List[float], Dict, Dict]:
        try:
            cpu = proc.cpu_percent(interval=None)
            mem = proc.memory_percent()
            threads = proc.num_threads()
            name = (proc.name() or "").lower()
            user = (proc.username() or "").lower()
            exe = proc.exe() if hasattr(proc, "exe") else None
            cmdline_list = proc.cmdline()
            cmdline = " ".join(cmdline_list) if cmdline_list else ""
            num_conns = len(conns)
            is_system = int(user in ("system", "root", "local service", "network service"))

            has_remote, is_listen = 0, 0
            for c in conns:
                if c.raddr:
                    has_remote = 1
                if c.status == psutil.CONN_LISTEN:
                    is_listen = 1

            ancestry = []
            parent_name = ""
            try:
                parent = proc.parent()
                if parent:
                    parent_name = (parent.name() or "").lower()
                    ancestry.append(parent_name)
                    gp = parent.parent()
                    if gp:
                        ancestry.append((gp.name() or "").lower())
            except:
                pass

            ancestry_str = " > ".join(ancestry)
            entropy = self._approx_entropy_for_exe(exe) if exe else 0.0

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return [], {}, {}

        numeric_info = {
            "cpu_percent": cpu,
            "mem_percent": mem,
            "num_threads": threads,
            "num_connections": num_conns,
            "is_system": is_system,
            "has_remote": has_remote,
            "is_listen": is_listen,
            "entropy": entropy,
        }

        meta_info = {
            "name": name,
            "user": user,
            "exe": exe,
            "cmdline": cmdline,
            "ancestry": ancestry_str,
            "parent_name": parent_name,
        }

        features = [
            cpu,
            mem,
            threads,
            num_conns,
            is_system,
            has_remote,
            is_listen,
            entropy,
        ]
        return features, numeric_info, meta_info

    def score(self, f: List[float], meta: Dict) -> float:
        if not f:
            return 0.0

        (
            cpu,
            mem,
            threads,
            conns,
            is_system,
            has_remote,
            is_listen,
            entropy,
        ) = f

        name = meta.get("name", "")
        parent = meta.get("parent_name", "")
        cmdline = meta.get("cmdline", "")

        score = 0.0

        # CPU
        if cpu > 85:
            score += 0.35
        elif cpu > 60:
            score += 0.25
        elif cpu > 30:
            score += 0.10

        # MEM
        if mem > 70:
            score += 0.25
        elif mem > 40:
            score += 0.15

        # connections
        if conns > 50:
            score += 0.20
        elif conns > 20:
            score += 0.15
        elif conns > 5:
            score += 0.05

        # remote/listen
        if has_remote:
            score += 0.10
        if is_listen:
            score += 0.10

        # threads
        if threads > 220:
            score += 0.15
        elif threads > 60:
            score += 0.05

        # entropy
        if entropy > 7.2:
            score += 0.25
        elif entropy > 6.5:
            score += 0.15

        # LOLBIN rules
        lname = name.lower()
        lparent = parent.lower()

        if lname in {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            if "-enc" in cmdline.lower() or "frombase64string" in cmdline.lower():
                score += 0.35
            else:
                score += 0.15

        # Office spawning interpreter
        if lparent in {"winword.exe", "excel.exe", "outlook.exe"}:
            if lname in {"powershell.exe", "cmd.exe", "wscript.exe"}:
                score += 0.35

        # high-risk combination
        if not is_system and has_remote and cpu > 60 and conns > 20:
            score += 0.30

        return min(score, 1.0)


# ---------------- PROC GUARD ENGINE ----------------

class ProcGuard:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = EventLogger(
            path=config["event_log_path"],
            max_size_mb=config["max_log_size_mb"],
            backups=config["rotation_backups"],
        )
        self.firewall = FirewallManager(dry_run=config["firewall_dry_run"])
        self.model = HybridModel()
        self.baseline = BaselineManager(config["baseline_path"])
        self.baseline.load()

        self.whitelist_names = {n.lower() for n in config["whitelist_process_names"]}
        self.whitelist_users = {u.lower() for u in config["whitelist_users"]}
        self.blacklist_names = {n.lower() for n in config["blacklist_process_names"]}

        self.threshold = config["threshold"]
        self.auto_kill = config["auto_kill"]
        self.auto_block = config["auto_block"]
        self.escalation_boost = config["escalation_score_boost"]

        self.alert_on_listen = config["alert_on_listen_ports"]
        self.alert_on_remote = config["alert_on_remote_connections"]

        self.state = ProcessStateTracker()
        self.rate = RateLimiter(config["max_events_per_minute"])
        self.hostname = platform.node() or "host"

        self.scan_count = 0
        self.alert_count = 0
        self.kill_count = 0
        self.block_count = 0
        self.last_stats = time.time()

    def _get_conns(self, proc: psutil.Process):
        try:
            return proc.net_connections(kind="inet")
        except:
            return []

    def _heuristics(self, name: str, user: str, info: Dict, conns):
        boost = 0.0
        reasons = []

        lname = name.lower()
        luser = user.lower()

        if lname in self.whitelist_names or luser in self.whitelist_users:
            reasons.append("whitelisted")
            return -0.5, reasons

        if lname in self.blacklist_names:
            boost += 0.6
            reasons.append("user_blacklist")

        if lname in KNOWN_BAD_NAMES:
            boost += 0.5
            reasons.append("known_bad_name")

        for c in conns:
            try:
                if c.raddr and c.raddr.port in SUSPICIOUS_PORTS:
                    boost += 0.3
                    reasons.append(f"bad_port:{c.raddr.port}")
                    break
            except:
                pass

        cpu = info.get("cpu_percent", 0)
        mem = info.get("mem_percent", 0)

        if cpu > 75:
            boost += 0.20
            reasons.append("high_cpu")
        if mem > 75:
            boost += 0.20
            reasons.append("high_mem")

        if not info.get("is_system", 0) and info.get("num_connections", 0) > 25:
            boost += 0.25
            reasons.append("many_conn_non_system")

        if self.alert_on_remote and info.get("has_remote", 0):
            boost += 0.10
            reasons.append("remote_connections")

        if self.alert_on_listen and info.get("is_listen", 0):
            boost += 0.10
            reasons.append("listening")

        ent = info.get("entropy", 0)
        if ent > 7.2:
            boost += 0.20
            reasons.append("high_entropy")

        return boost, reasons

    def _format_conns(self, conns):
        out = []
        for c in conns:
            try:
                out.append({
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status,
                })
            except:
                pass
        return out

    def monitor_once(self):
        self.scan_count += 1

        for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "username"]):
            try:
                pinfo = proc.info
            except:
                continue

            pid = pinfo.get("pid")
            name = pinfo.get("name") or ""
            user = pinfo.get("username") or ""

            if pid == os.getpid():
                continue

            conns = self._get_conns(proc)
            features, numeric_info, meta_info = self.model.extract_features(proc, conns)
            if not features:
                continue

            ml_score = self.model.score(features, meta_info)
            baseline_dev = self.baseline.deviation_score(numeric_info)
            boost, reasons = self._heuristics(name, user, numeric_info, conns)

            st = self.state.update(pid, ml_score)
            if st.get("alert_count", 0) > 3:
                boost += self.escalation_boost
                reasons.append("repeated_offender")

            score = ml_score + 0.35 * baseline_dev + boost
            score = min(max(score, 0.0), 1.0)

            if score < self.threshold:
                continue

            st = self.state.increment_alert(pid)
            action = None

            if self.auto_kill and pid not in (0, 4):
                try:
                    proc.terminate()
                    action = "terminated"
                    self.kill_count += 1
                except:
                    pass

            if self.auto_block:
                for c in conns:
                    try:
                        if c.raddr:
                            self.firewall.block_ip(c.raddr.ip)
                            self.block_count += 1
                            action = (action + "+blocked_ips") if action else "blocked_ips"
                    except:
                        pass

            event = SuspiciousEvent(
                timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                host=self.hostname,
                pid=pid,
                ppid=pinfo.get("ppid"),
                name=name,
                username=user,
                score=score,
                reason=",".join(reasons) if reasons else "ml+baseline",
                cpu_percent=numeric_info.get("cpu_percent", 0),
                mem_percent=numeric_info.get("mem_percent", 0),
                num_threads=numeric_info.get("num_threads", 0),
                connections=self._format_conns(conns),
                action_taken=action,
                ancestry=meta_info.get("ancestry"),
                exe_path=meta_info.get("exe"),
                entropy=numeric_info.get("entropy", 0),
                cmdline=meta_info.get("cmdline"),
            )

            if self.rate.allow():
                self.logger.log(event)
                print(f"[ALERT] PID={pid} name={name} user={user} score={score:.2f} reason={event.reason} action={action}")
                self.alert_count += 1
            else:
                print("[RateLimiter] Dropping event (limit reached).")

    def run_monitor_loop(self, interval: float):
        print(
            f"[ProcGuard] HYBRID SENTINEL ACTIVE | interval={interval}s | threshold={self.threshold} "
            f"| auto_kill={self.auto_kill} | auto_block={self.auto_block}"
        )
        while True:
            try:
                self.monitor_once()
                now = time.time()
                if now - self.last_stats > 60:
                    print(
                        f"[Stats] scans={self.scan_count} alerts={self.alert_count} "
                        f"kills={self.kill_count} blocks={self.block_count}"
                    )
                    self.last_stats = now
                time.sleep(interval)
            except KeyboardInterrupt:
                print("[ProcGuard] Stopped by user.")
                break


# ---------------- BASELINE MODE ----------------

def run_baseline(config: Dict):
    duration = config["baseline_duration"]
    interval = config["scan_interval"]
    path = config["baseline_path"]

    print(f"[Baseline] Running for {duration}s...")

    model = HybridModel()
    baseline = BaselineManager(path)
    start = time.time()

    while time.time() - start < duration:
        for proc in psutil.process_iter(attrs=["pid"]):
            try:
                p = psutil.Process(proc.info["pid"])
                conns = p.net_connections(kind="inet")
                _, numeric_info, _ = model.extract_features(p, conns)
                if numeric_info:
                    baseline.update(numeric_info)
            except:
                continue
        time.sleep(interval)

    baseline.save()
    print("[Baseline] Complete.")


# ---------------- CLI & MAIN ----------------

def parse_args():
    p = argparse.ArgumentParser(description="SynthicSoft ProcGuard v4.0 Hybrid Sentinel")
    p.add_argument("--mode", choices=["monitor", "baseline"], default="monitor")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    p.add_argument("--interval", type=float)
    p.add_argument("--threshold", type=float)
    p.add_argument("--event-log")
    p.add_argument("--baseline-path")
    p.add_argument("--auto-kill", action="store_true")
    p.add_argument("--auto-block", action="store_true")
    p.add_argument("--no-firewall-dry-run", action="store_true")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    cfg_mgr = ConfigManager(path=args.config)
    cfg_mgr.apply_cli_overrides(args)
    config = cfg_mgr.config

    if args.mode == "baseline":
        run_baseline(config)
        return

    guard = ProcGuard(config)
    guard.run_monitor_loop(interval=config["scan_interval"])


if __name__ == "__main__":
    if platform.system().lower().startswith("win"):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
