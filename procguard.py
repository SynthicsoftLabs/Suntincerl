#!/usr/bin/env python3
"""
SuntinCerl ProcGuard v6.0.0
Windows Hybrid EDR Sentinel — SynthicSoft Labs
Enhanced Edition with Advanced Detection & Rich Layman UI

Improvements in v6.0:
- Process tree anomaly detection
- File system monitoring for suspicious writes
- Persistence mechanism detection
- Network beaconing detection
- Memory injection indicators
- Improved parent-child relationship analysis
- Performance optimizations
- Enhanced threat intelligence
"""

import argparse, hashlib, json, math, os, platform, signal, sys, time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, UTC
from typing import Dict, List, Optional, Tuple, Set, Deque
import psutil

# ======================================================
# COLOR + BANNER
# ======================================================

class C:
    R = "\033[91m"
    Y = "\033[93m"
    G = "\033[92m"
    B = "\033[94m"
    C = "\033[96m"
    W = "\033[97m"
    D = "\033[90m"
    M = "\033[95m"
    X = "\033[0m"

def color(text: str, col: str, enabled: bool) -> str:
    return f"{col}{text}{C.X}" if enabled else text

BANNER = r"""
███████╗██╗   ██╗███╗   ██╗████████╗██╗███╗   ██╗ ██████╗███████╗██████╗ 
██╔════╝██║   ██║████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██╔════╝██╔══██╗
███████╗██║   ██║██╔██╗ ██║   ██║   ██║██╔██╗ ██║██║     █████╗  ██████╔╝
╚════██║██║   ██║██║╚██╗██║   ██║   ██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗
███████║╚██████╔╝██║ ╚████║   ██║   ██║██║ ╚████║╚██████╗███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝
                    ProcGuard v6.0 - Enhanced Detection Suite
"""

# ======================================================
# CONFIG
# ======================================================

DEFAULT_CONFIG_PATH = "procguard_config.json"
DEFAULT_EVENT_LOG = "procguard_events.jsonl"
DEFAULT_BASELINE_PATH = "procguard_baseline.json"
HTTPS_PORT = 443
HTTP_PORT = 80
DNS_PORT = 53

HIGH_RISK_PORTS = {4444, 3389, 5900, 22, 23, 9050, 1337, 1433, 3306, 5432, 6379}

DEFAULT_CONFIG: Dict[str, object] = {
    "threshold": 0.82,
    "scan_interval": 5.0,
    "safe_mode": True,
    "auto_kill": False,
    "auto_block": False,
    "firewall_dry_run": True,
    "event_log_path": DEFAULT_EVENT_LOG,
    "baseline_path": DEFAULT_BASELINE_PATH,
    "baseline_duration": 180,
    "max_events_per_minute": 400,
    "max_log_size_mb": 5,
    "rotation_backups": 3,
    "escalation_score_boost": 0.18,
    "ui_mode": "layman",
    "color_output": True,
    "enable_file_monitoring": True,
    "enable_persistence_detection": True,
    "enable_network_beaconing": True,
    "enable_process_tree_analysis": True,
    "beaconing_window": 300,  # 5 minutes
    "beaconing_tolerance": 10,  # seconds
    "everyday_apps": [
        "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
        "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "outlook.exe",
        "notepad.exe", "wordpad.exe", "code.exe", "notepad++.exe",
        "explorer.exe", "dllhost.exe", "runtimebroker.exe",
        "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
        "taskmgr.exe", "dwm.exe", "conhost.exe", "fontdrvhost.exe"
    ],
    "known_bad_names": [
        "mimikatz.exe", "procdump.exe", "cobaltstrike.exe",
        "nc.exe", "netcat.exe", "pscp.exe", "plink.exe",
        "certutil.exe", "bitsadmin.exe"
    ],
    "suspicious_lolbins": [
        "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "regsvr32.exe", "rundll32.exe", "wmic.exe", "certutil.exe"
    ],
    "trusted_domains": [
        "github.com", "githubusercontent.com", "openai.com", "chat.openai.com",
        "google.com", "microsoft.com", "cloudflare.com", "windows.com"
    ],
    "alert_on_listen_ports": True,
    "alert_on_remote_connections": True,
}

# ======================================================
# UTILITY
# ======================================================

def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")

def calc_entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    freq: Dict[int, int] = {}
    for b in chunk:
        freq[b] = freq.get(b, 0) + 1
    e = 0.0
    total = len(chunk)
    for c in freq.values():
        p = c / total
        e -= p * math.log2(p)
    return e

def file_entropy(path: Optional[str]) -> float:
    if not path or not os.path.isfile(path):
        return 0.0
    try:
        with open(path, "rb") as f:
            chunk = f.read(65536)
        return round(calc_entropy(chunk), 3)
    except Exception:
        return 0.0

def classify_ip(ip: str) -> str:
    try:
        parts = list(map(int, ip.split(".")))
        if ip == "127.0.0.1":
            return "loopback"
        if parts[0] == 10:
            return "private"
        if parts[0] == 192 and parts[1] == 168:
            return "private"
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return "private"
        return "public"
    except Exception:
        return "unknown"

# ======================================================
# CONFIG MANAGER
# ======================================================

class ConfigManager:
    def __init__(self, path: str):
        self.path = path
        self.config: Dict[str, object] = DEFAULT_CONFIG.copy()
        self.load()

    def load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.config.update(data)
            except Exception:
                pass
        else:
            try:
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.config, f, indent=2)
            except Exception:
                pass

    def apply_cli(self, a: argparse.Namespace) -> None:
        if a.threshold is not None:
            self.config["threshold"] = a.threshold
        if a.interval is not None:
            self.config["scan_interval"] = a.interval
        if a.event_log:
            self.config["event_log_path"] = a.event_log
        if a.baseline_path:
            self.config["baseline_path"] = a.baseline_path
        if a.ui_mode:
            self.config["ui_mode"] = a.ui_mode
        if a.no_color:
            self.config["color_output"] = False
        if a.enforce:
            self.config["safe_mode"] = False
            self.config["auto_kill"] = True
            self.config["auto_block"] = True
            self.config["firewall_dry_run"] = False

# ======================================================
# HASH CACHE
# ======================================================

class HashCache:
    def __init__(self):
        self.cache: Dict[str, str] = {}
        self.initial: Dict[str, str] = {}

    def sha256(self, path: Optional[str]) -> Optional[str]:
        if not path or not os.path.isfile(path):
            return None
        if path in self.cache:
            return self.cache[path]
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            digest = h.hexdigest()
            self.cache[path] = digest
            if path not in self.initial:
                self.initial[path] = digest
            return digest
        except Exception:
            return None

    def changed(self, path: Optional[str]) -> bool:
        if not path:
            return False
        current = self.sha256(path)
        if current is None:
            return False
        baseline = self.initial.get(path, current)
        return current != baseline

# ======================================================
# PROCESS TREE ANALYZER
# ======================================================

class ProcessTreeAnalyzer:
    """Analyzes parent-child process relationships for anomalies"""
    
    def __init__(self):
        # (parent, child) pairs that are suspicious
        self.suspicious_chains = {
            # Office apps spawning scripts
            ("winword.exe", "powershell.exe"),
            ("winword.exe", "wscript.exe"),
            ("winword.exe", "cmd.exe"),
            ("excel.exe", "powershell.exe"),
            ("excel.exe", "wscript.exe"),
            ("excel.exe", "cmd.exe"),
            ("outlook.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"),
            # Browsers spawning unexpected children
            ("chrome.exe", "wscript.exe"),
            ("chrome.exe", "powershell.exe"),
            ("msedge.exe", "wscript.exe"),
            ("msedge.exe", "powershell.exe"),
            ("firefox.exe", "wscript.exe"),
            ("firefox.exe", "powershell.exe"),
            # PDF readers spawning scripts
            ("acrord32.exe", "powershell.exe"),
            ("acrord32.exe", "cmd.exe"),
        }
        
        # Processes that should only be spawned by specific parents
        self.expected_parents = {
            "svchost.exe": {"services.exe"},
            "taskhost.exe": {"svchost.exe"},
            "taskhostw.exe": {"svchost.exe"},
        }
    
    def check_suspicious_chain(self, parent: str, child: str) -> Tuple[bool, float]:
        """Check if parent-child relationship is suspicious"""
        pair = (parent.lower(), child.lower())
        if pair in self.suspicious_chains:
            return True, 0.35
        return False, 0.0
    
    def check_wrong_parent(self, child: str, parent: str) -> Tuple[bool, float]:
        """Check if process has unexpected parent"""
        child_lower = child.lower()
        if child_lower in self.expected_parents:
            expected = self.expected_parents[child_lower]
            if parent.lower() not in expected:
                return True, 0.30
        return False, 0.0
    
    def get_full_ancestry(self, proc: psutil.Process, max_depth: int = 5) -> List[str]:
        """Get complete process tree ancestry"""
        chain = []
        current = proc
        for _ in range(max_depth):
            try:
                parent = current.parent()
                if not parent:
                    break
                chain.append(parent.name().lower())
                current = parent
            except:
                break
        return chain

# ======================================================
# FILE SYSTEM WATCHER
# ======================================================

class FileSystemWatcher:
    """Monitor suspicious file system activity"""
    
    SUSPICIOUS_PATHS = {
        r"C:\Windows\Temp",
        r"C:\Windows\System32\Tasks",
        r"C:\ProgramData",
        r"AppData\Local\Temp",
        r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    }
    
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".vbs", ".ps1", ".bat", ".cmd", ".hta"
    }
    
    def __init__(self):
        self.recent_writes: Dict[int, List[Tuple[str, float]]] = {}  # pid -> [(path, time)]
        
    def check_suspicious_file_activity(self, proc: psutil.Process) -> Tuple[float, List[str]]:
        """Detect suspicious file writes"""
        boost = 0.0
        reasons = []
        
        try:
            open_files = proc.open_files()
            suspicious_files = []
            
            for f in open_files:
                path = f.path.lower()
                
                # Check if in suspicious directory
                is_suspicious_loc = any(sp.lower() in path for sp in self.SUSPICIOUS_PATHS)
                
                # Check extension
                has_suspicious_ext = any(path.endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS)
                
                if is_suspicious_loc and has_suspicious_ext:
                    suspicious_files.append(path)
            
            if len(suspicious_files) > 3:
                boost += 0.25
                reasons.append(f"suspicious_file_writes:{len(suspicious_files)}")
            elif len(suspicious_files) > 0:
                boost += 0.10
                reasons.append("suspicious_file_activity")
                
        except:
            pass
        
        return boost, reasons

# ======================================================
# PERSISTENCE DETECTOR
# ======================================================

class PersistenceDetector:
    """Detect attempts to establish persistence"""
    
    PERSISTENCE_KEYWORDS = {
        "reg add": 0.35,
        "new-itemproperty": 0.35,
        "schtasks /create": 0.40,
        "sc create": 0.40,
        "sc config": 0.30,
        "wmic process call create": 0.35,
        "start-process": 0.20,
    }
    
    PERSISTENCE_REGISTRY_PATHS = [
        r"\run",
        r"\runonce",
        r"\runservices",
        r"\userinit",
        r"\shell\open\command",
    ]
    
    def check_persistence_attempt(self, proc: psutil.Process) -> Tuple[float, List[str]]:
        """Check if process is attempting persistence"""
        boost = 0.0
        reasons = []
        
        try:
            cmdline = " ".join(proc.cmdline()).lower()
            
            # Check for persistence keywords in command line
            for keyword, score in self.PERSISTENCE_KEYWORDS.items():
                if keyword in cmdline:
                    # Additional check for registry persistence
                    if "reg add" in keyword or "new-itemproperty" in keyword:
                        if any(path in cmdline for path in self.PERSISTENCE_REGISTRY_PATHS):
                            boost += score
                            reasons.append(f"persistence_registry:{keyword}")
                    else:
                        boost += score
                        reasons.append(f"persistence_attempt:{keyword}")
                        
        except:
            pass
            
        return boost, reasons

# ======================================================
# NETWORK ANALYZER
# ======================================================

class NetworkAnalyzer:
    """Enhanced network behavior analysis with beaconing detection"""
    
    def __init__(self, beaconing_window: int = 300, tolerance: int = 10):
        # pid -> [(ip, port, timestamp)]
        self.connection_history: Dict[int, Deque[Tuple[str, int, float]]] = defaultdict(lambda: deque(maxlen=50))
        self.beaconing_window = beaconing_window
        self.tolerance = tolerance
        
    def analyze_connections(
        self, 
        pid: int, 
        conns: List[psutil._common.sconn],
        trusted_domains: List[str]
    ) -> Tuple[float, List[str]]:
        """Analyze network connections for anomalies"""
        
        boost = 0.0
        reasons = []
        
        if not conns:
            return boost, reasons
        
        current_time = time.time()
        unique_ips = set()
        unique_ports = set()
        public_connections = 0
        
        for conn in conns:
            if not conn.raddr:
                continue
                
            ip = conn.raddr.ip
            port = conn.raddr.port
            
            unique_ips.add(ip)
            unique_ports.add(port)
            
            # Track connection
            self.connection_history[pid].append((ip, port, current_time))
            
            # Check for public IP connections
            if classify_ip(ip) == "public":
                public_connections += 1
        
        # Excessive unique IPs (possible scanning or C2 rotation)
        if len(unique_ips) > 20:
            boost += 0.20
            reasons.append(f"many_unique_ips:{len(unique_ips)}")
        elif len(unique_ips) > 10:
            boost += 0.10
            reasons.append(f"multiple_ips:{len(unique_ips)}")
        
        # Excessive port diversity (possible port scanning)
        if len(unique_ports) > 30:
            boost += 0.25
            reasons.append(f"port_scanning:{len(unique_ports)}")
        elif len(unique_ports) > 15:
            boost += 0.12
            reasons.append(f"diverse_ports:{len(unique_ports)}")
        
        # Check for beaconing behavior
        beacon_boost, beacon_reason = self._detect_beaconing(pid)
        if beacon_boost > 0:
            boost += beacon_boost
            reasons.append(beacon_reason)
        
        return boost, reasons
    
    def _detect_beaconing(self, pid: int) -> Tuple[float, str]:
        """Detect regular beaconing patterns (C2 communication)"""
        
        if pid not in self.connection_history:
            return 0.0, ""
        
        history = list(self.connection_history[pid])
        if len(history) < 5:
            return 0.0, ""
        
        # Group by destination
        dest_times: Dict[Tuple[str, int], List[float]] = defaultdict(list)
        for ip, port, timestamp in history:
            dest_times[(ip, port)].append(timestamp)
        
        # Check for regular intervals to same destination
        for dest, times in dest_times.items():
            if len(times) < 5:
                continue
            
            times_sorted = sorted(times)
            intervals = [times_sorted[i+1] - times_sorted[i] for i in range(len(times_sorted)-1)]
            
            if len(intervals) < 4:
                continue
            
            # Calculate interval consistency
            avg_interval = sum(intervals) / len(intervals)
            
            # Check if intervals are consistent (within tolerance)
            consistent = all(abs(interval - avg_interval) < self.tolerance for interval in intervals)
            
            if consistent and 10 < avg_interval < 300:  # Beaconing every 10s-5min
                return 0.30, f"beaconing_detected:interval_{avg_interval:.0f}s"
        
        return 0.0, ""

# ======================================================
# MEMORY INJECTION DETECTOR
# ======================================================

class MemoryInjectionDetector:
    """Detect signs of memory injection or process hollowing"""
    
    def check_injection_indicators(self, proc: psutil.Process) -> Tuple[float, List[str]]:
        """Check for memory injection indicators"""
        boost = 0.0
        reasons = []
        
        try:
            # Check for suspicious memory usage patterns
            mem_info = proc.memory_info()
            
            # Unusual memory page permissions (requires additional libraries)
            # This is a simplified check
            
            # Check if executable name doesn't match path (possible hollowing)
            try:
                name = proc.name().lower()
                exe_path = proc.exe()
                if exe_path:
                    actual_name = os.path.basename(exe_path).lower()
                    if name != actual_name:
                        boost += 0.25
                        reasons.append("name_path_mismatch")
            except:
                pass
            
            # Check for processes with no command line (possible injection)
            try:
                cmdline = proc.cmdline()
                if not cmdline or len(cmdline) == 0:
                    boost += 0.15
                    reasons.append("no_cmdline")
            except:
                pass
                
        except:
            pass
        
        return boost, reasons

# ======================================================
# EVENT LOGGING
# ======================================================

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
    action_taken: str
    ancestry: str
    exe_path: Optional[str]
    entropy: float
    cmdline: str
    sha256: Optional[str]
    safe_mode: bool
    detection_details: Dict[str, object]  # New field for detailed detection info

class EventLogger:
    def __init__(self, path: str, max_size_mb: int, backups: int):
        self.path = path
        self.max_bytes = max_size_mb * 1024 * 1024
        self.backups = backups

    def _rotate(self) -> None:
        if not os.path.exists(self.path):
            return
        if os.path.getsize(self.path) < self.max_bytes:
            return
        for i in range(self.backups, 0, -1):
            src = f"{self.path}.{i}"
            dst = f"{self.path}.{i+1}"
            if os.path.exists(src):
                if i == self.backups:
                    os.remove(src)
                else:
                    os.rename(src, dst)
        os.rename(self.path, f"{self.path}.1")

    def log(self, event: SuspiciousEvent) -> None:
        self._rotate()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event)) + "\n")

# ======================================================
# BASELINE
# ======================================================

class BaselineManager:
    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Dict[str, float]] = {}

    def load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except Exception:
                pass

    def save(self) -> None:
        for k, d in self.data.items():
            d["avg"] = d["sum"] / max(1, d["count"])
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def update(self, numeric: Dict[str, float]) -> None:
        for k, v in numeric.items():
            if k not in self.data:
                self.data[k] = {"min": v, "max": v, "sum": v, "count": 1}
            else:
                d = self.data[k]
                d["min"] = min(d["min"], v)
                d["max"] = max(d["max"], v)
                d["sum"] += v
                d["count"] += 1

    def deviation(self, numeric: Dict[str, float]) -> float:
        if not self.data:
            return 0.0
        total = 0.0
        count = 0
        for k, v in numeric.items():
            if k not in self.data:
                continue
            d = self.data[k]
            if d["max"] == d["min"]:
                continue
            dist = abs(v - d["sum"] / d["count"]) / (d["max"] - d["min"])
            total += dist
            count += 1
        if count == 0:
            return 0.0
        return min(total / count, 1.0)

# ======================================================
# RATE LIMITER
# ======================================================

class RateLimiter:
    def __init__(self, max_per_minute: int):
        self.max = max_per_minute
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

# ======================================================
# HYBRID MODEL
# ======================================================

class HybridModel:
    def extract(self, proc: psutil.Process, conns: List[psutil._common.sconn], hc: HashCache):
        try:
            cpu = proc.cpu_percent()
            mem = proc.memory_percent()
            thr = proc.num_threads()
            name = (proc.name() or "").lower()
            user = (proc.username() or "").lower()
            exe = proc.exe() if hasattr(proc, "exe") else None
            cmdline = " ".join(proc.cmdline() or [])
            num_conns = len(conns)
            has_remote = any(c.raddr for c in conns)
            is_listen = any(c.status == psutil.CONN_LISTEN for c in conns)
            parent = proc.parent()
            parent_name = (parent.name().lower() if parent else "")
            ancestry: List[str] = []
            if parent:
                ancestry.append(parent_name)
                gp = parent.parent()
                if gp:
                    ancestry.append((gp.name() or "").lower())
            ent = file_entropy(exe)
            sha = hc.sha256(exe)
        except Exception:
            return [], {}, {}
        
        numeric = {
            "cpu": cpu,
            "mem": mem,
            "thr": thr,
            "conns": num_conns,
            "rem": int(has_remote),
            "lis": int(is_listen),
            "ent": ent,
        }
        
        meta = {
            "name": name,
            "user": user,
            "exe": exe,
            "cmd": cmdline,
            "parent": parent_name,
            "anc": " > ".join(ancestry),
            "sha": sha,
        }
        
        features = [cpu, mem, thr, num_conns, int(has_remote), int(is_listen), ent]
        return features, numeric, meta

    def score(self, features: List[float], meta: Dict[str, object]) -> float:
        if not features:
            return 0.0
        cpu, mem, thr, conns, has_remote, is_listen, ent = features
        name = str(meta.get("name", "")).lower()
        cmd = str(meta.get("cmd", "")).lower()
        parent = str(meta.get("parent", "")).lower()

        s = 0.0
        if cpu > 80:
            s += 0.25
        elif cpu > 50:
            s += 0.15
        if mem > 75:
            s += 0.18
        elif mem > 50:
            s += 0.10
        if thr > 128:
            s += 0.12
        elif thr > 64:
            s += 0.05
        if conns > 40:
            s += 0.12
        elif conns > 10:
            s += 0.05
        if has_remote:
            s += 0.04
        if is_listen:
            s += 0.04
        if ent > 7.2:
            s += 0.22
        elif ent > 6.6:
            s += 0.12

        lolbins = {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
        if name in lolbins:
            s += 0.20
            if any(x in cmd for x in ["-enc", "base64", "downloadstring", "frombase64string", "iex", "invoke-expression"]):
                s += 0.30

        if parent in {"winword.exe", "excel.exe", "outlook.exe"} and name in lolbins:
            s += 0.30
        if parent in {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"} and name in lolbins:
            s += 0.30

        return min(s, 1.0)

# ======================================================
# PROC GUARD ENGINE
# ======================================================

class ProcGuard:
    def __init__(self, cfg: Dict[str, object]):
        self.cfg = cfg
        self.host = platform.node() or "host"
        self.everyday = {x.lower() for x in cfg["everyday_apps"]}  # type: ignore
        self.known_bad = {x.lower() for x in cfg["known_bad_names"]}  # type: ignore
        self.suspicious_lolbins = {x.lower() for x in cfg["suspicious_lolbins"]}  # type: ignore
        self.trusted = [x.lower() for x in cfg["trusted_domains"]]  # type: ignore
        self.threshold: float = float(cfg["threshold"])  # type: ignore
        self.safe_mode: bool = bool(cfg["safe_mode"])  # type: ignore
        self.ui_mode: str = str(cfg["ui_mode"])  # type: ignore
        self.color_enabled: bool = bool(cfg["color_output"])  # type: ignore

        self.auto_kill = False if self.safe_mode else bool(cfg["auto_kill"])  # type: ignore
        self.auto_block = False if self.safe_mode else bool(cfg["auto_block"])  # type: ignore
        self.firewall_dry_run = bool(cfg["firewall_dry_run"])  # type: ignore
        self.escalation_boost: float = float(cfg["escalation_score_boost"])  # type: ignore

        self.alert_on_listen = bool(cfg["alert_on_listen_ports"])  # type: ignore
        self.alert_on_remote = bool(cfg["alert_on_remote_connections"])  # type: ignore
        
        # Feature flags
        self.enable_file_monitoring = bool(cfg["enable_file_monitoring"])  # type: ignore
        self.enable_persistence = bool(cfg["enable_persistence_detection"])  # type: ignore
        self.enable_beaconing = bool(cfg["enable_network_beaconing"])  # type: ignore
        self.enable_tree_analysis = bool(cfg["enable_process_tree_analysis"])  # type: ignore

        self.logger = EventLogger(
            str(cfg["event_log_path"]),  # type: ignore
            int(cfg["max_log_size_mb"]),  # type: ignore
            int(cfg["rotation_backups"]),  # type: ignore
        )
        self.baseline = BaselineManager(str(cfg["baseline_path"]))  # type: ignore
        self.baseline.load()
        self.model = HybridModel()
        self.hash_cache = HashCache()
        self.ratelimiter = RateLimiter(int(cfg["max_events_per_minute"]))  # type: ignore

        # Enhanced detection modules
        self.tree_analyzer = ProcessTreeAnalyzer()
        self.fs_watcher = FileSystemWatcher()
        self.persist_detector = PersistenceDetector()
        self.net_analyzer = NetworkAnalyzer(
            int(cfg.get("beaconing_window", 300)),  # type: ignore
            int(cfg.get("beaconing_tolerance", 10))  # type: ignore
        )
        self.mem_detector = MemoryInjectionDetector()

        self.scan_count = 0
        self.alert_count = 0
        self.kill_count = 0
        self.block_count = 0
        self.alert_counts: Dict[int, int] = {}
        self.last_stats = time.time()
        self.last_summary = time.time()

    def _is_everyday(self, name: str) -> bool:
        return name.lower() in self.everyday

    def _format_conns(self, conns: List[psutil._common.sconn]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        for c in conns:
            try:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                if c.raddr:
                    ip = c.raddr.ip
                    port = c.raddr.port
                    out.append({
                        "laddr": laddr,
                        "raddr": f"{ip}:{port} ({classify_ip(ip)})",
                        "status": c.status,
                    })
                else:
                    out.append({
                        "laddr": laddr,
                        "raddr": "",
                        "status": c.status,
                    })
            except Exception:
                continue
        return out

    def _build_pid_conn_map(self) -> Dict[int, List[psutil._common.sconn]]:
        mapping: Dict[int, List[psutil._common.sconn]] = {}
        try:
            all_conns = psutil.net_connections(kind="inet")
            for c in all_conns:
                if c.pid is not None:
                    mapping.setdefault(c.pid, []).append(c)
        except Exception:
            pass
        return mapping

    def _heuristics(
        self, 
        proc: psutil.Process,
        name: str, 
        numeric: Dict[str, float], 
        conns: List[psutil._common.sconn],
        meta: Dict[str, object]
    ) -> Tuple[float, List[str], Dict[str, object]]:
        """Enhanced heuristics with new detection modules"""
        boost = 0.0
        reasons: List[str] = []
        details: Dict[str, object] = {}
        
        lname = name.lower()

        # Known bad names
        if lname in self.known_bad:
            boost += 0.45
            reasons.append("known_bad_name")
            details["known_bad"] = True

        # Resource consumption
        cpu = numeric.get("cpu", 0.0)
        mem = numeric.get("mem", 0.0)
        conns_count = numeric.get("conns", 0.0)
        ent = numeric.get("ent", 0.0)

        if cpu > 85:
            boost += 0.20
            reasons.append("very_high_cpu")
        elif cpu > 60:
            boost += 0.10
            reasons.append("high_cpu")

        if mem > 80:
            boost += 0.18
            reasons.append("very_high_mem")
        elif mem > 60:
            boost += 0.10
            reasons.append("high_mem")

        if conns_count > 30:
            boost += 0.10
            reasons.append("many_connections")

        # High-risk ports
        for c in conns:
            try:
                if not c.raddr:
                    continue
                port = c.raddr.port
                if port != HTTPS_PORT and port not in {HTTP_PORT, DNS_PORT} and port in HIGH_RISK_PORTS:
                    boost += 0.20
                    reasons.append(f"high_risk_port:{port}")
            except Exception:
                continue

        if self.alert_on_remote and numeric.get("rem", 0) == 1:
            boost += 0.05
            reasons.append("remote_connections")

        if self.alert_on_listen and numeric.get("lis", 0) == 1:
            boost += 0.05
            reasons.append("listening_port")

        if ent > 7.3:
            boost += 0.18
            reasons.append("high_entropy")
        elif ent > 6.7:
            boost += 0.10
            reasons.append("elevated_entropy")

        # Process tree analysis
        if self.enable_tree_analysis:
            parent_name = str(meta.get("parent", ""))
            if parent_name:
                is_sus, tree_boost = self.tree_analyzer.check_suspicious_chain(parent_name, lname)
                if is_sus:
                    boost += tree_boost
                    reasons.append(f"suspicious_parent_child:{parent_name}>{lname}")
                    details["suspicious_chain"] = f"{parent_name} -> {lname}"
                
                is_wrong, wrong_boost = self.tree_analyzer.check_wrong_parent(lname, parent_name)
                if is_wrong:
                    boost += wrong_boost
                    reasons.append(f"wrong_parent:{lname}_from_{parent_name}")
                    details["wrong_parent"] = True

        # File system monitoring
        if self.enable_file_monitoring:
            fs_boost, fs_reasons = self.fs_watcher.check_suspicious_file_activity(proc)
            boost += fs_boost
            reasons.extend(fs_reasons)
            if fs_boost > 0:
                details["file_activity"] = True

        # Persistence detection
        if self.enable_persistence:
            persist_boost, persist_reasons = self.persist_detector.check_persistence_attempt(proc)
            boost += persist_boost
            reasons.extend(persist_reasons)
            if persist_boost > 0:
                details["persistence_attempt"] = True

        # Network beaconing
        if self.enable_beaconing and conns:
            net_boost, net_reasons = self.net_analyzer.analyze_connections(
                proc.pid, conns, self.trusted
            )
            boost += net_boost
            reasons.extend(net_reasons)
            if net_boost > 0:
                details["network_anomaly"] = True

        # Memory injection indicators
        mem_boost, mem_reasons = self.mem_detector.check_injection_indicators(proc)
        boost += mem_boost
        reasons.extend(mem_reasons)
        if mem_boost > 0:
            details["injection_indicators"] = True

        return boost, reasons, details

    def _print_evt(self, e: SuspiciousEvent) -> None:
        """Enhanced alert output for laymen and analysts"""
        
        # Analyst mode (more compact, raw data)
        if self.ui_mode == "analyst":
            hdr = color("[ALERT]", C.R, self.color_enabled)
            print(f"{hdr} PID={e.pid} name={e.name} score={e.score:.2f} reason={e.reason} action={e.action_taken}")
            print(f"   EXE: {e.exe_path}")
            print(f"   CMD: {e.cmdline}")
            if e.sha256:
                print(f"   SHA: {e.sha256}")
            if e.ancestry:
                print(f"   ANCESTRY: {e.ancestry}")
            if e.detection_details:
                print(f"   DETAILS: {json.dumps(e.detection_details)}")
            if e.connections:
                print("   CONNS:")
                for c in e.connections[:6]:
                    print("     ", c)
            print()
            return

        # Layman mode — color-coded severity, explanations
        if e.score >= 0.90:
            sev_col = C.R
            sev_label = "CRITICAL"
        elif e.score >= 0.75:
            sev_col = C.Y
            sev_label = "HIGH RISK"
        else:
            sev_col = C.C
            sev_label = "SUSPICIOUS"

        bar_len = int(e.score * 20)
        bar = color("█" * bar_len, sev_col, self.color_enabled) + color("░" * (20 - bar_len), C.D, self.color_enabled)

        hdr = color("[Security Alert]", C.R, self.color_enabled)
        print()
        print(hdr + " Suspicious behavior detected in a running program\n")
        print(color("──────────────────────────────────────────", C.D, self.color_enabled))

        print(color(" Program Details:", C.C, self.color_enabled))
        print(f"   Name:        {e.name}")
        print(f"   PID:         {e.pid}")
        print(f"   User:        {e.username}")
        if e.exe_path:
            print(f"   Location:    {e.exe_path}")
        if e.ancestry:
            print(f"   Parent:      {e.ancestry}")
        print(f"   Command:     {e.cmdline or '(no command line)'}")

        print(color("\n Risk Evaluation:", C.C, self.color_enabled))
        print(f"   Severity:    {color(sev_label, sev_col, self.color_enabled)}")
        print(f"   Score:       {e.score:.2f}  (0 = safe, 1 = very dangerous)")
        print(f"   Threat Bar:  {bar}")
        print(f"   Reason(s):   {e.reason}")

        print(color("\n What This Means:", C.C, self.color_enabled))
        meaning: List[str] = []
        
        if "entropy" in e.reason:
            meaning.append("- The file looks obfuscated or packed (often used by malware).")
        if "beaconing" in e.reason:
            meaning.append("- The program is communicating on a regular schedule (C2 behavior).")
        if "remote" in e.reason:
            meaning.append("- The program is connecting to remote servers unexpectedly.")
        if "listen" in e.reason:
            meaning.append("- The program opened a listening port (possible backdoor behavior).")
        if "known_bad" in e.reason:
            meaning.append("- The program is a known hacking or malware tool.")
        if "persistence" in e.reason:
            meaning.append("- The program is trying to survive system reboots (persistence).")
        if "suspicious_parent_child" in e.reason or "wrong_parent" in e.reason:
            meaning.append("- The program was launched in an unusual way (process tree anomaly).")
        if "file_writes" in e.reason or "file_activity" in e.reason:
            meaning.append("- The program is writing suspicious files to the system.")
        if "injection" in e.reason:
            meaning.append("- Signs of memory injection or process manipulation detected.")
        if "port_scanning" in e.reason:
            meaning.append("- The program appears to be scanning network ports.")
        if not meaning:
            meaning.append("- The program behaved differently than this system normally does.")

        for m in meaning:
            print("  ", m)

        print(color("\n Recommended Action:", C.C, self.color_enabled))
        if self.safe_mode:
            print("   Safe Mode is ON — no programs will be stopped automatically.")
            print("   • Review the details above carefully.")
            print("   • If this is NOT a trusted app, you can end the task manually.")
            print("   • Consider investigating the program's origin and purpose.")
        else:
            print("   Enforcement is active.")
            print(f"   Action Taken: {color(e.action_taken, sev_col, self.color_enabled)}")

        if e.connections:
            print(color("\n Network Activity:", C.C, self.color_enabled))
            for c in e.connections[:5]:
                print("   •", c)

        print(color("──────────────────────────────────────────\n", C.D, self.color_enabled))

    def monitor_once(self) -> None:
        self.scan_count += 1
        pid_conn_map = self._build_pid_conn_map()

        for proc in psutil.process_iter(attrs=["pid", "name", "username", "ppid"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
            except Exception:
                continue

            if pid == os.getpid():
                continue
            if self._is_everyday(name):
                continue

            conns = pid_conn_map.get(pid, [])
            features, numeric, meta = self.model.extract(proc, conns, self.hash_cache)
            if not features:
                continue

            deviation = self.baseline.deviation(numeric)
            ml_score = self.model.score(features, meta)
            h_boost, reasons, details = self._heuristics(proc, name, numeric, conns, meta)

            prev_alerts = self.alert_counts.get(pid, 0)
            if prev_alerts >= 2:
                h_boost += self.escalation_boost
                reasons.append("repeat_offender")
                details["repeat_offender"] = prev_alerts

            score = ml_score + 0.3 * deviation + h_boost
            score = max(0.0, min(score, 1.0))
            
            if score < self.threshold:
                continue

            self.alert_counts[pid] = prev_alerts + 1

            action = "logged_only"
            if not self.safe_mode:
                if self.auto_kill:
                    try:
                        proc.terminate()
                        self.kill_count += 1
                        action = "terminated"
                    except Exception:
                        pass
                if self.auto_block:
                    for c in conns:
                        try:
                            if not c.raddr:
                                continue
                            ip = c.raddr.ip
                            port = c.raddr.port
                            if port in {HTTPS_PORT, HTTP_PORT, DNS_PORT}:
                                continue
                            cmd = f'netsh advfirewall firewall add rule name="ProcGuard_{ip}" dir=out action=block remoteip={ip}'
                            if not self.firewall_dry_run:
                                os.system(cmd)
                            self.block_count += 1
                            action = "terminated+blocked_ip" if action == "terminated" else "blocked_ip"
                        except Exception:
                            continue

            event = SuspiciousEvent(
                timestamp=utc_now(),
                host=self.host,
                pid=pid,
                ppid=proc.info.get("ppid", -1),
                name=name,
                username=str(meta.get("user", "")),
                score=score,
                reason=",".join(reasons) if reasons else "ml",
                cpu_percent=float(numeric.get("cpu", 0.0)),
                mem_percent=float(numeric.get("mem", 0.0)),
                num_threads=int(numeric.get("thr", 0)),
                connections=self._format_conns(conns),
                action_taken=action,
                ancestry=str(meta.get("anc", "")),
                exe_path=str(meta.get("exe", "")) if meta.get("exe") else None,
                entropy=float(numeric.get("ent", 0.0)),
                cmdline=str(meta.get("cmd", "")),
                sha256=str(meta.get("sha", "")) if meta.get("sha") else None,
                safe_mode=self.safe_mode,
                detection_details=details,
            )

            if self.ratelimiter.allow():
                self.logger.log(event)
                self._print_evt(event)
                self.alert_count += 1

    def loop(self) -> None:
        mode_label = "SAFE (log-only)" if self.safe_mode else "ENFORCE (kill/block)"
        hdr = color("[ProcGuard ACTIVE]", C.G, self.color_enabled)
        
        features_enabled = []
        if self.enable_tree_analysis:
            features_enabled.append("ProcessTree")
        if self.enable_file_monitoring:
            features_enabled.append("FileMonitor")
        if self.enable_persistence:
            features_enabled.append("Persistence")
        if self.enable_beaconing:
            features_enabled.append("Beaconing")
        
        features_str = ", ".join(features_enabled) if features_enabled else "None"
        
        print(f"{hdr} mode={mode_label} interval={self.cfg['scan_interval']} threshold={self.threshold}")
        print(f"Enhanced Features: {features_str}")
        print(color("──────────────────────────────────────────", C.D, self.color_enabled))
        
        while True:
            try:
                self.monitor_once()
                now = time.time()
                if now - self.last_stats > 60:
                    stats_line = f"[Stats] scans={self.scan_count} alerts={self.alert_count} kills={self.kill_count} blocks={self.block_count}"
                    print(color(stats_line, C.D, self.color_enabled))
                    self.last_stats = now
                if now - self.last_summary > 300:  # Every 5 minutes
                    print(color("=== Summary ===", C.C, self.color_enabled))
                    print(f"Scans: {self.scan_count} | Alerts: {self.alert_count} | Kills: {self.kill_count} | Blocks: {self.block_count}")
                    print(color("===============", C.C, self.color_enabled))
                    self.last_summary = now
                time.sleep(float(self.cfg["scan_interval"]))  # type: ignore
            except KeyboardInterrupt:
                print("\n[ProcGuard] Stopped.")
                break

# ======================================================
# BASELINE MODE
# ======================================================

def run_baseline(cfg: Dict[str, object]) -> None:
    duration = int(cfg["baseline_duration"])  # type: ignore
    interval = float(cfg["scan_interval"])  # type: ignore
    path = str(cfg["baseline_path"])  # type: ignore
    print(f"[Baseline] Training for {duration}s...")
    bm = BaselineManager(path)
    hc = HashCache()
    model = HybridModel()
    start = time.time()
    samples = 0
    
    while time.time() - start < duration:
        pid_conn_map: Dict[int, List[psutil._common.sconn]] = {}
        try:
            all_conns = psutil.net_connections(kind="inet")
            for c in all_conns:
                if c.pid is not None:
                    pid_conn_map.setdefault(c.pid, []).append(c)
        except Exception:
            pass

        for proc in psutil.process_iter(attrs=["pid"]):
            pid = proc.info["pid"]
            conns = pid_conn_map.get(pid, [])
            features, numeric, meta = model.extract(proc, conns, hc)
            if numeric:
                bm.update(numeric)
                samples += 1
        
        elapsed = int(time.time() - start)
        remaining = duration - elapsed
        print(f"[Baseline] Progress: {elapsed}s/{duration}s | Samples: {samples} | Remaining: {remaining}s", end="\r")
        time.sleep(interval)
    
    bm.save()
    print(f"\n[Baseline] Complete. {samples} samples collected and saved to {path}")

# ======================================================
# CLI + MAIN
# ======================================================

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="SuntinCerl ProcGuard v6.0 — Windows EDR Sentinel")
    ap.add_argument("--mode", choices=["monitor", "baseline"], default="monitor")
    ap.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    ap.add_argument("--interval", type=float, help="Scan interval in seconds")
    ap.add_argument("--threshold", type=float, help="Detection threshold (0.0-1.0)")
    ap.add_argument("--event-log", help="Path to event log file")
    ap.add_argument("--baseline-path", help="Path to baseline data file")
    ap.add_argument("--ui-mode", choices=["layman", "analyst"], help="UI display mode")
    ap.add_argument("--no-color", action="store_true", help="Disable color output")
    ap.add_argument("--enforce", action="store_true", help="Enable enforcement mode (kill/block)")
    return ap.parse_args()

def main() -> None:
    if platform.system().lower() != "windows":
        print("ProcGuard is Windows-only.")
        sys.exit(1)
    
    print(color(BANNER, C.C, True))
    
    args = parse_args()
    cfg_mgr = ConfigManager(args.config)
    cfg_mgr.apply_cli(args)
    cfg = cfg_mgr.config
    
    if args.mode == "baseline":
        run_baseline(cfg)
        return
    
    guard = ProcGuard(cfg)
    
    try:
        guard.loop()
    except Exception as e:
        print(f"\n[ProcGuard] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
