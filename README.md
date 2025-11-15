# ProcGuard v6.0 - Enhanced Windows EDR Sentinel

## What's New in v6.0

### Major Enhancements

1. **Process Tree Analysis**
   - Detects suspicious parent-child process relationships
   - Identifies Office apps spawning scripts (macro-based attacks)
   - Detects browsers launching unexpected processes
   - Validates legitimate system process ancestry

2. **Network Beaconing Detection**
   - Identifies C2 communication patterns
   - Detects regular interval connections (beaconing)
   - Tracks connection history per process
   - Configurable detection windows and tolerance

3. **Persistence Mechanism Detection**
   - Registry Run key modifications
   - Scheduled task creation attempts
   - Service creation/modification
   - Startup folder manipulation

4. **File System Monitoring**
   - Tracks suspicious file writes
   - Monitors temp directory activity
   - Detects rapid executable creation
   - Identifies persistence-related file operations

5. **Memory Injection Indicators**
   - Process name/path mismatches
   - Missing command line arguments
   - Suspicious memory patterns

6. **Enhanced Network Analysis**
   - Port scanning detection
   - Excessive IP diversity tracking
   - High-risk port connections
   - Public vs. private IP classification

## Installation

### Requirements
```bash
pip install psutil --break-system-packages
```

### Quick Start
```bash
# Run in safe mode (monitoring only)
python procguard_v6.py

# Run baseline training first (recommended)
python procguard_v6.py --mode baseline

# Run in enforcement mode (DANGEROUS - will kill/block)
python procguard_v6.py --enforce
```

## Configuration

### Config File: procguard_config.json

```json
{
  "threshold": 0.82,
  "scan_interval": 5.0,
  "safe_mode": true,
  "ui_mode": "layman",
  
  "enable_file_monitoring": true,
  "enable_persistence_detection": true,
  "enable_network_beaconing": true,
  "enable_process_tree_analysis": true,
  
  "beaconing_window": 300,
  "beaconing_tolerance": 10,
  
  "auto_kill": false,
  "auto_block": false,
  "firewall_dry_run": true
}
```

### Key Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `threshold` | 0.82 | Detection threshold (0.0-1.0) |
| `scan_interval` | 5.0 | Seconds between scans |
| `safe_mode` | true | Log only, don't take action |
| `ui_mode` | "layman" | Display mode (layman/analyst) |
| `enable_file_monitoring` | true | Monitor file system activity |
| `enable_persistence_detection` | true | Detect persistence attempts |
| `enable_network_beaconing` | true | Detect C2 beaconing |
| `enable_process_tree_analysis` | true | Analyze process relationships |
| `beaconing_window` | 300 | Seconds to track connections |
| `beaconing_tolerance` | 10 | Beaconing interval tolerance (seconds) |

## Usage Examples

### 1. Normal Monitoring (Safe Mode)
```bash
python procguard_v6.py
```
- Logs all suspicious activity
- No automated responses
- User reviews alerts manually

### 2. Baseline Training
```bash
python procguard_v6.py --mode baseline
```
- Learns normal system behavior
- Run for 3-5 minutes on clean system
- Creates `procguard_baseline.json`

### 3. Custom Threshold
```bash
python procguard_v6.py --threshold 0.75
```
- Lower threshold = more sensitive
- Higher threshold = fewer false positives

### 4. Analyst Mode
```bash
python procguard_v6.py --ui-mode analyst
```
- Compact output
- Raw technical data
- Faster scanning of logs

### 5. Enforcement Mode (CAUTION)
```bash
python procguard_v6.py --enforce
```
- **WARNING**: Will terminate suspicious processes
- Will add firewall rules
- Only use if you understand the risks

## Detection Examples

### Example 1: Macro-Based Attack
```
[Security Alert] Suspicious behavior detected in a running program

 Program Details:
   Name:        powershell.exe
   PID:         4892
   Parent:      winword.exe > explorer.exe
   
 Risk Evaluation:
   Severity:    CRITICAL
   Score:       0.94
   Reason(s):   suspicious_parent_child:winword.exe>powershell.exe,
                high_entropy,persistence_registry
                
 What This Means:
   - The program was launched in an unusual way (process tree anomaly).
   - The file looks obfuscated or packed (often used by malware).
   - The program is trying to survive system reboots (persistence).
```

### Example 2: Beaconing C2
```
[Security Alert] Suspicious behavior detected in a running program

 Program Details:
   Name:        update_manager.exe
   PID:         3344
   
 Risk Evaluation:
   Severity:    HIGH RISK
   Score:       0.88
   Reason(s):   beaconing_detected:interval_60s,remote_connections
                
 What This Means:
   - The program is communicating on a regular schedule (C2 behavior).
   - The program is connecting to remote servers unexpectedly.
```

### Example 3: Port Scanning
```
[Security Alert] Suspicious behavior detected in a running program

 Program Details:
   Name:        scanner.exe
   PID:         5612
   
 Risk Evaluation:
   Severity:    CRITICAL
   Score:       0.91
   Reason(s):   port_scanning:45,many_unique_ips:32
                
 What This Means:
   - The program appears to be scanning network ports.
```

## Detection Mechanism Details

### Threat Scoring System

Base score components:
- **ML Model**: 0.0 - 1.0 (resource usage, network patterns)
- **Behavioral Deviation**: 0.0 - 0.3 (from baseline)
- **Heuristic Boosts**: Various (specific detections)

#### Heuristic Score Boosts

| Detection | Score Boost | Severity |
|-----------|-------------|----------|
| Known bad executable | +0.45 | Critical |
| Persistence attempt | +0.35 - 0.40 | High |
| Parent-child anomaly | +0.30 - 0.35 | High |
| Beaconing detected | +0.30 | High |
| High-risk port | +0.20 | Medium |
| Suspicious file writes | +0.10 - 0.25 | Medium |
| Memory injection indicators | +0.15 - 0.25 | Medium |
| Repeat offender | +0.18 | Escalating |

### Process Tree Analysis

Suspicious chains detected:
- Office apps → PowerShell/Scripts
- Browsers → PowerShell/Scripts  
- PDF readers → Command interpreters
- System processes from wrong parents

### Network Beaconing Algorithm

1. Track all connections per process
2. Group connections by destination (IP:Port)
3. Calculate time intervals between connections
4. Detect consistent intervals (10s - 300s)
5. Flag if intervals match within tolerance

### File System Monitoring

Monitored locations:
- `C:\Windows\Temp`
- `C:\Windows\System32\Tasks`
- `C:\ProgramData`
- `AppData\Local\Temp`
- Startup folders

Suspicious extensions:
- `.exe`, `.dll`, `.scr`
- `.vbs`, `.ps1`, `.bat`, `.cmd`
- `.hta`

### Persistence Detection

Methods detected:
- Registry Run keys
- Scheduled tasks
- Service creation/modification
- WMI event consumers
- Startup folder writes

## Event Logging

All events logged to `procguard_events.jsonl` in JSON Lines format:

```json
{
  "timestamp": "2025-11-14T10:30:45Z",
  "host": "DESKTOP-ABC123",
  "pid": 4892,
  "name": "powershell.exe",
  "score": 0.94,
  "reason": "suspicious_parent_child,persistence_registry",
  "action_taken": "logged_only",
  "detection_details": {
    "suspicious_chain": "winword.exe -> powershell.exe",
    "persistence_attempt": true
  },
  "connections": [...],
  "sha256": "abc123...",
  "safe_mode": true
}
```

## Performance Considerations

### Resource Usage
- CPU: ~2-5% during scans
- Memory: ~50-100 MB
- Scan time: ~1-3 seconds per cycle

### Optimization Tips

1. **Increase scan interval** for less CPU usage:
   ```bash
   python procguard_v6.py --interval 10
   ```

2. **Disable features** you don't need in config:
   ```json
   {
     "enable_file_monitoring": false,
     "enable_beaconing": false
   }
   ```

3. **Use baseline** to reduce false positives:
   ```bash
   # Train baseline on clean system
   python procguard_v6.py --mode baseline
   
   # Then monitor
   python procguard_v6.py
   ```

## Troubleshooting

### High False Positive Rate
- Lower threshold: `--threshold 0.85`
- Train baseline on your normal workload
- Add legitimate tools to `everyday_apps` in config

### Missing Detections
- Increase threshold sensitivity: `--threshold 0.75`
- Enable all detection features
- Check baseline isn't over-fitted to malicious behavior

### Performance Issues
- Increase scan interval: `--interval 10`
- Disable unnecessary features
- Reduce `beaconing_window` size

## Safety Notes

### Safe Mode (Default)
✅ **Safe to run** - Only logs events, no automated actions
- Review alerts manually
- Learn system behavior
- Tune detection thresholds

### Enforcement Mode (--enforce)
⚠️ **DANGEROUS** - Automated responses enabled
- May kill legitimate processes
- May block legitimate connections
- Test thoroughly in safe mode first
- Keep firewall_dry_run: true initially

### Best Practices

1. **Always start with baseline training**
2. **Run in safe mode for 24+ hours**
3. **Review logs before enabling enforcement**
4. **Whitelist known-good applications**
5. **Test firewall rules with dry_run: true**
6. **Keep backups of working configurations**

## Advanced Usage

### Custom Detection Rules

Edit config to add custom patterns:

```json
{
  "known_bad_names": [
    "mimikatz.exe",
    "your_malware.exe"
  ],
  "suspicious_lolbins": [
    "powershell.exe",
    "your_script_runner.exe"
  ],
  "everyday_apps": [
    "chrome.exe",
    "your_trusted_app.exe"
  ]
}
```

### Integration with SIEM

Parse `procguard_events.jsonl` with your SIEM:

```bash
# Example: Splunk Universal Forwarder
[monitor://C:\path\to\procguard_events.jsonl]
sourcetype = json
index = security
```

### Automated Response Scripts

Create custom response handlers:

```python
import json

with open('procguard_events.jsonl', 'r') as f:
    for line in f:
        event = json.loads(line)
        if event['score'] > 0.95:
            # Custom response logic
            send_alert(event)
            isolate_host(event['host'])
```

## Comparison with v5.1

| Feature | v5.1 | v6.0 |
|---------|------|------|
| Process Tree Analysis | ❌ | ✅ |
| Beaconing Detection | ❌ | ✅ |
| Persistence Detection | ❌ | ✅ |
| File System Monitoring | ❌ | ✅ |
| Memory Injection Detection | ❌ | ✅ |
| Network Analysis | Basic | Advanced |
| Event Logging | Basic | Enhanced with details |
| Performance | Good | Optimized |

## Contributing

Found a false positive pattern? Want to improve detection?
- Document the behavior
- Identify the legitimate process
- Suggest threshold adjustments
- Propose whitelist additions

## License

SynthicSoft Labs - Internal Security Tool

## Support

For issues or questions:
1. Check logs: `procguard_events.jsonl`
2. Review configuration
3. Verify Windows compatibility
4. Check psutil installation

---

**Version**: 6.0.0  
**Last Updated**: November 2025  
**Platform**: Windows 10/11  
**Python**: 3.8+
