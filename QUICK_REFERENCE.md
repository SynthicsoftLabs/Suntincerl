# ProcGuard v6.0 - Quick Reference Guide

## Installation & Setup

### Install Dependencies
```powershell
pip install psutil --break-system-packages
```

### First-Time Setup
```powershell
# 1. Train baseline on clean system (IMPORTANT!)
python procguard_v6.py --mode baseline

# 2. Run monitoring in safe mode
python procguard_v6.py

# 3. Review alerts for 24+ hours before enabling enforcement
```

## Common Commands

### Basic Operations

| Command | Description |
|---------|-------------|
| `python procguard_v6.py` | Start monitoring (safe mode) |
| `python procguard_v6.py --mode baseline` | Train baseline behavior |
| `python procguard_v6.py --ui-mode analyst` | Compact output for analysts |
| `python procguard_v6.py --threshold 0.75` | More sensitive detection |
| `python procguard_v6.py --interval 10` | Scan every 10 seconds |
| `python procguard_v6.py --no-color` | Disable colored output |

### Advanced Operations

| Command | Description |
|---------|-------------|
| `python procguard_v6.py --enforce` | **DANGER**: Enable auto-kill/block |
| `python procguard_v6.py --config custom.json` | Use custom config file |
| `python procguard_v6.py --event-log alerts.jsonl` | Custom log path |

## Reading Alerts

### Severity Levels

| Score | Severity | Color | Action |
|-------|----------|-------|--------|
| 0.90+ | CRITICAL | Red | Investigate immediately |
| 0.75-0.89 | HIGH RISK | Yellow | Review within 1 hour |
| 0.60-0.74 | SUSPICIOUS | Cyan | Monitor & investigate |

### Common Alert Reasons

| Reason | Meaning | Threat Level |
|--------|---------|--------------|
| `known_bad_name` | Recognized hacking tool | ⚠️⚠️⚠️ Critical |
| `beaconing_detected` | C2 communication pattern | ⚠️⚠️⚠️ Critical |
| `persistence_attempt` | Trying to survive reboot | ⚠️⚠️⚠️ Critical |
| `suspicious_parent_child` | Unusual process launch | ⚠️⚠️ High |
| `high_entropy` | Packed/obfuscated file | ⚠️⚠️ High |
| `port_scanning` | Network reconnaissance | ⚠️⚠️ High |
| `many_connections` | Excessive network activity | ⚠️ Medium |
| `suspicious_file_writes` | Writing to suspicious locations | ⚠️ Medium |

## Investigation Steps

### When You See an Alert

1. **Don't Panic** - Review the details carefully
2. **Check Process Details**:
   - Is it a legitimate program?
   - Does the parent process make sense?
   - Is the file path normal?
3. **Review Network Activity**:
   - Are connections to known good IPs?
   - Is beaconing actually C2 or legitimate?
4. **Google the SHA256** - Check VirusTotal
5. **Decide Action**:
   - False positive → Add to whitelist
   - True threat → Terminate & investigate

### False Positive Handling

If legitimate app triggers alerts:

1. **Add to everyday_apps** in config:
   ```json
   "everyday_apps": [
     "your_app.exe"
   ]
   ```

2. **Or adjust threshold** if too sensitive:
   ```bash
   python procguard_v6.py --threshold 0.85
   ```

## Log Analysis

### View Recent Alerts
```powershell
# PowerShell
Get-Content procguard_events.jsonl -Tail 10 | ConvertFrom-Json | Format-Table

# CMD
type procguard_events.jsonl | findstr "CRITICAL"
```

### Count Alerts by Reason
```powershell
# PowerShell
Get-Content procguard_events.jsonl | ForEach-Object {
    ($_ | ConvertFrom-Json).reason
} | Group-Object | Sort-Object Count -Descending
```

### Find High-Score Alerts
```powershell
# PowerShell - Alerts above 0.9
Get-Content procguard_events.jsonl | ForEach-Object {
    $event = $_ | ConvertFrom-Json
    if ($event.score -gt 0.9) { $event }
} | Format-List
```

## Configuration Tuning

### Reduce False Positives

1. **Lower sensitivity**:
   ```json
   "threshold": 0.85
   ```

2. **Whitelist your tools**:
   ```json
   "everyday_apps": ["your_app.exe"]
   ```

3. **Disable overly sensitive features**:
   ```json
   "enable_file_monitoring": false
   ```

### Increase Detection

1. **Higher sensitivity**:
   ```json
   "threshold": 0.70
   ```

2. **Enable all features**:
   ```json
   "enable_file_monitoring": true,
   "enable_persistence_detection": true,
   "enable_network_beaconing": true,
   "enable_process_tree_analysis": true
   ```

3. **Shorter beaconing intervals**:
   ```json
   "beaconing_window": 180,
   "beaconing_tolerance": 5
   ```

## Performance Optimization

### High CPU Usage?
```json
{
  "scan_interval": 10,              // Scan less frequently
  "enable_file_monitoring": false,  // Disable expensive checks
  "enable_beaconing": false         // Reduce memory tracking
}
```

### Missing Alerts?
```json
{
  "scan_interval": 3,    // Scan more frequently
  "threshold": 0.75      // More sensitive
}
```

## Emergency Procedures

### If Malware Detected

1. **Disconnect network** (if beaconing detected)
2. **Note the PID** from alert
3. **Kill process manually**:
   ```powershell
   Stop-Process -Id <PID> -Force
   ```
4. **Block IP** (if needed):
   ```powershell
   netsh advfirewall firewall add rule name="Block_Malware" dir=out action=block remoteip=<IP>
   ```
5. **Scan with antivirus**
6. **Review logs** for entry point

### If System Unstable After Enforcement

1. **Stop ProcGuard**: Ctrl+C
2. **Review recent firewall rules**:
   ```powershell
   netsh advfirewall firewall show rule name=all | findstr "ProcGuard"
   ```
3. **Remove suspicious rules**:
   ```powershell
   netsh advfirewall firewall delete rule name="ProcGuard_<IP>"
   ```
4. **Restart in safe mode**:
   ```powershell
   python procguard_v6.py --config procguard_config.json
   ```

## Detection Examples

### Example 1: Macro Malware
```
[Security Alert] Suspicious behavior detected

 Program Details:
   Name:        powershell.exe
   Parent:      winword.exe > explorer.exe
   
 Risk Evaluation:
   Severity:    CRITICAL
   Score:       0.94
   
 Action: Investigate Word document that launched PowerShell
```

### Example 2: Ransomware
```
[Security Alert] Suspicious behavior detected

 Program Details:
   Name:        cryptor.exe
   
 Risk Evaluation:
   Severity:    CRITICAL
   Score:       0.96
   Reason:      suspicious_file_writes:47,high_entropy,high_cpu
   
 Action: IMMEDIATELY kill process and disconnect network
```

### Example 3: C2 Beacon
```
[Security Alert] Suspicious behavior detected

 Program Details:
   Name:        updater.exe
   
 Risk Evaluation:
   Severity:    HIGH RISK
   Score:       0.88
   Reason:      beaconing_detected:interval_60s
   
 Action: Review destination IP, block if malicious
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No alerts generated | Lower threshold or disable baseline |
| Too many false positives | Increase threshold or whitelist apps |
| High CPU usage | Increase scan_interval |
| Script crashes | Check Python version (3.8+) and psutil |
| Firewall rules not created | Run as Administrator |
| Colors not showing | Check terminal supports ANSI |

## Best Practices

✅ **DO**:
- Train baseline on clean system first
- Run in safe mode for 24+ hours
- Review logs regularly
- Keep whitelists updated
- Test threshold changes gradually

❌ **DON'T**:
- Enable enforcement without testing
- Set threshold below 0.70
- Ignore CRITICAL alerts
- Disable all detection features
- Run without baseline training

## Support Checklist

If you need help:

- [ ] Check ProcGuard version: `v6.0`
- [ ] Python version: `python --version` (3.8+)
- [ ] psutil installed: `pip show psutil`
- [ ] Config file exists: `procguard_config.json`
- [ ] Log file readable: `procguard_events.jsonl`
- [ ] Running as Administrator (for enforcement)
- [ ] Review recent events in log
- [ ] Note exact error message

## Quick Feature Reference

| Feature | Config Key | Default | Purpose |
|---------|-----------|---------|---------|
| Process Tree | `enable_process_tree_analysis` | true | Detect suspicious parent-child |
| Beaconing | `enable_network_beaconing` | true | Detect C2 communication |
| Persistence | `enable_persistence_detection` | true | Detect survival mechanisms |
| File Monitor | `enable_file_monitoring` | true | Detect suspicious writes |
| Safe Mode | `safe_mode` | true | Log-only (no actions) |
| Auto Kill | `auto_kill` | false | Terminate threats |
| Auto Block | `auto_block` | false | Add firewall rules |

## Version History

- **v6.0** (Current): Enhanced detection, beaconing, persistence
- **v5.1**: Initial release with basic ML detection

---

**Quick Help**: For detailed information, see `README_PROCGUARD_V6.md`
