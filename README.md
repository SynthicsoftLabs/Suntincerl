# SuntinCerl ProcGuard

## Hybrid ML Endpoint Defense Sentinel ~ SynthicSoft Labs

## Overview

SuntinCerl ProcGuard is a self-contained, real-time behavioral EDR engine for Windows 10 and Windows 11.
Built under SynthicSoft Labs’ SuntinCerl Security Framework, the system provides rapid autonomous detection and mitigation of malicious processes using hybrid machine-learning style scoring combined with advanced heuristics.

ProcGuard requires only psutil, operates fully offline, and delivers enterprise-grade functionality suitable for researchers, blue teams, home users, SOC automation, and advanced operators.

## Features
- Hybrid ML Scoring Engine

- ProcGuard assigns a dynamic threat score based on:

- CPU and memory behavior

- Thread count anomalies

- Network connection density

- Entropy estimation of executables

- Command-line pattern detection

- Parent/child process lineage

- System vs. non-system ownership

- Heuristic and Signature Detection

- ProcGuard includes detection for:

- Common red-team and post-exploitation tooling

- LOLBins abused in malicious chains

- Packed or obfuscated binaries (high entropy)

- Suspicious remote and listening ports

- Office applications spawning Powershell, WScript, or MSHTA

- Unusual network activity from user-level processes

- Autonomous Response

- Default behavior includes:

- Terminating high-risk processes

- Blocking remote IP addresses via Windows Firewall

- Logging each event in JSONL format for SOC integration

- Network Awareness

## Provides real-time analysis of:

- Outbound and inbound connections

- Listening ports

- High-connection-volume behavior

- Frequently abused attacker ports

- Adaptive Baseline (Optional)

- A short training period builds a behavioral baseline of normal activity:

py procguard.py --mode baseline


Scores are adjusted according to how far a process deviates from system norms.

## Logging

All detections are written to:

procguard_events.jsonl


with automatic log rotation.

Minimal Dependencies

ProcGuard requires only:

pip install psutil


There is no cloud connectivity, telemetry, or external ML framework dependency.

## Installation
1. Install the required dependency
pip install psutil

2. Clone the repository
git clone https://github.com/SynthicsoftLabs/Suntincerl
cd Suntincerl

3. Optional: Generate a baseline
py procguard.py --mode baseline

4. Start the sentinel
py procguard.py

Example Output
[ALERT] PID=4860 name=powershell.exe score=0.78 reason=known_bad_name action=terminated+blocked_ips

Example Event Log Entry
{
  "timestamp": "2025-11-14T05:22:14.183920Z",
  "host": "DESKTOP-12345",
  "pid": 4860,
  "ppid": 4320,
  "name": "powershell.exe",
  "username": "NT AUTHORITY\\SYSTEM",
  "score": 0.75,
  "reason": "known_bad_name,high_entropy,remote_connections",
  "cpu_percent": 86.4,
  "mem_percent": 12.3,
  "num_threads": 34,
  "connections": [
    {
      "laddr": "192.168.1.7:49823",
      "raddr": "31.13.71.36:443",
      "status": "ESTABLISHED"
    }
  ],
  "action_taken": "terminated+blocked_ips",
  "ancestry": "winword.exe > powershell.exe",
  "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "entropy": 7.31,
  "cmdline": "powershell -enc ..."
}

Configuration

A default procguard_config.json is generated on first run.

Example:

{
  "threshold": 0.70,
  "auto_kill": true,
  "auto_block": true,
  "scan_interval": 5.0,
  "alert_on_listen_ports": true,
  "alert_on_remote_connections": true
}


Adjust thresholds, intervals, whitelists, blacklists, or firewall behavior as needed.

## Roadmap

Planned SuntinCerl modules:

SuntinCerl-NetSentinel

SuntinCerl-FileSentry

SuntinCerl-SOCNode

SuntinCerl-AutoCodex

SuntinCerl-CloudMesh

Future ProcGuard enhancements:

YARA-lite rule engine

In-memory behavioral scanning

DLL load anomaly tracking

Registry monitoring

Powershell telemetry inspection

User/device behavioral modeling

## About SynthicSoft Labs

SynthicSoft Labs develops autonomous cyber-defense technologies emphasizing local inference, zero-cloud dependence, and real-time response.
Our mission is to deliver accessible, transparent, and effective security tooling engineered for modern threats.

Website: https://synthicsoftlabs.com

GitHub: https://github.com/SynthicsoftLabs
