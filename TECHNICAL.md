# LOTL Detector

**Living off the Land Detection and Prevention System**

A real-time security monitoring system using eBPF/LSM for detecting and preventing Living off the Land (LOTL) attacks on Linux systems.

## Features

- **Real-time Detection**: Uses eBPF to monitor process execution with minimal overhead
- **Tiered Blocking**: 
  - Tier 1: Kernel-level blocking of known-bad binaries (instant, first-attempt)
  - Tier 2: Userspace regex pattern matching (alerts, optional blocking)
- **Baseline Learning**: Rolling baseline with exponential decay to detect anomalies
- **Ancestry Tracking**: Allow legitimate operations (apt, dpkg) while blocking abuse
- **Fileless Execution Detection**: Monitors memfd_create and /proc/*/fd execution
- **Self-Protection**: Protects detector process from being killed or tampered with
- **Busybox Abuse Detection**: Identifies dangerous applets invoked via busybox

## Defense Model

### What We Can Block (First Attempt)

| Capability | Mechanism |
|------------|-----------|
| Block nc, ncat, socat | Kernel path + inode blocklist |
| Block memfd/fexecve execution | Kernel LSM hook |
| Block copies of dangerous binaries | Inode matching |
| Block /proc/pid/mem writes | LSM hook (enforce mode) |

### What We Can Detect (Alert)

| Capability | Mechanism |
|------------|-----------|
| Suspicious arguments | Userspace regex patterns |
| LD_PRELOAD injection | Environment variable capture |
| Busybox applet abuse | Applet extraction and matching |
| Behavioral anomalies | Baseline comparison |
| Kernel module loading | Tracepoint monitoring |
| ptrace injection | Tracepoint monitoring |
| Foreign eBPF programs | LSM hook monitoring |

### Explicit Limitations

1. **First-Strike Gap**: Attacks using legitimate binaries (bash, python, curl) with malicious arguments succeed on first execution. System detects immediately, then optionally blocks user.

2. **Memory-Only Attacks**: In-process code execution (interpreter eval/exec) is not visible to execve monitoring.

3. **Encrypted Traffic**: Cannot inspect HTTPS payload content.

## Requirements

- Linux kernel 6.1+ with BPF LSM support
- Python 3.12+
- bcc (BPF Compiler Collection)
- Root privileges

### Enable BPF LSM

```bash
# Check if BPF LSM is enabled
cat /sys/kernel/security/lsm

# If 'bpf' is not listed, run:
sudo ./scripts/enable_bpf_lsm.sh
# Then reboot
```

## Installation

```bash
# Install system dependencies
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# Clone repository
git clone https://github.com/your-org/lotl-detector.git
cd lotl-detector

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package
pip install -e ".[dev]"
```

## Usage

### Quick Start

```bash
# Start in bootstrap mode (learning)
sudo python -m lotl_detector

# Start in specific mode
sudo python -m lotl_detector --mode learn

# With custom configuration
sudo python -m lotl_detector --config /etc/lotl/detector.yaml
```

### Command Line Options

```
usage: python -m lotl_detector [-h] [--config CONFIG] [--mode {bootstrap,learn,enforce,paranoid}]
                               [--probes-dir PROBES_DIR] [--rules-dir RULES_DIR]
                               [--no-lsm] [--debug]

Options:
  --config, -c     Path to configuration file
  --mode, -m       Operational mode (overrides config)
  --probes-dir     Path to BPF probes directory
  --rules-dir      Path to rules directory
  --no-lsm         Disable LSM hooks (for testing)
  --debug          Enable debug logging
```

### Operational Modes

```
Bootstrap (24h) ──auto──► Learn (7d) ──manual──► Enforce
     │                        │                      │
     ▼                        ▼                      ▼
 LOG ONLY              ALERT ONLY              BLOCK + ALERT
 No alerts             Tier1: block            Tier1: block
 Collect baseline      Tier2: alert            Tier2: alert + user block
```

### Systemd Service

```bash
# Copy service file
sudo cp systemd/lotl-detector.service /etc/systemd/system/

# Create config directory
sudo mkdir -p /etc/lotl/rules
sudo cp rules/*.yaml /etc/lotl/rules/
sudo cp config/detector.yaml /etc/lotl/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable lotl-detector
sudo systemctl start lotl-detector
```

## Configuration

Main configuration file: `/etc/lotl/detector.yaml`

```yaml
mode: learn

logging:
  level: INFO
  directory: /var/log/lotl
  syslog_enabled: true

database:
  path: /var/lib/lotl/detector.db
  max_age_days: 30

baseline:
  decay_half_life_days: 7
  anomaly_threshold: 2.0
```

### Rule Files

- `rules/tier1_blocklist.yaml` - Binaries blocked at kernel level
- `rules/tier2_patterns.yaml` - Userspace detection patterns
- `rules/ancestry_allowlist.yaml` - Package manager exceptions

## Logs

| File | Contents |
|------|----------|
| `/var/log/lotl/events.jsonl` | All process execution events |
| `/var/log/lotl/alerts.jsonl` | Security alerts |
| `/var/run/lotl/metrics.json` | Health metrics |

### Log Format (JSONL)

```json
{"timestamp": 1704067200, "level": "WARNING", "logger": "lotl_detector", "alert": {"pid": 1234, "filename": "/usr/bin/nc", "alert_type": "BLOCKED_EXEC", "severity": "CRITICAL", "rule_id": "tier1-nc"}}
```

## Emergency Disable (Panic Button)

If the detector is causing issues:

```bash
# Method 1: Create panic file (switches to observe-only)
sudo touch /var/run/lotl/DISABLE

# Method 2: Kernel command line (requires reboot)
# Add lotl.disable=1 to kernel parameters

# To re-enable
sudo rm /var/run/lotl/DISABLE
```

## Recovery Procedures

### Detector Crashes

```bash
# Check logs
journalctl -u lotl-detector -n 100

# Restart service
sudo systemctl restart lotl-detector

# If BPF errors, try with LSM disabled
sudo python -m lotl_detector --no-lsm
```

### Database Corruption

```bash
# Backup and recreate
sudo mv /var/lib/lotl/detector.db /var/lib/lotl/detector.db.backup
sudo systemctl restart lotl-detector
```

### Locked Out User

```bash
# Check blocked users
sudo cat /var/log/lotl/alerts.jsonl | grep BLOCKED_USER

# Remove from blocklist (requires restart)
sudo systemctl restart lotl-detector
```

## Development

### Running Tests

```bash
# Activate virtual environment
source .venv/bin/activate

# Run unit tests
pytest tests/unit -v

# Run with coverage
pytest tests/unit --cov=lotl_detector

# Run attack simulations (doesn't require root)
pytest tests/attack_simulations -v
```

### Project Structure

```
lotl-detector/
├── probes/                 # BPF C source files
│   ├── common.h           # Shared definitions
│   ├── execve_trace.c     # Process execution tracing
│   ├── lsm_enforce.c      # Blocking enforcement
│   └── ...
├── lotl_detector/          # Python package
│   ├── core/              # Core modules
│   ├── bpf/               # BPF loader
│   ├── detection/         # Detection engines
│   └── processes/         # Worker processes
├── rules/                  # Detection rules
├── tests/                  # Test suite
└── systemd/               # Service files
```

## Security Considerations

- Runs as root (required for BPF)
- Uses safe YAML loading (no code execution)
- Parameterized SQL queries (no injection)
- Regex timeout protection (50ms max)
- Log injection prevention
- Bounded queues and caches

## License

MIT License - See LICENSE file

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `pytest tests/unit -v`
4. Submit a pull request

## Acknowledgments

- [bcc (BPF Compiler Collection)](https://github.com/iovisor/bcc)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)

