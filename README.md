# IoT Scanner

A network security tool that scans local networks for IoT devices with weak
SSH and Telnet credentials. It discovers active hosts, checks for open service
ports, and attempts dictionary-based credential testing using nmap.

> **Authorised use only.** This tool is intended for security auditing of
> networks you own or have explicit permission to test. Unauthorised scanning
> or credential testing may be illegal in your jurisdiction.

## Features

- Auto-detects local subnets or accepts a specific target CIDR
- Scans for open SSH (port 22) and Telnet (port 23) ports
- Attempts dictionary-based credential testing via nmap scripts
- Interactive and non-interactive (scriptable) modes
- Configurable ports, timeouts, and wordlists
- Timestamped logging with multiple verbosity levels
- Clean signal handling and temp-file cleanup
- View previous scan results

## Requirements

- **Bash** 4.0+
- **nmap** with NSE scripts (`ssh-brute`, `telnet-brute`)
- Standard Unix tools: `ip`, `awk`, `grep`
- Root/sudo privileges recommended for reliable host discovery

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt install nmap
```

## Quick Start

```bash
git clone https://github.com/sfxhewitt/IoTScanner.git
cd IoTScanner
chmod +x IoT-Scanner.sh

# Interactive mode
sudo ./IoT-Scanner.sh

# Non-interactive scan of a specific subnet
sudo ./IoT-Scanner.sh -n -v -t 192.168.1.0/24
```

## Usage

```
Usage: IoT-Scanner.sh [OPTIONS]

Options:
  -t, --target CIDR        Target network CIDR (e.g. 192.168.1.0/24)
  -o, --output-dir DIR     Directory for credential result files (default: .)
  -c, --config FILE        Path to configuration file
  -U, --user-file FILE     Path to username wordlist
  -P, --pass-file FILE     Path to password wordlist
      --ssh-port PORT      SSH port to scan (default: 22)
      --telnet-port PORT   Telnet port to scan (default: 23)
      --timeout DURATION   Brute-force timeout per host (default: 8s)
  -v, --verbose            Enable verbose output
  -q, --quiet              Suppress non-essential output
  -l, --log FILE           Write log to FILE
  -n, --non-interactive    Run without interactive menus
      --version            Print version and exit
  -h, --help               Show help message
```

### Examples

```bash
# Interactive mode
./IoT-Scanner.sh

# Scan specific network with verbose output and logging
sudo ./IoT-Scanner.sh -n -v -t 10.0.0.0/24 -l scan.log

# Use custom wordlists
sudo ./IoT-Scanner.sh -n -U /path/to/users.txt -P /path/to/passwords.txt

# Custom ports and output directory
sudo ./IoT-Scanner.sh -n --ssh-port 2222 --telnet-port 2323 -o /tmp/results

# Use a configuration file
sudo ./IoT-Scanner.sh -n -c scanner.conf
```

## Configuration

Copy the example configuration file and edit as needed:

```bash
cp scanner.conf.example scanner.conf
```

Configuration file format (KEY=VALUE):

```ini
SSH_PORT=22
TELNET_PORT=23
SCAN_TIMEOUT=8s
USER_FILE=/path/to/usernames.txt
PASS_FILE=/path/to/passwords.txt
OUTPUT_DIR=/var/log/iot-scanner/results
LOG_FILE=/var/log/iot-scanner/scanner.log
```

CLI arguments take precedence over configuration file values.

## Testing

Tests use [bats-core](https://github.com/bats-core/bats-core).

```bash
# Install bats (Debian/Ubuntu)
sudo apt install bats

# Run tests
make test
```

## CI/CD

A GitHub Actions workflow runs ShellCheck and the bats test suite on every
push to `main` and on pull requests. See `.github/workflows/ci.yml`.

## Output

Scan results are written to the output directory (default: current directory):

- `SSH-Credentials.txt` - found SSH credentials per host
- `Telnet-Credentials.txt` - found Telnet credentials per host

When using `--log`, a timestamped log file records all scan activity for audit
purposes.
