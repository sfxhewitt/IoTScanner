#!/usr/bin/env bash
#
# IoT-Scanner - Network IoT device security scanner
# Scans local networks for IoT devices with weak SSH/Telnet credentials.
#
# Usage: ./IoT-Scanner.sh [OPTIONS]
#   Run without options for interactive mode.
#   See --help for non-interactive usage.

set -euo pipefail

readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"

# ---------- Color definitions ----------
readonly RED='\033[1;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[1;32m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# ---------- Defaults ----------
VERBOSE=0
QUIET=0
OUTPUT_DIR="."
LOG_FILE=""
TARGET=""
CONFIG_FILE=""
SCAN_TIMEOUT="8s"
SSH_PORT=22
TELNET_PORT=23
USER_FILE=""
PASS_FILE=""
NON_INTERACTIVE=0

# ---------- Temp directory (set in main, cleaned on exit) ----------
TMPDIR_WORK=""

# =========================================================================
#  Utility functions
# =========================================================================

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

IoT network security scanner - tests devices for weak SSH/Telnet credentials.

Options:
  -t, --target CIDR        Target network CIDR (e.g. 192.168.1.0/24).
                            Defaults to auto-detecting local subnets.
  -o, --output-dir DIR     Directory to write credential result files
                            (default: current directory).
  -c, --config FILE        Path to configuration file.
  -U, --user-file FILE     Path to username wordlist file.
  -P, --pass-file FILE     Path to password wordlist file.
      --ssh-port PORT      SSH port to scan (default: 22).
      --telnet-port PORT   Telnet port to scan (default: 23).
      --timeout DURATION   Brute-force timeout per host (default: 8s).
  -v, --verbose            Enable verbose output.
  -q, --quiet              Suppress non-essential output.
  -l, --log FILE           Write log to FILE.
  -n, --non-interactive    Run scan without interactive menus (implies verbose).
      --version            Print version and exit.
  -h, --help               Show this help message and exit.

Examples:
  $SCRIPT_NAME                         # Interactive mode
  $SCRIPT_NAME -n -v                   # Non-interactive, verbose, auto-detect network
  $SCRIPT_NAME -n -t 10.0.0.0/24      # Scan a specific subnet
  $SCRIPT_NAME -n -o /tmp/results      # Save results to /tmp/results

Configuration file:
  Create a file (e.g. scanner.conf) with KEY=VALUE pairs:
    SSH_PORT=22
    TELNET_PORT=23
    SCAN_TIMEOUT=8s
    USER_FILE=/path/to/users.txt
    PASS_FILE=/path/to/passwords.txt

EOF
}

log() {
    local level="$1"
    shift
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local message="[$timestamp] [$level] $*"

    if [[ -n "$LOG_FILE" ]]; then
        echo "$message" >> "$LOG_FILE"
    fi

    case "$level" in
        ERROR)
            printf "%b[ERROR] %s%b\n" "$RED" "$*" "$NC" >&2
            ;;
        WARN)
            printf "%b[WARN] %s%b\n" "$YELLOW" "$*" "$NC" >&2
            ;;
        INFO)
            if [[ "$QUIET" -eq 0 ]]; then
                printf "%b[INFO]%b %s\n" "$GREEN" "$NC" "$*"
            fi
            ;;
        DEBUG)
            if [[ "$VERBOSE" -eq 1 ]]; then
                printf "%b[DEBUG]%b %s\n" "$BOLD" "$NC" "$*"
            fi
            ;;
    esac
}

die() {
    log ERROR "$@"
    exit 1
}

cleanup() {
    if [[ -n "$TMPDIR_WORK" && -d "$TMPDIR_WORK" ]]; then
        rm -rf "$TMPDIR_WORK"
        log DEBUG "Cleaned up temp directory: $TMPDIR_WORK"
    fi
}

# =========================================================================
#  Validation helpers
# =========================================================================

check_dependencies() {
    local missing=()
    for cmd in nmap ip awk grep; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required dependencies: ${missing[*]}. Please install them before running."
    fi

    log DEBUG "All dependencies satisfied"
}

check_nmap_scripts() {
    local scripts=("ssh-brute" "telnet-brute")
    for script in "${scripts[@]}"; do
        if ! nmap --script-help "$script" &>/dev/null; then
            log WARN "Nmap script '$script' not found. Some scans may fail."
        fi
    done
}

check_root_or_warn() {
    if [[ $EUID -ne 0 ]]; then
        log WARN "Running without root privileges. Network discovery (ping scan) may be limited."
        log WARN "Consider running with: sudo $SCRIPT_NAME $*"
    fi
}

validate_port() {
    local port="$1"
    local name="$2"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        die "Invalid $name port: $port (must be 1-65535)"
    fi
}

validate_output_dir() {
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        mkdir -p "$OUTPUT_DIR" || die "Cannot create output directory: $OUTPUT_DIR"
    fi
    if [[ ! -w "$OUTPUT_DIR" ]]; then
        die "Output directory is not writable: $OUTPUT_DIR"
    fi
}

# =========================================================================
#  Configuration
# =========================================================================

load_config() {
    local config_file="$1"
    if [[ ! -f "$config_file" ]]; then
        die "Configuration file not found: $config_file"
    fi
    if [[ ! -r "$config_file" ]]; then
        die "Configuration file not readable: $config_file"
    fi

    log DEBUG "Loading configuration from: $config_file"

    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        key="$(echo "$key" | xargs)"
        value="$(echo "$value" | xargs)"

        case "$key" in
            SSH_PORT)       SSH_PORT="$value" ;;
            TELNET_PORT)    TELNET_PORT="$value" ;;
            SCAN_TIMEOUT)   SCAN_TIMEOUT="$value" ;;
            USER_FILE)      USER_FILE="$value" ;;
            PASS_FILE)      PASS_FILE="$value" ;;
            OUTPUT_DIR)     OUTPUT_DIR="$value" ;;
            LOG_FILE)       LOG_FILE="$value" ;;
            *)              log WARN "Unknown config key: $key" ;;
        esac
    done < "$config_file"
}

# =========================================================================
#  Wordlist generation
# =========================================================================

setup_wordlists() {
    local user_file="$TMPDIR_WORK/user.txt"
    local pass_file="$TMPDIR_WORK/pass.txt"

    if [[ -n "$USER_FILE" ]]; then
        if [[ ! -f "$USER_FILE" ]]; then
            die "User wordlist file not found: $USER_FILE"
        fi
        cp "$USER_FILE" "$user_file"
        log DEBUG "Using custom username wordlist: $USER_FILE"
    else
        cat > "$user_file" <<'EOF'
admin
root
ubnt
support
service
guest
tech
EOF
        log DEBUG "Using default username wordlist (7 entries)"
    fi

    if [[ -n "$PASS_FILE" ]]; then
        if [[ ! -f "$PASS_FILE" ]]; then
            die "Password wordlist file not found: $PASS_FILE"
        fi
        cp "$PASS_FILE" "$pass_file"
        log DEBUG "Using custom password wordlist: $PASS_FILE"
    else
        cat > "$pass_file" <<'EOF'
admin
root
password
guest
service
1234
EOF
        log DEBUG "Using default password wordlist (6 entries)"
    fi
}

# =========================================================================
#  Network discovery
# =========================================================================

discover_targets() {
    local ips_file="$TMPDIR_WORK/ips.txt"
    local live_file="$TMPDIR_WORK/live_hosts.txt"

    if [[ -n "$TARGET" ]]; then
        echo "$TARGET" > "$ips_file"
        log INFO "Using specified target: $TARGET"
    else
        log INFO "Auto-detecting local subnets..."
        ip -4 addr show | grep -w "inet" | awk '{print $2}' | grep -v '^127\.' > "$ips_file" || true

        if [[ ! -s "$ips_file" ]]; then
            die "Could not detect any local network interfaces"
        fi
        log DEBUG "Detected subnets: $(tr '\n' ', ' < "$ips_file")"
    fi

    log INFO "Scanning for active hosts..."
    if ! nmap -oG "$TMPDIR_WORK/nmap_ping.txt" -sn -iL "$ips_file" > /dev/null 2>&1; then
        die "Nmap host discovery failed. Check network connectivity and permissions."
    fi

    grep "^Host:" "$TMPDIR_WORK/nmap_ping.txt" | awk '{print $2}' > "$live_file" 2>/dev/null || true

    if [[ ! -s "$live_file" ]]; then
        log WARN "No active hosts found on the network"
        return 1
    fi

    local host_count
    host_count="$(wc -l < "$live_file")"
    log INFO "Found $host_count active host(s)"

    echo "$live_file"
}

# =========================================================================
#  Port scanning and credential testing
# =========================================================================

scan_port() {
    local ip="$1"
    local port="$2"

    local result
    result="$(nmap "$ip" -p "$port" 2>/dev/null | grep -E 'open|closed' | awk '{print $2}')" || true
    echo "$result"
}

count_open_ports() {
    local live_file="$1"
    local port="$2"

    local count
    count="$(nmap -iL "$live_file" -p "$port" 2>/dev/null | grep -E 'open' | wc -l)" || true
    echo "$count"
}

brute_force_telnet() {
    local ip="$1"
    local port="$2"
    local user_file="$TMPDIR_WORK/user.txt"
    local pass_file="$TMPDIR_WORK/pass.txt"
    local xml_file="$TMPDIR_WORK/telnet_${ip}.xml"
    local cred_file="$OUTPUT_DIR/Telnet-Credentials.txt"

    log DEBUG "Attempting Telnet brute-force on $ip:$port"

    local nmap_output
    nmap_output="$(nmap -oX "$xml_file" -p "$port" \
        --script telnet-brute \
        --script-args "userdb=$user_file,passdb=$pass_file,telnet-brute.timeout=$SCAN_TIMEOUT" \
        "$ip" 2>/dev/null)" || true

    if echo "$nmap_output" | grep -qE 'Valid'; then
        local -a users=()
        local -a passwords=()

        mapfile -t users < <(grep -oP '(?<=username">)[^<]*(?=</elem>)' "$xml_file" 2>/dev/null || true)
        mapfile -t passwords < <(grep -oP '(?<=password">)[^<]*(?=</elem>)' "$xml_file" 2>/dev/null || true)

        if [[ ${#users[@]} -gt 0 ]]; then
            {
                echo "The telnet credentials for $ip are:"
                for i in "${!users[@]}"; do
                    printf "%s : %s\n" "${users[i]}" "${passwords[i]:-<empty>}"
                done
                echo ""
            } >> "$cred_file"

            log INFO "Telnet credentials FOUND for $ip"

            if [[ "$VERBOSE" -eq 1 ]]; then
                for i in "${!users[@]}"; do
                    printf "  %btelnet -l %s %s%b (password: %b%s%b)\n" \
                        "$YELLOW" "${users[i]}" "$ip" "$NC" \
                        "$YELLOW" "${passwords[i]:-<empty>}" "$NC"
                done
            fi
            return 0
        fi
    fi

    log DEBUG "Telnet credentials not found for $ip"
    if [[ "$VERBOSE" -eq 1 ]]; then
        printf "  %bNo valid Telnet credentials found for %s%b\n" "$BOLD" "$ip" "$NC"
    fi
    return 1
}

brute_force_ssh() {
    local ip="$1"
    local port="$2"
    local user_file="$TMPDIR_WORK/user.txt"
    local pass_file="$TMPDIR_WORK/pass.txt"
    local xml_file="$TMPDIR_WORK/ssh_${ip}.xml"
    local cred_file="$OUTPUT_DIR/SSH-Credentials.txt"

    log DEBUG "Attempting SSH brute-force on $ip:$port"

    local nmap_output
    nmap_output="$(nmap -oX "$xml_file" -p "$port" \
        --script ssh-brute \
        --script-args "userdb=$user_file,passdb=$pass_file,ssh-brute.timeout=$SCAN_TIMEOUT" \
        "$ip" 2>/dev/null)" || true

    if echo "$nmap_output" | grep -qE 'Valid'; then
        local -a users=()
        local -a passwords=()

        mapfile -t users < <(grep -oP '(?<=username">)[^<]*(?=</elem>)' "$xml_file" 2>/dev/null || true)
        mapfile -t passwords < <(grep -oP '(?<=password">)[^<]*(?=</elem>)' "$xml_file" 2>/dev/null || true)

        if [[ ${#users[@]} -gt 0 ]]; then
            {
                echo "The SSH credentials for $ip are:"
                for i in "${!users[@]}"; do
                    printf "%s : %s\n" "${users[i]}" "${passwords[i]:-<empty>}"
                done
                echo ""
            } >> "$cred_file"

            log INFO "SSH credentials FOUND for $ip"

            if [[ "$VERBOSE" -eq 1 ]]; then
                for i in "${!users[@]}"; do
                    printf "  %bssh %s@%s%b (password: %b%s%b)\n" \
                        "$YELLOW" "${users[i]}" "$ip" "$NC" \
                        "$YELLOW" "${passwords[i]:-<empty>}" "$NC"
                done
            fi
            return 0
        fi
    fi

    log DEBUG "SSH credentials not found for $ip"
    if [[ "$VERBOSE" -eq 1 ]]; then
        printf "  %bNo valid SSH credentials found for %s%b\n" "$BOLD" "$ip" "$NC"
    fi
    return 1
}

# =========================================================================
#  Main scan orchestration
# =========================================================================

run_scan() {
    local found_vulnerable=0

    # Remove previous credential files from output dir
    rm -f "$OUTPUT_DIR/SSH-Credentials.txt" "$OUTPUT_DIR/Telnet-Credentials.txt"

    setup_wordlists

    local live_file
    live_file="$(discover_targets)" || { log INFO "No hosts to scan. Exiting."; return 0; }

    local hosts
    mapfile -t hosts < "$live_file"

    # --- Telnet scan ---
    log INFO "Scanning for open Telnet ports (port $TELNET_PORT)..."
    local telnet_open
    telnet_open="$(count_open_ports "$live_file" "$TELNET_PORT")"
    log INFO "Found $telnet_open host(s) with Telnet port $TELNET_PORT open"

    for ip in "${hosts[@]}"; do
        local port_status
        port_status="$(scan_port "$ip" "$TELNET_PORT")"
        if [[ "$port_status" == "open" ]]; then
            if [[ "$VERBOSE" -eq 1 ]]; then
                printf "%bAttempting dictionary attack on %s (Telnet)%b\n" "$RED" "$ip" "$NC"
            fi
            if brute_force_telnet "$ip" "$TELNET_PORT"; then
                found_vulnerable=1
            fi
        fi
    done

    # --- SSH scan ---
    log INFO "Scanning for open SSH ports (port $SSH_PORT)..."
    local ssh_open
    ssh_open="$(count_open_ports "$live_file" "$SSH_PORT")"
    log INFO "Found $ssh_open host(s) with SSH port $SSH_PORT open"

    for ip in "${hosts[@]}"; do
        local port_status
        port_status="$(scan_port "$ip" "$SSH_PORT")"
        if [[ "$port_status" == "open" ]]; then
            if [[ "$VERBOSE" -eq 1 ]]; then
                printf "%bAttempting dictionary attack on %s (SSH)%b\n" "$RED" "$ip" "$NC"
            fi
            if brute_force_ssh "$ip" "$SSH_PORT"; then
                found_vulnerable=1
            fi
        fi
    done

    # --- Results summary ---
    echo ""
    if [[ "$found_vulnerable" -eq 1 ]]; then
        printf "%bVulnerable device(s) found on the network. Please review credentials and take action.%b\n" "$RED" "$NC"
        log WARN "Vulnerable devices detected - credential files written to: $OUTPUT_DIR"

        if [[ -f "$OUTPUT_DIR/Telnet-Credentials.txt" ]]; then
            log INFO "Telnet results: $OUTPUT_DIR/Telnet-Credentials.txt"
        fi
        if [[ -f "$OUTPUT_DIR/SSH-Credentials.txt" ]]; then
            log INFO "SSH results: $OUTPUT_DIR/SSH-Credentials.txt"
        fi
    else
        printf "%bAll devices appear secure. No weak credentials found.%b\n" "$GREEN" "$NC"
        log INFO "Scan complete - no vulnerable devices found"
    fi
}

show_previous_results() {
    local found=0

    if [[ -f "$OUTPUT_DIR/Telnet-Credentials.txt" ]]; then
        printf "%b--- Telnet Credentials ---%b\n" "$BOLD" "$NC"
        cat "$OUTPUT_DIR/Telnet-Credentials.txt"
        found=1
    fi

    if [[ -f "$OUTPUT_DIR/SSH-Credentials.txt" ]]; then
        printf "%b--- SSH Credentials ---%b\n" "$BOLD" "$NC"
        cat "$OUTPUT_DIR/SSH-Credentials.txt"
        found=1
    fi

    if [[ "$found" -eq 0 ]]; then
        printf "%bNo previous scan results found in: %s%b\n" "$YELLOW" "$OUTPUT_DIR" "$NC"
    fi
}

interactive_menu() {
    PS3='Please enter your choice: '
    local options=("Start Scan" "Previous Scan Results" "Quit")

    select opt in "${options[@]}"; do
        case "$opt" in
            "Start Scan")
                PS3='Please enter your choice: '
                local scan_options=("Quick Scan" "Verbose Scan" "Back")
                select scan_opt in "${scan_options[@]}"; do
                    case "$scan_opt" in
                        "Quick Scan")
                            VERBOSE=0
                            run_scan
                            exit 0
                            ;;
                        "Verbose Scan")
                            VERBOSE=1
                            run_scan
                            exit 0
                            ;;
                        "Back")
                            break
                            ;;
                        *)
                            printf "%b'%s' is not a valid option%b\n" "$RED" "$REPLY" "$NC"
                            ;;
                    esac
                done
                PS3='Please enter your choice: '
                ;;
            "Previous Scan Results")
                show_previous_results
                ;;
            "Quit")
                log INFO "Exiting."
                exit 0
                ;;
            *)
                printf "%b'%s' is not a valid option%b\n" "$RED" "$REPLY" "$NC"
                ;;
        esac
    done
}

# =========================================================================
#  Argument parsing
# =========================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --version)
                echo "$SCRIPT_NAME version $VERSION"
                exit 0
                ;;
            -t|--target)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                TARGET="$2"
                shift 2
                ;;
            -o|--output-dir)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -c|--config)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                CONFIG_FILE="$2"
                shift 2
                ;;
            -U|--user-file)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                USER_FILE="$2"
                shift 2
                ;;
            -P|--pass-file)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                PASS_FILE="$2"
                shift 2
                ;;
            --ssh-port)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                SSH_PORT="$2"
                shift 2
                ;;
            --telnet-port)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                TELNET_PORT="$2"
                shift 2
                ;;
            --timeout)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                SCAN_TIMEOUT="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            -l|--log)
                [[ -z "${2:-}" ]] && die "Option $1 requires an argument"
                LOG_FILE="$2"
                shift 2
                ;;
            -n|--non-interactive)
                NON_INTERACTIVE=1
                shift
                ;;
            -*)
                die "Unknown option: $1 (use --help for usage)"
                ;;
            *)
                die "Unexpected argument: $1 (use --help for usage)"
                ;;
        esac
    done
}

# =========================================================================
#  Main entry point
# =========================================================================

main() {
    parse_args "$@"

    # Load config file if specified (CLI args take precedence)
    if [[ -n "$CONFIG_FILE" ]]; then
        load_config "$CONFIG_FILE"
    fi

    # Validate settings
    validate_port "$SSH_PORT" "SSH"
    validate_port "$TELNET_PORT" "Telnet"
    validate_output_dir

    # Check dependencies
    check_dependencies

    # Create secure temp directory
    TMPDIR_WORK="$(mktemp -d "${TMPDIR:-/tmp}/iot-scanner.XXXXXX")"
    trap cleanup EXIT INT TERM HUP

    log DEBUG "Temp directory: $TMPDIR_WORK"
    log DEBUG "Output directory: $OUTPUT_DIR"
    log INFO "IoT Scanner v$VERSION starting"

    check_root_or_warn "$@"
    check_nmap_scripts

    if [[ "$NON_INTERACTIVE" -eq 1 ]]; then
        run_scan
    else
        interactive_menu
    fi
}

# Only run main when executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
