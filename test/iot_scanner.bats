#!/usr/bin/env bats

# IoT Scanner test suite
# Requires bats-core: https://github.com/bats-core/bats-core

SCRIPT="./IoT-Scanner.sh"

setup() {
  TEST_BIN="$BATS_TEST_DIRNAME/mockbin"
  mkdir -p "$TEST_BIN"

  # Mock sudo to just run the command without privilege escalation
  cat <<'EOM' > "$TEST_BIN/sudo"
#!/bin/bash
shift
"$@"
EOM
  chmod +x "$TEST_BIN/sudo"

  # Mock apt to always succeed
  cat <<'EOM' > "$TEST_BIN/apt"
#!/bin/bash
exit 0
EOM
  chmod +x "$TEST_BIN/apt"

  # Mock nmap to produce controlled output
  cat <<'EOM' > "$TEST_BIN/nmap"
#!/bin/bash
# Default: produce empty output
for arg in "$@"; do
  if [[ "$arg" == "--script-help" ]]; then
    echo "script help output"
    exit 0
  fi
done
exit 0
EOM
  chmod +x "$TEST_BIN/nmap"

  # Mock ip command
  cat <<'EOM' > "$TEST_BIN/ip"
#!/bin/bash
echo "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
EOM
  chmod +x "$TEST_BIN/ip"

  export PATH="$TEST_BIN:$PATH"
  cd "$BATS_TEST_DIRNAME/.."
}

teardown() {
  rm -rf "$TEST_BIN"
  # Clean up any output files created during tests
  rm -f /tmp/iot-scanner-test-*.txt
}

# -------------------------------------------------------------------
#  CLI option tests
# -------------------------------------------------------------------

@test "--help prints usage information" {
  run bash "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage:"* ]]
  [[ "$output" == *"--target"* ]]
  [[ "$output" == *"--verbose"* ]]
}

@test "--version prints version string" {
  run bash "$SCRIPT" --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"version"* ]]
}

@test "unknown option produces an error" {
  run bash "$SCRIPT" --bogus-option
  [ "$status" -ne 0 ]
  [[ "$output" == *"Unknown option"* ]]
}

@test "--target requires an argument" {
  run bash "$SCRIPT" -t
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires an argument"* ]]
}

@test "--output-dir requires an argument" {
  run bash "$SCRIPT" -o
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires an argument"* ]]
}

@test "--log requires an argument" {
  run bash "$SCRIPT" -l
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires an argument"* ]]
}

@test "--config requires an argument" {
  run bash "$SCRIPT" -c
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires an argument"* ]]
}

# -------------------------------------------------------------------
#  Validation tests
# -------------------------------------------------------------------

@test "invalid SSH port is rejected" {
  run bash "$SCRIPT" --ssh-port 99999 -n
  [ "$status" -ne 0 ]
  [[ "$output" == *"Invalid"* ]]
}

@test "invalid Telnet port is rejected" {
  run bash "$SCRIPT" --telnet-port abc -n
  [ "$status" -ne 0 ]
  [[ "$output" == *"Invalid"* ]]
}

@test "missing config file is rejected" {
  run bash "$SCRIPT" -c /nonexistent/config.conf -n
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found"* ]]
}

@test "missing user wordlist file is rejected" {
  run bash "$SCRIPT" -U /nonexistent/users.txt -n
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found"* ]]
}

@test "missing password wordlist file is rejected" {
  run bash "$SCRIPT" -P /nonexistent/pass.txt -n
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found"* ]]
}

# -------------------------------------------------------------------
#  Interactive mode tests
# -------------------------------------------------------------------

@test "interactive menu is displayed" {
  run bash -c "echo 3 | $SCRIPT"
  [[ "$output" == *"Please enter your choice"* ]]
}

@test "interactive quit exits cleanly" {
  run bash -c "echo 3 | $SCRIPT"
  [ "$status" -eq 0 ]
}

@test "previous results reports no results when none exist" {
  run bash -c "printf '2\n3\n' | $SCRIPT -o /tmp"
  [[ "$output" == *"No previous scan results"* ]]
}

# -------------------------------------------------------------------
#  Configuration file tests
# -------------------------------------------------------------------

@test "config file is loaded correctly" {
  local conf="$BATS_TEST_DIRNAME/test_config.conf"
  cat > "$conf" <<EOF
SSH_PORT=2222
TELNET_PORT=2323
SCAN_TIMEOUT=10s
EOF

  # The config should load; we test that invalid port would fail if bad
  # and that valid config doesn't cause errors (will fail at nmap stage)
  run bash "$SCRIPT" -c "$conf" --version
  [ "$status" -eq 0 ]

  rm -f "$conf"
}

@test "config file with unknown keys produces warning" {
  local conf="$BATS_TEST_DIRNAME/test_config_unknown.conf"
  cat > "$conf" <<EOF
UNKNOWN_KEY=value
SSH_PORT=22
EOF

  run bash "$SCRIPT" -c "$conf" -n -v
  [[ "$output" == *"Unknown config key"* ]]

  rm -f "$conf"
}

# -------------------------------------------------------------------
#  Function sourcing tests
# -------------------------------------------------------------------

@test "script can be sourced without executing" {
  run bash -c "source $SCRIPT && echo 'sourced ok'"
  [[ "$output" == *"sourced ok"* ]]
}

@test "validate_port accepts valid ports" {
  run bash -c "source $SCRIPT && validate_port 22 SSH && echo ok"
  [[ "$output" == *"ok"* ]]
}

@test "validate_port rejects port 0" {
  run bash -c "source $SCRIPT && validate_port 0 SSH"
  [ "$status" -ne 0 ]
}

@test "validate_port rejects port above 65535" {
  run bash -c "source $SCRIPT && validate_port 70000 SSH"
  [ "$status" -ne 0 ]
}

@test "validate_port rejects non-numeric input" {
  run bash -c "source $SCRIPT && validate_port abc SSH"
  [ "$status" -ne 0 ]
}

# -------------------------------------------------------------------
#  Non-interactive scan test (with mock nmap)
# -------------------------------------------------------------------

@test "non-interactive scan runs without errors" {
  run bash "$SCRIPT" -n -t 192.168.1.0/24
  # With our mock nmap that returns empty output, it should warn about no hosts
  [[ "$output" == *"No active hosts"* ]] || [[ "$output" == *"No hosts to scan"* ]]
}

@test "non-interactive verbose scan includes debug output" {
  run bash "$SCRIPT" -n -v -t 192.168.1.0/24
  [[ "$output" == *"[DEBUG]"* ]]
}

@test "quiet mode suppresses INFO messages" {
  run bash "$SCRIPT" -n -q -t 192.168.1.0/24
  # Should NOT contain [INFO] lines
  if [[ "$output" == *"[INFO]"* ]]; then
    false
  fi
}
