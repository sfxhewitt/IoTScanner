#!/usr/bin/env bats

setup() {
  TEST_BIN="$BATS_TEST_DIRNAME/mockbin"
  mkdir -p "$TEST_BIN"
  cat <<'EOM' > "$TEST_BIN/sudo"
#!/bin/bash
shift
"$@"
EOM
  chmod +x "$TEST_BIN/sudo"
  cat <<'EOM' > "$TEST_BIN/apt"
#!/bin/bash
exit 0
EOM
  chmod +x "$TEST_BIN/apt"
  cat <<'EOM' > "$TEST_BIN/nmap"
#!/bin/bash
exit 0
EOM
  chmod +x "$TEST_BIN/nmap"
  export PATH="$TEST_BIN:$PATH"
  cd "$BATS_TEST_DIRNAME/.."  # move to repo root
}

teardown() {
  rm -rf "$TEST_BIN"
}

@test "main menu is displayed" {
  run bash -c "echo 3 | ./IoT-Scanner.sh"
  [[ "$output" == *"Please enter your choice"* ]]
}
