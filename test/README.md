# Tests

This directory contains tests for **IoT-Scanner.sh**.

## Setup

Install [bats-core](https://github.com/bats-core/bats-core). On Debian/Ubuntu:

```bash
sudo apt install bats
```

Or install from source:

```bash
git clone https://github.com/bats-core/bats-core.git
sudo ./bats-core/install.sh /usr/local
```

## Running tests

From the repository root, run:

```bash
make test
```

This will execute all Bats tests inside this directory.
