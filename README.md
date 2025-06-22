# IoTScanner
# A script that tests IoT devices on your network.

To use this script clone it into a directory on your machine by running

`git clone https://github.com/sfxhewitt/IoTScanner`

you may need to give execute permissions, do this by typing

`chmod +x IoTScanner.sh`

then run it by typing

`./IoTScanner.sh or bash IoTScanner.sh`

## Testing

Tests are written using [bats-core](https://github.com/bats-core/bats-core).
Install bats and run the following command from the repository root:

```bash
make test
```

This will execute all tests under the `test/` directory.
