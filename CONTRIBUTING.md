# Contributing to zlodev

Thanks for your interest in contributing!

## Getting started

1. Install [Zig 0.15.2](https://ziglang.org/download/)
2. Clone the repo and build:
   ```sh
   git clone https://github.com/vandot/zlodev.git
   cd zlodev
   zig build
   ```
3. Run tests per-file (there is no `zig build test` step):
   ```sh
   zig test src/dns.zig
   zig test src/har.zig
   zig test src/proxy.zig
   zig test src/requests.zig
   zig test src/intercept.zig
   zig test src/http_wire.zig
   zig test src/hold.zig
   zig test src/jsonfmt.zig
   zig test src/subprocess.zig
   zig test src/search.zig
   zig test src/clipboard.zig
   ```
   `tests/install.zig` and `tests/integration.zig` are run in CI; see `.github/workflows/ci.yml` for the setup they need.

## How to contribute

- **Bug reports**: Open an issue with steps to reproduce
- **Feature requests**: Open an issue describing the use case
- **Pull requests**: Fork, create a branch, make your changes, and open a PR

## Code style

- Follow existing patterns in the codebase
- Use structured log format: `component=X op=Y field=value`
- Run relevant tests before submitting

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
