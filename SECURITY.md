# Security Policy

zlodev installs a local certificate authority into your system trust store and
binds ports 80, 443 and (optionally) 53, so security reports are taken seriously.

## Supported versions

Only the [latest release](https://github.com/vandot/zlodev/releases/latest) receives
security fixes. Please confirm the issue on the latest release before reporting.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report privately through GitHub:
[Report a vulnerability](https://github.com/vandot/zlodev/security/advisories/new)

Include, where you can:

- zlodev version (`zlodev --version`) and operating system
- how zlodev was started (flags or `.zlodev` config)
- steps to reproduce, and what an attacker gains

You can expect an acknowledgement within 7 days. Once a fix is ready, it ships in
a new release and the advisory is published with credit to the reporter, unless
you prefer to stay anonymous.

## Scope

In scope:

- the generated CA and leaf certificates, their private keys and file permissions
- trust store installation and removal (`install` / `uninstall`)
- the proxy, HTTP server and DNS server being reachable or abusable by anyone
  other than the local user in the default configuration
- memory safety and parsing bugs reachable from the network
- the release artifacts and `install.sh`

Out of scope:

- exposure that follows from explicitly binding to a non-loopback address
  (`--bind`, `-l`), which is intended to accept remote clients
- behaviour of the upstream dev server that zlodev forwards to
- attacks that require an attacker who already runs code as the local user
