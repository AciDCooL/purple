# Security Policy

## Supported versions

Only the latest release receives security patches.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

## Reporting a vulnerability

Please report vulnerabilities through
[GitHub Security Advisories](https://github.com/erickochen/purple/security/advisories/new).

Do not open a public issue for security vulnerabilities.

If GitHub is inaccessible you can email security@getpurple.sh.

### What to include

- Description of the vulnerability and its impact
- Steps to reproduce or a proof of concept
- The version of purple you tested against
- Whether the issue is already publicly known

### What to expect

- We aim to acknowledge reports within a week
- We aim to provide a fix or status update within 30 days
- Credit in the changelog and GitHub advisory (unless you prefer
  to stay anonymous)

We will not pursue legal action against anyone who reports a
vulnerability in good faith and follows this policy.

## Scope

### In scope

- Credential or token leakage (askpass, keychain, provider tokens)
- SSH config injection or path traversal
- Arbitrary code execution not initiated by the user
- File browser directory traversal beyond intended scope
- Container ID or shell command injection
- Bypass of TLS verification when not explicitly disabled
- Tampering with the self-update mechanism

### Out of scope

Purple is a terminal SSH client that executes commands by design.
The following are not considered vulnerabilities:

- Command execution via SSH connections. Purple spawns the system
  `ssh` binary as its core function
- Snippet execution on user-selected hosts
- Askpass prompting for passwords the user has configured
- Attacks that require pre-existing access to the user's machine.
  Read access to `~/.ssh/config` and `~/.purple/` is assumed.
  Bugs that cause purple to write sensitive files with wrong
  permissions are still in scope
- Denial of service against the local TUI process
- Social engineering or phishing

## Disclosure policy

We follow coordinated disclosure with a 90-day window. Please
keep your report confidential until a fix is released or 90 days
have passed since the initial report.
