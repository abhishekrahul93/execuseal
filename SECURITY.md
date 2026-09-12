# Security Policy

This project is pre-alpha and must not be treated as a complete security
boundary. Do not deploy it as the only control protecting high-impact systems.

Please do not open public issues for suspected vulnerabilities. Until a private
reporting address is established, use GitHub's private vulnerability reporting
feature on the repository. Include reproduction steps, expected impact, and the
affected version. We will acknowledge reports when the public repository is
launched and publish a supported-version policy before the first stable release.

## Deployment warning

The current API-key mechanism is an initial authenticated boundary. Use HTTPS,
store keys outside source control, restrict network exposure, and rotate any key
that may have leaked. The in-memory audit chain resets on process restart and is
not suitable as the only production audit record.
