# Security Policy

## Reporting a Vulnerability

**Do not** open a public issue for security vulnerabilities. Instead, email your report to security@ralabarge.dev with:

- **Title**: Brief description of the vulnerability
- **Affected version(s)**: Which bluTruth versions are affected
- **Description**: Technical details and proof-of-concept (if possible)
- **Impact**: What an attacker could do if this vulnerability is exploited
- **Proposed fix** (optional): Any ideas on how to fix it

We will acknowledge receipt within 48 hours and provide an estimated timeline for a fix.

## Security Response Timeline

- **Acknowledgment**: Within 48 hours of report
- **Investigation & patch development**: 5-14 days depending on severity
- **Release**: We will issue a security release as soon as the fix is ready
- **Disclosure**: We will disclose the vulnerability details 30 days after the public fix is released

## Severity Levels

| Level | Description | Response Time |
|-------|-------------|----------------|
| **Critical** | Arbitrary code execution, complete system compromise | 24-48 hours |
| **High** | Authentication bypass, privilege escalation | 3-5 days |
| **Medium** | Information disclosure, limited privilege escalation | 5-14 days |
| **Low** | Minor issues, cosmetic problems | Next release |

## Security Best Practices

### For bluTruth Users

1. **Keep bluTruth updated**: Security patches are released regularly. Run `pip install --upgrade blutruth` to get the latest version.

2. **Restrict access to btmon**: bluTruth requires `cap_net_admin` or root. Only give this capability to trusted users:
   ```bash
   sudo setcap cap_net_admin+eip $(which btmon)
   ```

3. **Protect stored logs**: SQLite databases and JSONL files contain raw Bluetooth traffic. Restrict file permissions:
   ```bash
   chmod 600 ~/.local/share/blutruth/*.db
   chmod 600 ~/.local/share/blutruth/*.jsonl
   ```

4. **Use secure transports**: If running the web UI on a network, use TLS:
   ```bash
   blutruth serve --host 0.0.0.0 --ssl-certfile cert.pem --ssl-keyfile key.pem
   ```

5. **Monitor for suspicious devices**: bluTruth logs all connected devices. Regularly review device history for unauthorized access.

### For Contributors

1. All commits should be signed (`git commit -S`)
2. All pull requests must pass security checks:
   - `pip-audit` for dependency vulnerabilities
   - `bandit` for code-level issues
   - `semgrep` for pattern-based security flaws
3. Changes to HCI parsing or kernel interaction need careful review
4. New collectors should isolate untrusted input (device names, log content)

## Known Limitations

- **Device ID spoofing**: MAC addresses can be spoofed. Trust the source of your Bluetooth devices.
- **Kernel module tampering**: If the kernel module is compromised, all data from `dmesg` and eBPF cannot be trusted.
- **Air capture**: The Ubertooth and BLE sniffer collectors are mock-only and not functional.
- **Timing side-channels**: Correlation engine timestamps rely on kernel monotonic clocks which can be skewed.

## Security Audit

bluTruth has not undergone a third-party security audit. If you're considering using it in a regulated environment, we recommend:

1. Internal code review by your security team
2. Fuzz testing on HCI parsers
3. Review of eBPF kernel module code
4. Assessment of data handling in collectors

We welcome and encourage security audits. If you've found issues during an audit, please report them using the process above.

## Dependencies & Vulnerabilities

We use `pip-audit` to continuously check for vulnerable dependencies. Run it yourself:

```bash
pip-audit --desc
```

To report a vulnerable dependency issue:

```bash
pip install --upgrade blutruth
```

If you find a vulnerability in a dependency, follow this process:

1. Report it to the upstream project's security contact
2. File an issue with us if bluTruth is affected
3. We'll release a patched version with updated pins

## Security Releases

Security releases are issued as `X.Y.Z` (no `-alpha` or `-beta` tags) and announced on:

- GitHub Releases page
- Project README (pinned notice)
- Email to watchers (if subscribed)

Subscribe to security releases: https://github.com/RALaBarge/bluTruth/releases/tag/security-notice
