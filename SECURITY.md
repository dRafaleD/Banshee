# Security policy

Banshee is an alpha-stage, offline analysis tool. Security fixes target the latest
development branch and subsequent release; older tags have no separate maintenance
branch. No response-time or support SLA is promised.

## Report a vulnerability

Use GitHub's private vulnerability reporting option under the repository's
Security tab when available. If it is unavailable, open an issue requesting a
private reporting channel without including vulnerability details or samples.

Include the affected version/commit, OS, command, expected behavior, observed
impact and a minimal synthetic reproduction. Remove credentials and personal data.
Do not upload malware or real private keys. Coordinate disclosure with maintainers.

## Trust boundaries

- Parsing untrusted input is bounded but is not a sandbox. Use a restricted account
  and an isolated environment for hostile files.
- Secret detection is heuristic. Redaction cannot guarantee removal of every secret.
- Evidence SHA-256 manifests detect inconsistencies, not authenticity: someone who
  can replace both files and manifest can produce a self-consistent bundle.
- Bundles omit samples by default; `--include-sample` copies the original data.
- JWT inspection is not verification. Certificate-chain checks do not establish OS
  trust or online revocation status; PE signature presence is metadata only.
- Dependency audits cover published advisories, not all possible vulnerabilities.

Do not run Banshee as a privileged service. Treat reports as sensitive and review
them before sharing. See the README for command-specific resource limits.
