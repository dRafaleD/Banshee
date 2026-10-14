# Ongoing security checks

Banshee's support and private reporting policy is in [SECURITY.md](../SECURITY.md).
Only the latest development branch and subsequent release receive fixes; old
tags do not acquire a separate maintenance promise. No SLA is claimed.

- `security.yml` runs on dependency changes, weekly and on manual dispatch. It
  audits both application and fuzz lockfiles; advisories and warnings fail the job.
- `fuzz.yml` runs bounded parser smoke campaigns on relevant changes, weekly and
  on dispatch. Failed inputs remain available as artifacts for 14 days.
- Dependabot checks application dependencies, fuzz dependencies and action pins
  weekly. An update proposal is not an automatically approved security fix.
- CI runs security regression tests on each supported native architecture. A
  passing dependency audit is not a complete source-code security assessment.

## Handle a failure

1. Preserve the exact commit, run URL, tool/advisory versions and synthetic input.
2. Reproduce safely offline in a restricted environment. Never execute samples.
3. Review reachability and impact; do not blindly suppress an advisory or change
   a parser limit to make the check pass.
4. Add a regression, fix the cause, then verify all affected platforms. Use the
   private reporting channel for sensitive findings before public disclosure.
5. Record the affected and fixed versions in release notes. Check the next
   scheduled run; an old green badge does not establish current health.

GitHub delivers workflow failure notifications according to each maintainer's
account settings. This project does not silently change those preferences or
promise an external alert service. No public security issues are created
automatically from potentially sensitive scanner output.

GitHub schedules run from the default branch. These expanded checks are
implemented and verified on the quality-cycle development branch; their new
weekly schedules take effect after review/merge to master. A branch push/manual
run verifies the jobs, not future scheduler delivery.
