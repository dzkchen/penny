# Next Vulnerability Fixture

This is a deliberately insecure local test app for Penny and other app-audit models.

## Intended gaps vs Penny's deterministic Python detectors

- Broken object-level authorization / IDOR on order reads and cancellations.
- CSRF exposure on a cookie-authenticated state-changing endpoint.
- Insecure session cookie configuration.
- Plaintext password storage and password logging on failed login.
- Privilege escalation by trusting a client-controlled role header.

## Notes

- Do not deploy this app.
- The routes are intentionally small and obvious so AI review tools can explain them.
- If you want to compare deterministic vs AI review, run Penny both with and without `--ai`.
