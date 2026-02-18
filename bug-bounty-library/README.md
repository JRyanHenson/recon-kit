# Bug Bounty Testing Library

A quick-reference library of testing steps and payload examples for common web bug bounty classes.

## How to use this library

1. Pick a bug class below.
2. Follow the test flow in order.
3. Start with low-noise payloads before high-impact checks.
4. Log request/response pairs and evidence as you test.

## Bug class sheets

- [Cross-Site Scripting (XSS)](xss.md)
- [SQL Injection (SQLi)](sqli.md)
- [Server-Side Request Forgery (SSRF)](ssrf.md)
- [Insecure Direct Object References (IDOR/BOLA)](idor.md)
- [Authentication and Session Weaknesses](auth-session.md)
- [Cross-Site Request Forgery (CSRF)](csrf.md)
- [File Upload Vulnerabilities](file-upload.md)
- [Open Redirect](open-redirect.md)
- [Path Traversal and Local File Inclusion](path-traversal-lfi.md)
- [OS Command Injection](command-injection.md)

## Reporting checklist

- Clear reproduction steps with exact endpoint and method.
- Payload used and why it works.
- Security impact on confidentiality, integrity, or availability.
- Practical remediation guidance.
