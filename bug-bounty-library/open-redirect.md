# Open Redirect

## Test flow

1. Locate redirect parameters like `next`, `url`, `redirect_uri`, `returnTo`.
2. Test absolute, protocol-relative, and encoded external URLs.
3. Check if allowlist validation is prefix-based and bypassable.
4. Confirm exploit chain potential (OAuth token theft, phishing).

## Payload examples

- `?next=https://evil.tld`
- `?next=//evil.tld`
- `?next=/\\evil.tld`
- `?next=https:%2f%2fevil.tld`
- `?next=https://trusted.tld.evil.tld`
- `?next=https://trusted.tld@evil.tld`

## Notes

- Standalone severity may be low, but chain impact can be critical.
- Include real chain scenario if present (for example OAuth flow abuse).
