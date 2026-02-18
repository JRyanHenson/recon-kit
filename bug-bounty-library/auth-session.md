# Authentication and Session Weaknesses

## Test flow

1. Map login, registration, reset, MFA, and session lifecycle endpoints.
2. Check brute-force/rate-limit controls and lockout behavior.
3. Test password reset tokens for predictability/reuse/expiry issues.
4. Validate session invalidation on logout/password change.
5. Inspect cookie flags and token handling in browser/mobile clients.

## Test checks

- Missing `HttpOnly`, `Secure`, `SameSite` on session cookies.
- Session fixation after login.
- JWT issues: `alg=none`, weak secret, missing signature verification.
- MFA bypass through alternate endpoints or flow tampering.
- Verbose authentication errors that enable user enumeration.

## Payload examples

### Username enumeration pattern

- Compare response difference for:
- `email=known_user@target.tld`
- `email=unknown_user@target.tld`

### JWT tampering

- Change role claim from `user` to `admin` and test authorization response.
- Try expired token reuse.

## Notes

- Prioritize account takeover and privilege escalation impact.
- Document exact session/token timeline for reproducibility.
