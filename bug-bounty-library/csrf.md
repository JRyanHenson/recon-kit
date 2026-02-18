# Cross-Site Request Forgery (CSRF)

## Test flow

1. Identify state-changing actions: email/password change, payment details, transfers.
2. Verify if anti-CSRF token is required and validated server-side.
3. Check if token is bound to session and action.
4. Test SameSite cookie behavior and CORS assumptions.
5. Build PoC HTML form and confirm action in victim browser context.

## Payload examples

### Basic auto-submit PoC

```html
<form action="https://target.tld/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.tld">
</form>
<script>document.forms[0].submit()</script>
```

### JSON endpoint probe

- Test if endpoint accepts `application/x-www-form-urlencoded` fallback.
- Check if preflight/CORS blocks are incorrectly relied upon as CSRF defense.

## Notes

- High severity when action is sensitive and needs no user interaction.
- If CSRF token exists, test replay, omission, and cross-account reuse.
