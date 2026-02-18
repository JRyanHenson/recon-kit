# Insecure Direct Object Reference (IDOR/BOLA)

## Test flow

1. Identify object references: IDs, UUIDs, order numbers, filenames.
2. Capture baseline request as User A.
3. Replay with User B and swap object identifiers.
4. Test read, update, delete, and action endpoints.
5. Verify if authorization checks are object-level, not just role-level.

## Test patterns

- Increment/decrement numeric IDs (`1001` -> `1002`).
- Replace UUIDs from another account.
- Swap nested object IDs in JSON.
- Test mobile/API endpoints separately from web UI.

## Payload examples

### Path/Query

- `GET /api/v1/invoices/1002`
- `GET /api/v1/users/<victim_uuid>/profile`

### JSON body

```json
{
  "account_id": "victim-account-id",
  "transfer_amount": 100
}
```

## Notes

- Strong evidence includes cross-account data access or modification.
- Include before/after screenshots and object ownership proof.
