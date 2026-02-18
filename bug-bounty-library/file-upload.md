# File Upload Vulnerabilities

## Test flow

1. Identify upload endpoints and post-upload retrieval paths.
2. Test server-side validation: extension, MIME type, magic bytes.
3. Attempt filename/path manipulation and double extensions.
4. Check if uploaded files are executable or publicly accessible.
5. Probe parser-based vectors (image libraries, document converters).

## Payload examples

### Extension and content tricks

- `shell.php` with image MIME.
- `image.jpg.php`
- `image.php%00.jpg` (legacy null-byte checks)
- Polyglot file (valid image + script payload)

### Filename manipulation

- `../../test.txt`
- `..%2f..%2fwebroot/shell.php`

### SVG script probe

- Upload SVG containing script/event payloads and open via app-rendered context.

## Notes

- Report includes storage path, execution path, and access controls.
- Distinguish direct RCE vs stored XSS via uploaded content.
