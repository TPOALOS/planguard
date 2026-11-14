# Changelog

## 1.0.0

First release.

- Reads `terraform show -json` output (file or stdin); never runs terraform
- Flags destroy/replace of critical resources, newly world-open sensitive ports, public S3 settings, encryption off, deletion protection off, new public IPs
- Change summary (add/change/delete/replace); sensitive values redacted
- `--fail-on`, `--json`, `--allow-destroy`
