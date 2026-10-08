# Zscaler simulator

Specialist bots that mimic three Zscaler decisions and, when credentials are present, read the tenant through OneAPI:

- ZIA web policy: `ALLOW`, `BLOCK`, `CAUTION`, or `ISOLATE`
- ZPA private access: `ALLOW` or `BLOCK`
- DLP classification of text an operator pastes

Reserved hosts ending in `.test`, `.example`, or `.invalid` use the built-in catalog. Other hosts use URL lookup and URL filtering rules when these variables are set:

- `ZSCALER_CLIENT_ID`
- `ZSCALER_CLIENT_SECRET`
- `ZSCALER_VANITY_DOMAIN` (the label only, such as `acme`)
- `ZSCALER_CLOUD` (optional; `production` uses `api.zsapi.net`)
- `ZSCALER_CUSTOMER_ID` (required for ZPA reads)

The API client is read-only. It can look up URLs and list filtering rules, categories, DLP dictionaries, application segments, and access-policy rules. It does not activate changes, submit sandbox files, or intercept traffic.

```bash
bdk validate --dir .
bdk info --dir . --json
bdk call evaluate_web_policy --dir . --input '{"url":"https://malware.example.test"}'
bdk dev
```
