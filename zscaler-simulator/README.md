# Zscaler simulator

Specialist bots that mimic three Zscaler decisions and, when credentials are present, read the tenant through OneAPI:

- ZIA web policy: `ALLOW`, `BLOCK`, `CAUTION`, or `ISOLATE`
- ZPA private access: `ALLOW` or `BLOCK`
- DLP classification of text an operator pastes

For integrators, `build_zpa_integration_map` turns app segments and access policies into a stable JSON shape. It links direct app and segment-group policy targets, identifies segments without policy coverage, flags policy targets that no longer resolve, and lists unsupported condition types. `evaluate_private_access` uses live app segments and top-down access policies when the requested application is not one of the local demo segments.

Reserved hosts ending in `.test`, `.example`, or `.invalid` use the built-in catalog. Other hosts use URL lookup and URL filtering rules when these variables are set:

- `ZSCALER_CLIENT_ID`
- `ZSCALER_CLIENT_SECRET`
- `ZSCALER_VANITY_DOMAIN` (the label only, such as `acme`)
- `ZSCALER_CLOUD` (optional; `production` uses `api.zsapi.net`)
- `ZSCALER_CUSTOMER_ID` (required for ZPA reads)

The API client is read-only. It can look up URLs and list filtering rules, categories, DLP dictionaries, application segments, and access-policy rules. It does not activate changes, submit sandbox files, or intercept traffic.

Live policy simulation supports common `APP`, `APP_GROUP`, `SAML`, `SAML_GROUP`, `SCIM`, `SCIM_GROUP`, `POSTURE`, `PLATFORM`, and `CLIENT_TYPE` criteria. Unknown or missing criteria fail closed. A response with `complete: false` must not be treated as a complete tenant export.

```bash
bdk validate --dir .
bdk info --dir . --json
bdk call evaluate_web_policy --dir . --input '{"url":"https://malware.example.test"}'
bdk call build_zpa_integration_map --dir . --input '{"source":"mock"}'
bdk dev
```
