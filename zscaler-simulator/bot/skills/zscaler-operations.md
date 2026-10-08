---
description: Use when choosing a Zscaler specialist, reading OneAPI, or explaining a mock versus live policy decision.
---

# Zscaler operations

1. Web browsing, URL categories, or cloud-app actions go to `zia-web`, which calls `evaluate_web_policy`.
2. Private applications, ZPA, app segments, device posture, or user groups go to `zpa-access`, which calls `evaluate_private_access`. Pass `managedDevice` and `mfa` from the request. Omitted posture checks are treated as failed.
3. Pasted text, DLP, credentials, or card numbers go to `dlp-inspector`, which calls `classify_sensitive_data`.
4. A request to list tenant configuration calls `zscaler_api` with one of: `zia.urlLookup`, `zia.listUrlFilteringRules`, `zia.listUrlCategories`, `zia.listDlpDictionaries`, `zpa.listApplicationSegments`, `zpa.listAccessPolicyRules`.
5. Integration discovery, app-to-policy mapping, coverage, orphan targets, or normalized export calls `build_zpa_integration_map`. Prefer `source: "auto"`.
6. For live ZPA simulation, pass known `postureProfileIds`, `platform`, and `clientType` to `evaluate_private_access`. Missing or unsupported criteria fail closed.
7. Report `warning` when it is present. Missing credentials are a normal mock-mode result, not a failure of the local decision.
8. Do not invent a Zscaler action the tool did not return. Do not offer to activate staged changes.
