# 04. Mass assignment lets a user make themselves admin

| | |
|---|---|
| Severity | Critical |
| Category | OWASP API Security Top 10 2023, API3 Broken Object Property Level Authorization |
| CWE | CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| Endpoint | `PATCH /api/profile` |

## Summary

The profile endpoint copies every field from the request body onto the user object. The UI sends only `name` and `email`, but the server also accepts `role`.

## Reproduce

```bash
curl -s -X PATCH localhost:5000/api/profile -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice","role":"admin"}'
```

The response shows `"role": "admin"`. The same token can now call admin functions.

## Impact

Any registered user can escalate to administrator with one request, which gives full control over the application's data.

## Root cause

```python
for key, value in body.items():
    g.user[key] = value        # any key, including role
```

## Fix

```python
PROFILE_FIELDS_ALLOWED = {"name", "email"}
...
if key not in PROFILE_FIELDS_ALLOWED:
    continue
```

Use an explicit allowlist of writable fields. Do not bind request bodies directly to internal objects, and keep roles out of any user-writable model.

## How to find it in a real test

Take the response of a `GET` on an object, look at fields the UI never sends (`role`, `isAdmin`, `balance`, `verified`), and add them to the `PATCH` or `POST` body.
