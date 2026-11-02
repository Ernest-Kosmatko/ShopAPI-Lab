# 03. Admin endpoint open to regular users

| | |
|---|---|
| Severity | High |
| Category | OWASP API Security Top 10 2023, API5 Broken Function Level Authorization |
| CWE | CWE-285 Improper Authorization |
| Endpoint | `GET /api/admin/users` |

## Summary

The admin endpoint requires a valid login but does not check the role. Hiding it behind an `/admin` path does not protect it.

## Reproduce

```bash
curl -s localhost:5000/api/admin/users -H "Authorization: Bearer $TOKEN"
```

A regular user receives `200` with all accounts: usernames, e-mails and roles.

## Impact

Full user enumeration, including which accounts are administrators. This helps phishing and password attacks against privileged accounts.

## Root cause

Authentication is checked (`@auth_required`) but authorization is not.

## Fix

```python
if g.user["role"] != "admin":
    return error(403, "admin only")
```

Apply authorization in one place, for example a decorator or middleware keyed by role, so a new endpoint cannot forget it.

## How to find it in a real test

Collect admin-only URLs from the JavaScript bundle, documentation and responses, then call them with a low privilege token. Also try changing the HTTP method (`GET` to `POST`, `PUT`, `DELETE`) on endpoints that are protected only for one method.
