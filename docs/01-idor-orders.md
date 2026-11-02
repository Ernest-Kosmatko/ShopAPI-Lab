# 01. IDOR in the order endpoint

| | |
|---|---|
| Severity | High |
| Category | OWASP API Security Top 10 2023, API1 Broken Object Level Authorization |
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| Endpoint | `GET /api/orders/{id}` |

## Summary

The endpoint checks that the caller is logged in, but not that the order belongs to the caller. Any user can read any order by changing the ID in the URL.

## Reproduce

```bash
TOKEN=$(curl -s -X POST localhost:5000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 1001 is alice's own order, 1002 belongs to bob
curl -s localhost:5000/api/orders/1002 -H "Authorization: Bearer $TOKEN"
```

The response is `200` and contains bob's delivery address and items.

## Impact

Order IDs are sequential, so an attacker with one free account can read every customer's name, address and purchases by counting upwards. That is a personal data leak (GDPR) and enables targeted fraud.

## Root cause

```python
order = orders.get(order_id)
if order is None:
    return error(404, "order not found")
return jsonify(order)          # no ownership check
```

## Fix

```python
if order["user_id"] != g.user["id"] and g.user["role"] != "admin":
    return error(404, "order not found")
```

- Enforce ownership on the server for every object access.
- Return `404`, not `403`, so the existence of other IDs is not revealed.
- Non-sequential IDs (UUIDs) are defense in depth, not a fix on their own.

## How to find it in a real test

Log in as two users, collect an object ID from each, then request user B's object with user A's token. Repeat for every endpoint that takes an ID, including update and delete. Scanners usually miss this because the response is a normal `200`.
