# 02. Client-controlled price and negative quantity

| | |
|---|---|
| Severity | High |
| Category | OWASP API Security Top 10 2023, API6 Unrestricted Access to Sensitive Business Flows (business logic) |
| CWE | CWE-472 External Control of Assumed-Immutable Web Parameter, CWE-20 Improper Input Validation |
| Endpoint | `POST /api/orders` |

## Summary

The order endpoint accepts a `price` per item from the client and uses it for the total. It also accepts negative quantities.

## Reproduce

```bash
# pay one cent for a 349 monitor
curl -s -X POST localhost:5000/api/orders -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"product_id":3,"qty":1,"price":0.01}]}'
# total: 0.01

# negative quantity gives a negative total
curl -s -X POST localhost:5000/api/orders -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"product_id":3,"qty":-2}]}'
# total: -698.0
```

## Impact

Goods can be bought at any price. A negative total can turn into a refund or store credit depending on how payment is processed downstream. This causes direct financial loss.

## Root cause

```python
price = raw.get("price", product["price"])   # client value wins
qty = raw.get("qty")                          # only checked for int
```

## Fix

```python
if not 1 <= qty <= 100:
    return error(400, "qty must be between 1 and 100")
price = product["price"]                      # always from the server
```

Prices and totals are computed on the server from trusted data. The client sends only product IDs and quantities.

## How to find it in a real test

Intercept the checkout request in Burp and edit every numeric field: price, quantity, discount, shipping. Try zero, negative, very large and decimal values. Compare the server's total with what you sent.
