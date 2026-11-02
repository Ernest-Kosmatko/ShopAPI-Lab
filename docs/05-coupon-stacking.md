# 05. Coupon can be applied repeatedly

| | |
|---|---|
| Severity | Medium |
| Category | OWASP API Security Top 10 2023, API6 Unrestricted Access to Sensitive Business Flows |
| CWE | CWE-799 Improper Control of Interaction Frequency, CWE-841 Improper Enforcement of Behavioral Workflow |
| Endpoint | `POST /api/orders/{id}/coupon` |

## Summary

A single-use 10 percent coupon can be applied to the same order any number of times. Each call lowers the total again.

## Reproduce

```bash
for i in 1 2 3; do
  curl -s -X POST localhost:5000/api/orders/1001/coupon \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"code":"SAVE10"}'
done
```

The total goes 120.00, 108.00, 97.20, 87.48. A script can bring it close to zero.

## Impact

Loss of revenue and abuse of promotions. The flaw is invisible to scanners because every response is a valid `200`.

## Root cause

The server keeps a list of applied coupons but never checks it before applying again.

## Fix

```python
if code in order["coupons"]:
    return error(409, "coupon already used on this order")
```

Enforce business rules (single use, per customer limit, expiry) on the server, and apply the discount to the original price, not to the already discounted total.

The check and the update must also be atomic. If they are two steps, parallel requests can all pass the check before any of them records the coupon. In the lab's secure mode both steps run under a lock; in a real system use a database transaction or a unique constraint.

## How to find it in a real test

For every action that has a rule in the UI ("one per customer", "once"), send the request repeatedly, in parallel as well. Parallel requests can also break the check through a race condition when the "already used" state is written late.
