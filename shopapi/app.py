"""A small shop API with deliberate authorization and business logic flaws.

Run it in vulnerable mode to practice, or in secure mode (LAB_MODE=secure) to see
the same endpoints with the fixes applied. Bind it to localhost only.
"""

from __future__ import annotations

import os
import secrets
import threading
from functools import wraps

from flask import Flask, g, jsonify, request

PRODUCTS = {
    1: {"name": "Mechanical keyboard", "price": 120.00},
    2: {"name": "USB-C cable", "price": 9.90},
    3: {"name": "Monitor 27in", "price": 349.00},
}

COUPONS = {"SAVE10": 0.10}

PROFILE_FIELDS_ALLOWED = {"name", "email"}


def _seed():
    users = {
        1: {"id": 1, "username": "alice", "password": "alice123",
            "email": "alice@shop.test", "name": "Alice", "role": "user"},
        2: {"id": 2, "username": "bob", "password": "bob123",
            "email": "bob@shop.test", "name": "Bob", "role": "user"},
        3: {"id": 3, "username": "admin", "password": "admin123",
            "email": "admin@shop.test", "name": "Admin", "role": "admin"},
    }
    orders = {
        1001: {"id": 1001, "user_id": 1, "address": "Dluga 1, Poznan",
               "items": [{"product_id": 1, "qty": 1, "price": 120.00}],
               "coupons": [], "total": 120.00},
        1002: {"id": 1002, "user_id": 2, "address": "Kwiatowa 5, Gdansk",
               "items": [{"product_id": 3, "qty": 1, "price": 349.00}],
               "coupons": [], "total": 349.00},
    }
    return users, orders


def _public_user(user: dict) -> dict:
    return {k: v for k, v in user.items() if k != "password"}


def create_app(secure: bool | None = None) -> Flask:
    if secure is None:
        secure = os.environ.get("LAB_MODE", "vulnerable").lower() == "secure"

    app = Flask(__name__)
    app.config["SECURE"] = secure

    users, orders = _seed()
    tokens: dict[str, int] = {}
    next_order_id = [1003]
    coupon_lock = threading.Lock()

    def error(status: int, message: str):
        return jsonify({"error": message}), status

    def auth_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            token = header[7:] if header.startswith("Bearer ") else ""
            user_id = tokens.get(token)
            if user_id is None:
                return error(401, "authentication required")
            g.user = users[user_id]
            return fn(*args, **kwargs)
        return wrapper

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "mode": "secure" if secure else "vulnerable"})

    @app.post("/api/login")
    def login():
        body = request.get_json(silent=True) or {}
        for user in users.values():
            if (user["username"] == body.get("username")
                    and user["password"] == body.get("password")):
                token = secrets.token_hex(16)
                tokens[token] = user["id"]
                return jsonify({"token": token})
        return error(401, "invalid credentials")

    # Flaw 1: broken object level authorization (IDOR)
    @app.get("/api/orders/<int:order_id>")
    @auth_required
    def get_order(order_id: int):
        order = orders.get(order_id)
        if order is None:
            return error(404, "order not found")
        if secure and order["user_id"] != g.user["id"] and g.user["role"] != "admin":
            return error(404, "order not found")
        return jsonify(order)

    @app.get("/api/orders")
    @auth_required
    def list_orders():
        mine = [o for o in orders.values() if o["user_id"] == g.user["id"]]
        return jsonify(mine)

    # Flaw 2: client controlled price and negative quantity
    @app.post("/api/orders")
    @auth_required
    def create_order():
        body = request.get_json(silent=True) or {}
        items = []
        for raw in body.get("items", []):
            product = PRODUCTS.get(raw.get("product_id"))
            if product is None:
                return error(400, "unknown product")
            qty = raw.get("qty")
            if not isinstance(qty, int):
                return error(400, "qty must be an integer")
            if secure:
                if not 1 <= qty <= 100:
                    return error(400, "qty must be between 1 and 100")
                price = product["price"]
            else:
                price = raw.get("price", product["price"])
            items.append({"product_id": raw["product_id"], "qty": qty, "price": price})
        if not items:
            return error(400, "no items")

        order_id = next_order_id[0]
        next_order_id[0] += 1
        orders[order_id] = {
            "id": order_id, "user_id": g.user["id"],
            "address": body.get("address", ""), "items": items, "coupons": [],
            "total": round(sum(i["price"] * i["qty"] for i in items), 2),
        }
        return jsonify(orders[order_id]), 201

    # Flaw 3: broken function level authorization
    @app.get("/api/admin/users")
    @auth_required
    def admin_users():
        if secure and g.user["role"] != "admin":
            return error(403, "admin only")
        return jsonify([_public_user(u) for u in users.values()])

    # Flaw 4: mass assignment
    @app.patch("/api/profile")
    @auth_required
    def update_profile():
        body = request.get_json(silent=True) or {}
        for key, value in body.items():
            if key in ("id", "password"):
                continue
            if secure and key not in PROFILE_FIELDS_ALLOWED:
                continue
            g.user[key] = value
        return jsonify(_public_user(g.user))

    # Flaw 5: coupon can be applied repeatedly
    @app.post("/api/orders/<int:order_id>/coupon")
    @auth_required
    def apply_coupon(order_id: int):
        order = orders.get(order_id)
        if order is None or order["user_id"] != g.user["id"]:
            return error(404, "order not found")
        code = (request.get_json(silent=True) or {}).get("code")
        rate = COUPONS.get(code)
        if rate is None:
            return error(400, "invalid coupon")
        # The check and the update must be one atomic step, otherwise parallel
        # requests can all pass the check before any of them records the coupon.
        with coupon_lock:
            if secure and code in order["coupons"]:
                return error(409, "coupon already used on this order")
            order["coupons"].append(code)
            order["total"] = round(order["total"] * (1 - rate), 2)
        return jsonify(order)

    return app


def main() -> None:
    app = create_app()
    mode = "secure" if app.config["SECURE"] else "VULNERABLE"
    print(f"ShopAPI lab running in {mode} mode on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)


if __name__ == "__main__":
    main()
