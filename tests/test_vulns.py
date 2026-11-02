"""Each flaw is exploited against the vulnerable app and must fail against the secure one."""

import pytest

from shopapi import create_app


@pytest.fixture(params=[False, True], ids=["vulnerable", "secure"])
def lab(request):
    app = create_app(secure=request.param)
    return app.test_client(), request.param


def login(client, username):
    r = client.post("/api/login", json={"username": username, "password": f"{username}123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.get_json()['token']}"}


def test_idor_read_other_users_order(lab):
    client, secure = lab
    alice = login(client, "alice")
    r = client.get("/api/orders/1002", headers=alice)  # belongs to bob
    assert r.status_code == (404 if secure else 200)
    if not secure:
        assert r.get_json()["address"] == "Kwiatowa 5, Gdansk"


def test_owner_can_still_read_own_order(lab):
    client, _ = lab
    alice = login(client, "alice")
    assert client.get("/api/orders/1001", headers=alice).status_code == 200


def test_price_tampering(lab):
    client, secure = lab
    alice = login(client, "alice")
    r = client.post("/api/orders", headers=alice,
                    json={"items": [{"product_id": 3, "qty": 1, "price": 0.01}]})
    if secure:
        assert r.get_json()["total"] == 349.00
    else:
        assert r.get_json()["total"] == 0.01


def test_negative_quantity(lab):
    client, secure = lab
    alice = login(client, "alice")
    r = client.post("/api/orders", headers=alice,
                    json={"items": [{"product_id": 3, "qty": -2}]})
    assert r.status_code == (400 if secure else 201)
    if not secure:
        assert r.get_json()["total"] == -698.00


def test_admin_endpoint_open_to_regular_user(lab):
    client, secure = lab
    alice = login(client, "alice")
    r = client.get("/api/admin/users", headers=alice)
    assert r.status_code == (403 if secure else 200)
    if not secure:
        assert len(r.get_json()) == 3


def test_mass_assignment_privilege_escalation(lab):
    client, secure = lab
    alice = login(client, "alice")
    r = client.patch("/api/profile", headers=alice, json={"name": "Alice A", "role": "admin"})
    assert r.get_json()["name"] == "Alice A"
    assert r.get_json()["role"] == ("user" if secure else "admin")


def test_coupon_stacking(lab):
    client, secure = lab
    alice = login(client, "alice")
    first = client.post("/api/orders/1001/coupon", headers=alice, json={"code": "SAVE10"})
    assert first.status_code == 200 and first.get_json()["total"] == 108.00
    second = client.post("/api/orders/1001/coupon", headers=alice, json={"code": "SAVE10"})
    assert second.status_code == (409 if secure else 200)
    if not secure:
        assert second.get_json()["total"] == 97.20


def test_requires_authentication(lab):
    client, _ = lab
    assert client.get("/api/orders/1001").status_code == 401
