import json

from sqlalchemy import select

from app.enterprise import db as t
from app.enterprise.security import verify_password
from test_enterprise import client, login


def test_password_change_revokes_all_sessions_and_hashes_secret(client):
    user = login(client)
    first_cookie = client.cookies.get("qg_session")
    login(client)
    second_cookie = client.cookies.get("qg_session")
    password = "Sample@42"
    response = client.post("/api/admin/auth/password", json={
        "current_password": "test-password-123",
        "new_password": password, "confirm_password": password})
    assert response.status_code == 200 and response.json()["reauthentication_required"]
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert password not in response.text
    for cookie in (first_cookie, second_cookie):
        assert client.get("/api/admin/auth/me", headers={"Cookie": f"qg_session={cookie}"}).status_code == 401
    assert not client.app.state.db.all(select(t.sessions).where(t.sessions.c.user_id == user["id"]))
    assert client.post("/api/admin/auth/login", json={
        "username": "admin", "password": "test-password-123"}).status_code == 401
    login(client, password=password)
    stored = client.app.state.db.one(select(t.users).where(t.users.c.id == user["id"]))
    assert stored["password_hash"].startswith("scrypt$") and verify_password(password, stored["password_hash"])
    audits = client.app.state.db.all(select(t.operations).where(t.operations.c.action == "auth.password_changed"))
    assert len(audits) == 1 and audits[0]["target_id"] == user["id"]
    assert password not in json.dumps(audits) and "test-password-123" not in json.dumps(audits)


def test_password_change_rejects_unauthorized_invalid_and_wrong_password(client):
    payload = {"current_password": "test-password-123",
               "new_password": "Example@42", "confirm_password": "Example@42"}
    assert client.post("/api/admin/auth/password", json=payload).status_code == 401
    login(client)
    assert client.post("/api/admin/auth/password", headers={"X-CSRF-Token": "invalid"},
                       json=payload).status_code == 403
    rejected = client.post("/api/admin/auth/password", json=payload | {"current_password": "Wrong@42"})
    assert rejected.status_code == 403 and "Wrong@42" not in rejected.text
    for change in ({"confirm_password": "Different@42"},
                   {"new_password": "short", "confirm_password": "short"},
                   {"user_id": "someone-else"}):
        response = client.post("/api/admin/auth/password", json=payload | change)
        assert response.status_code == 422 and "Example@42" not in response.text
    assert client.get("/api/admin/auth/me").status_code == 200
    assert not client.app.state.db.all(select(t.operations).where(t.operations.c.action == "auth.password_changed"))


def test_member_changes_only_own_password_and_preserves_whitespace(client):
    admin = login(client)
    admin_cookie = client.cookies.get("qg_session")
    created = client.post("/api/admin/users", json={
        "username": "member", "password": "member-password-123"})
    assert created.status_code == 201
    member = login(client, username="member", password="member-password-123")
    password = "  Member@42  "
    response = client.post("/api/admin/auth/password", json={
        "current_password": "member-password-123",
        "new_password": password, "confirm_password": password})
    assert response.status_code == 200
    assert client.post("/api/admin/auth/login", json={
        "username": "member", "password": password.strip()}).status_code == 401
    assert login(client, username="member", password=password)["id"] == member["id"]
    admin_me = client.get("/api/admin/auth/me", headers={"Cookie": f"qg_session={admin_cookie}"})
    assert admin_me.status_code == 200 and admin_me.json()["user"]["id"] == admin["id"]


def test_login_rechecks_hash_after_verification(client, monkeypatch):
    from app.enterprise import admin
    from app.enterprise.security import hash_password
    original = admin.verify_password
    replacement = hash_password("updated-during-verification")
    def change_during_verification(password, encoded):
        valid = original(password, encoded)
        with client.app.state.db.engine.begin() as conn:
            conn.execute(t.users.update().values(password_hash=replacement))
        return valid
    monkeypatch.setattr(admin, "verify_password", change_during_verification)
    result = client.post("/api/admin/auth/login", json={
        "username": "admin", "password": "test-password-123"})
    assert result.status_code == 401
    assert not client.app.state.db.all(select(t.sessions))
