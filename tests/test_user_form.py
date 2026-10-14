"""The new-user form can require a password change at first sign-in."""

from __future__ import annotations

from flask import Flask

from security_console.users import _account_body, _can_reset_password


def _body(**extra: object) -> dict[str, object]:
    body: dict[str, object] = {
        "first_name": "New",
        "last_name": "User",
        "username": "new-user",
        "email": "new@example.com",
        "password": "correct-password",
        "role": "developer",
        "access": {},
    }
    body.update(extra)
    return body


def test_a_new_user_can_be_required_to_change_the_password() -> None:
    app = Flask(__name__)
    with app.app_context():
        parsed = _account_body(
            _body(must_change_password=True),
            password_required=True,
        )

    assert parsed["must_change_password"] is True


def test_a_new_user_keeps_the_password_when_the_flag_is_off() -> None:
    app = Flask(__name__)
    with app.app_context():
        parsed = _account_body(_body(), password_required=True)
        edited = _account_body(
            _body(must_change_password=True, password=""),
            password_required=False,
            current={"first_name": "New", "last_name": "User"},
        )

    assert parsed["must_change_password"] is False
    assert edited["must_change_password"] is False


def test_a_new_user_can_be_created_without_an_email() -> None:
    app = Flask(__name__)
    with app.app_context():
        blank = _account_body(_body(email="  "), password_required=True)
        omitted = _body()
        del omitted["email"]
        missing = _account_body(omitted, password_required=True)
        bad = _account_body(_body(email="not-an-email"), password_required=True)
        cleared = _account_body(
            _body(email="", password=""),
            password_required=False,
            current={
                "first_name": "New",
                "last_name": "User",
                "email": "old@example.com",
            },
        )

    assert blank["email"] == ""
    assert missing["email"] == ""
    assert bad.status_code == 400
    assert cleared["email"] == ""


def test_a_reset_requires_the_next_sign_in_only_with_a_password() -> None:
    app = Flask(__name__)
    current = {"first_name": "New", "last_name": "User"}
    with app.app_context():
        forced = _account_body(
            _body(password="replacement-pass", must_change_password=True),
            password_required=False,
            current=current,
        )
        optional = _account_body(
            _body(password="replacement-pass", must_change_password=False),
            password_required=False,
            current=current,
        )
        blank = _account_body(
            _body(password="", must_change_password=True),
            password_required=False,
            current=current,
        )

    assert forced["must_change_password"] is True
    assert optional["must_change_password"] is False
    assert blank["must_change_password"] is False


def test_only_the_admin_account_resets_another_admin() -> None:
    root = {"id": 1, "username": "admin", "role": "admin"}
    deputy = {"id": 4, "username": "sam", "role": "admin"}
    member = {"id": 2, "username": "ada", "role": "viewer"}

    assert _can_reset_password(root, member) is True
    assert _can_reset_password(deputy, member) is True
    assert _can_reset_password(root, deputy) is True
    assert _can_reset_password(deputy, root) is False
    assert _can_reset_password(root, root) is False
    assert _can_reset_password(member, deputy) is False
