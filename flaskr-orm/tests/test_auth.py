import pytest
from flask import  session
from flaskr.database import db
from flaskr.models import User
from flask_jwt_extended import current_user



def test_register(client, app, auth):
    assert client.get('/auth/register').status_code == 200
    response = auth.register("a", "a")
    
    assert response.headers["Location"] == "/auth/login"

    with app.app_context():
        stmt = db.select(User).where(User.username == "a")
        assert db.session.execute(stmt).scalar() is not None


@pytest.mark.parametrize(('username', 'password', 'message'), (
    ('', '', b'Username is required.'),
    ('a', '', b'Password is required.'),
    ('test', 'test', b'already registered'),
))
def test_register_validate_input(client, username, password, message, auth):
    response = auth.register(username, password)
    assert message in response.data


def test_login(client, auth):
    response = auth.login()
    assert response.headers["Location"] == "/"

    with client:
        client.get('/')
        assert current_user.id == 1
        assert current_user.username== 'test'


@pytest.mark.parametrize(('username', 'password', 'message'), (
    ('a', 'test', b'Incorrect username.'),
    ('test', 'a', b'Incorrect password.'),
))
def test_login_validate_input(auth, username, password, message):
    response = auth.login(username, password)
    assert message in response.data


def test_logout(client, auth):
    auth.login()

    with client:
        auth.logout()
        assert 'user_id' not in session
