import os
import pytest
from flaskr import create_app
from flaskr.database import db

with open(os.path.join(os.path.dirname(__file__), 'data.sql'), 'rb') as f:
    _data_sql = f.read().decode('utf8')

@pytest.fixture
def app():
    app = create_app(
        config_mode='testing',
        )
    with app.app_context():
        db.create_all()
        conn= db.session().connection().connection
        conn.executescript(_data_sql)
    yield app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

class AuthActions(object):
    def __init__(self, client):
        self._client = client

    def register(self, username='test', password='test'):
        return self._client.post(
            '/auth/register',
            data={'username': username, 'password': password}
        )

    def login(self, username='test', password='test'):
        return self._client.post(
            '/auth/login',
            data={'username': username, 'password': password}
        )
    
    def logout(self):
        return self._client.get('/auth/logout')


@pytest.fixture
def auth(client):
    return AuthActions(client)


class BlogActions(object):
    def __init__(self, client):
        self._client = client

    def create(self, title='test', body='test body'):
        return self._client.post(
            '/create',
            data={'title': title, 'body': body}
        )
    
    def update(self, id=1, title='updated', body='updated body'):
        return self._client.post(
            f'/{id}/update',  
            data={'title': title, 'body': body}
        )
    
    def delete(self, id=1):
        return self._client.post(
            f'/{id}/delete'  
        )
    
    def like(self, postid=1, userid=1):
        return self._client.post(
            f'/{postid}/like', 
        )
    
@pytest.fixture
def blog(client):
    return BlogActions(client)