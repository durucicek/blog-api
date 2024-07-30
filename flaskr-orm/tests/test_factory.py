from flaskr import create_app


def test_config():
    assert not create_app().testing
    assert create_app(config_mode="testing").testing


