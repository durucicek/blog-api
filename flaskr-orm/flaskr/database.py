from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_migrate import Migrate # type: ignore
from flask_jwt_extended import JWTManager


class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
migrate = Migrate()
jwt = JWTManager()

def init_app(app):
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    