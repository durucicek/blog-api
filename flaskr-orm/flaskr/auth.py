from flaskr.database import db, jwt
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from flask import (
    Blueprint, redirect, render_template, request, url_for, jsonify
)
from flask import request
from flask_jwt_extended import (
    get_jwt, set_access_cookies, jwt_required, create_access_token, jwt_required, get_jwt, current_user, create_refresh_token
)
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.models import User

bp = Blueprint('auth', __name__, url_prefix='/auth')

###########################################
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    print(jwt_data)
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()
###########################################
@jwt.expired_token_loader
def expired_token_callback(jwt_header, error):
    return redirect(url_for('auth.login'))
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return redirect(url_for('auth.login'))

@jwt.unauthorized_loader
def missing_token_callback(error):
    return redirect(url_for('auth.login'))
###########################################

@bp.after_app_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(hours=1))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=current_user, expires_delta=timedelta(minutes=10))
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username:
            return jsonify({"message": "Username is required."}), 400
        elif not password:
            return jsonify({"message": "Password is required."}), 400
        try:
            new_user = User(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": f"User {username} is already registered."}), 400
        else:
            return jsonify({"message": "User created successfully."}), 201

    return render_template('auth/register.html')

@bp.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        stmt = select(User).where(User.username == username)
        user = db.session.execute(stmt).scalar()

        if user is None:
            return jsonify({"message": "Incorrect username."}), 400
        elif not check_password_hash(user.password, password):
            return jsonify({"message": "Incorrect password."}), 400
        
        access_token = create_access_token(identity=user, expires_delta=timedelta(hours=10))
        refresh_token = create_refresh_token(identity=user, expires_delta=timedelta(days=1))

        return  jsonify({
            "message": "Login successful.",
            "tokens":{ 
                "access_token": access_token,
                "refresh_token": refresh_token
            }
            }), 200
   
@bp.route('/logout')
@jwt_required()
def logout():
    return jsonify({"message": "Logout successful."}), 200

# def login_required(view):
#     @functools.wraps(view)
#     def wrapped_view(**kwargs):
#         if not current_user:
#             flash('You must be logged in to view this page.', 'error')
#             return redirect(url_for('auth.login')), 403
#         return view(**kwargs)
#     return wrapped_view


