import base64
import calendar
import datetime
import hashlib

from flask import abort
import jwt

from constants import JWT_SECRET, JWT_ALGO, PWD_HASH_SALT, PWD_HASH_ITERATIONS
from service.user import UserService


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def generate_tokens(self, username, password, is_refresh=False):
        user = self.user_service.get_by_username(username)

        if user is None:
            raise abort(404)

        if not is_refresh:
            if not self.user_service.compare_passwords(user.password, password):
                abort(400)

        data = {
            "username": user.username,
            "role": user.role
        }

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    def approve_refresh_token(self, refresh_token):
        data = jwt.encode(jwt=refresh_token, key=JWT_SECRET, algorithm=[JWT_ALGO])
        username = data.get("username")

        return self.generate_tokens(username, None, is_refresh=True)


#def generate_password_digest(password):
    #return hashlib.pbkdf2_hmac(
        hash_name='sha256',
        #password=password.encode('UTF-8'),
        #salt=PWD_HASH_SALT,
        #iterations=PWD_HASH_ITERATIONS
    #)

#def generate_password_hash(password):
    #return base64.b64encode(generate_password_digest(password)).decode('UTF-8')


#def compare_passwords_hash(password_hash, other_password):
    #return password_hash==other_password

#def generate_tokens(username, password, is_refresh=False):
    #if username is None:
        #raise abort(404)
