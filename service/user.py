import base64
import hashlib
import hmac

from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS
from dao.user import UserDAO


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_all(self):
        return self.dao.get_all()

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def create(self, data):
        data["password"] = self.generate_password(data["password"])
        return self.dao.create(data)

    def update(self, data):
        data["password"] = self.generate_password(data["password"])
        self.dao.update(data)


    def delete(self, uid):
        self.dao.delete(uid)

    def generate_password(self, password):
        hash_digest = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )

        return base64.b64encode(hash_digest)

    def compare_passwords(self, hash_password, other_password):

        decoded_digest = base64.b64decode(hash_password)

        hash_digest = hashlib.pbkdf2_hmac(
            'sha256',
            other_password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )

        return hmac.compare_digest(decoded_digest, hash_digest)

