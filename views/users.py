from flask import request
from flask_restx import Resource, Namespace

from dao.model.user import UserSchema
from implemented import user_service

user_ns = Namespace('users')


@user_ns.route('/')
class MoviesView(Resource):
    def get(self):
        all_users = user_service.get_all()
        result = UserSchema(many=True).dump(all_users)
        return result, 200

    def post(self):
        req_json = request.json
        user_service.create(req_json)
        return "", 201


@user_ns.route('/<int:uid>')
class MovieView(Resource):
    def get(self, uid):
        return UserSchema().dump(user_service.get_one(uid)), 200

    def put(self, uid):
        req_json = request.json
        if "id" not in req_json:
            req_json["id"] = uid
        user_service.update(req_json)
        return "", 204


    def delete(self, uid):
        user_service.delete(uid)
        return "", 204
