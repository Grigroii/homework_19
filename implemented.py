from dao.director import DirectorDAO
from dao.genre import GenreDAO
from dao.movie import MovieDAO
from service.auth import AuthService
from service.director import DirectorService
from service.genre import GenreService
from service.movie import MovieService
from service.user import UserService
from setup_db import db
from dao.user import UserDAO

director_dao = DirectorDAO(session=db.session)
genre_dao = GenreDAO(session=db.session)
movie_dao = MovieDAO(session=db.session)
user_dao = UserDAO(session=db.session)


director_service = DirectorService(director_dao=director_dao)
genre_service = GenreService(genre_dao=genre_dao)
movie_service = MovieService(dao=movie_dao)
user_service = UserService(dao=user_dao)
auth_service = AuthService(user_service=user_service)

