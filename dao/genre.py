from dao.model.genre import Genre


class GenreDAO:
    def __init__(self, session):
        self.session = session

    def get_genres(self):
        return self.session.query(Genre).all()

    def get_genre_by_id(self, gid):
        return self.session.query(Genre).get(gid)

    def create(self, data):
        new_genre = Genre(**data)

        self.session.add(new_genre)
        self.session.commit()

        return new_genre

    def update(self, genre):
        self.session.add(genre)
        self.session.commit()

        return genre

    def delete(self, gid):
        genre = self.get_genre_by_id(gid)

        self.session.delete(genre)
        self.session.commit()

