from dao.director import DirectorDAO


class DirectorService:
    def __init__(self, director_dao: DirectorDAO):
        self.director_dao = director_dao

    def get_all(self):
        return self.director_dao.get_all()

    def get_one(self, did):
        return self.director_dao.get_one(did)

    def create(self, data):
        return self.director_dao.create(data)

    def update(self, data):
        did = data.get("id")
        director = self.get_one(did)

        director.name = data.get("name")
        self.director_dao.update(director)

    def update_partial(self, data):
        did = data.get("id")
        director = self.get_one(did)

        if "name" in data:
            director.name = data.get("name")

        self.director_dao.update(director)

    def delete(self, did):
        self.director_dao.delete(did)