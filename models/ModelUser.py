from .entities.User import User
from werkzeug.security import check_password_hash

class ModelUser():

    @classmethod
    def login(cls, db, user):
        try:
            cursor = db.connection.cursor()
            sql = """SELECT id, username, password, fullname FROM users 
                    WHERE username = %s"""
            cursor.execute(sql, (user.username,))
            row = cursor.fetchone()

            if row is not None:
                # Comprobar la contraseña con `check_password_hash()`
                if check_password_hash(row[2], user.password):
                    return User(row[0], row[1], row[2], row[3])
                else:
                    return None  # La contraseña no coincide
            else:
                return None  # Usuario no encontrado
                
        except Exception as ex:
            raise Exception(ex)

    @classmethod
    def get_by_id(cls, db, id):
        try:
            cursor = db.connection.cursor()
            sql = "SELECT id, username, fullname FROM users WHERE id = %s"
            cursor.execute(sql, (id,))
            row = cursor.fetchone()

            if row is not None:
                return User(row[0], row[1], None, row[2])
            else:
                return None
                
        except Exception as ex:
            raise Exception(ex)