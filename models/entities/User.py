from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import UserMixin

class User(UserMixin):
    # Administradores predefinidos
    ADMINS_FIJOS = {'Elton': '188'}

    def __init__(self, id, username, password, fullname="", role="cliente"):
        self.id = id
        self.username = username
        self.password = password
        self.fullname = fullname
        self.role = role  # <-- Usamos role, no categoria

    @classmethod
    def check_password(cls, hashed_password, password):
        return check_password_hash(hashed_password, password)

    @classmethod
    def es_admin_permitido(cls, username, password):
        return username in cls.ADMINS_FIJOS and cls.ADMINS_FIJOS[username] == password

    @classmethod
    def crear_admin_fijo(cls, db_connection):
        username = 'Elton'
        if username not in cls.ADMINS_FIJOS:
            return

        cursor = None
        try:
            cursor = db_connection.cursor()
            # Verificación usando 'role' en lugar de 'categoria'
            cursor.execute(
                "SELECT id FROM users WHERE username = %s AND role = 'admin'", 
                (username,)
            )
            
            if not cursor.fetchone():
                hashed_pwd = generate_password_hash(cls.ADMINS_FIJOS[username])
                cursor.execute(
                    """INSERT INTO users 
                    (username, password, fullname, role) 
                    VALUES (%s, %s, %s, %s)""",
                    (username, hashed_pwd, 'Administrador Principal', 'admin')
                )
                db_connection.commit()
                print(f"✅ Admin creado: {username}")
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            db_connection.rollback()
        finally:
            if cursor:
                cursor.close()