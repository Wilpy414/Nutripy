from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from app import User  # Importá tu modelo User desde tu app

# Conexiones
sqlite_engine = create_engine('sqlite:///instance/nutripy.db')
postgres_engine = create_engine('postgresql://nutripy_admin:1234@localhost/nutripy')

# Sesiones
SQLiteSession = sessionmaker(bind=sqlite_engine)
PostgresSession = sessionmaker(bind=postgres_engine)

sqlite_session = SQLiteSession()
postgres_session = PostgresSession()

# Leer usuarios desde SQLite
usuarios = sqlite_session.query(User).all()

# Insertar en PostgreSQL
for u in usuarios:
    nuevo_usuario = User(username=u.username, password=u.password)
    postgres_session.add(nuevo_usuario)

postgres_session.commit()
print("✅ Migración completada con éxito")