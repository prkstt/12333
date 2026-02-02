from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# ---------- ДОКУМЕНТЫ ----------
class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    doc_type = Column(String, nullable=False)
    path = Column(String, nullable=False)
    owner_id = Column(Integer, nullable=False)


# ---------- ПОЛЬЗОВАТЕЛИ ----------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="user")
