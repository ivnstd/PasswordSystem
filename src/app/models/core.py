from sqlalchemy import Column, Integer, String, LargeBinary
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    login = Column(String, unique=True)
    salt = Column(LargeBinary)
    hash = Column(LargeBinary)
