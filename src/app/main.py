import uvicorn
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select, insert, Column, Integer, String, LargeBinary
from sqlalchemy.orm import Session, declarative_base

import bcrypt
from jose import jwt, JWTError
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

from models.database import get_db, engine

"""__________________________________________________________________________________________________________________"""
app = FastAPI()
Base = declarative_base()
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    login = Column(String, unique=True)
    salt = Column(LargeBinary)
    hash = Column(LargeBinary)

def generate_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


"""__________________________________________________________________________________________________________________"""


@app.post("/registrate")
def registrate(usr: str, pwd: str, db: Session = Depends(get_db)):
    if not db.execute(select(User).where(User.login == usr)).fetchone():
        salt_val = bcrypt.gensalt()
        db.execute(insert(User).values(
            login=usr,
            salt=salt_val,
            hash=bcrypt.hashpw(bytes(pwd.encode('utf8')), salt_val)
        ))
        db.commit()
        return JSONResponse(content='Registration completed successfully :)', status_code=201)
    else:
        return JSONResponse(content='Registration is not possible :(', status_code=400)


@app.post("/auth")
def auth(usr: str, pwd: str, db: Session = Depends(get_db)):
    try:
        user = db.execute(select(User).where(User.login == usr)).fetchone()[0]

        if bcrypt.hashpw(bytes(pwd.encode('utf-8')), user.salt) == user.hash:

            access_token = generate_token(data={'id': user.id, 'typ': 'access_token'})
            refresh_token = generate_token(data={'id': user.id, 'typ': 'refresh_token'})

            response = JSONResponse(content='Correct password :)', status_code=200)
            response.set_cookie(key='Access-Token', value=access_token, httponly=True)
            response.set_cookie(key='Refresh-Token', value=refresh_token, httponly=True)
            return response
        else:
            return JSONResponse(content='Wrong password :(', status_code=403)
    except:
        return JSONResponse(content='Wrong login :(', status_code=400)


@app.post("/refresh")
def refresh(request: Request):
    token = request.cookies.get('Refresh-Token')
    try:
        claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        access_token = generate_token(data={'id': claims['id'], 'typ': 'access_token'})
        refresh_token = generate_token(data={'id': claims['id'], 'typ': 'refresh_token'})

        response = JSONResponse(content='The token was updated successfully :)', status_code=200)
        response.set_cookie(key='Access-Token', value=access_token, httponly=True)
        response.set_cookie(key='Refresh-Token', value=refresh_token, httponly=True)
        return response
    except JWTError:
        return JSONResponse(content='The token is invalid or the token has expired :(', status_code=403)


@app.get("/secret")
def root(request: Request):
    token = request.cookies.get('Access-Token')
    try:
        jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return JSONResponse(content='Access-Token is alright, you can see this secret information :)', status_code=200)
    except JWTError:
        return JSONResponse(content='The token is invalid or the token has expired :(', status_code=403)



if __name__ == '__main__':
    Base.metadata.create_all(bind=engine)
    uvicorn.run("main:app", reload=True)
