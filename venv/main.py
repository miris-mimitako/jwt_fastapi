from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, HTTPException, status,Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import json
from sqlalchemy import create_engine
import os
from pathlib import Path
import pandas as pd
from pydantic import BaseModel


# to get a string like this run:
# openssl rand -hex 32
# SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63eragae4taerhargarfaffvavetabtarab88e8d3e7"
# SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

""".secrets.json
At first create .secrets.json file
This file contains following structs.
{
    "jwt_env":{
        "ALGORITHM":"HS256",
        "ACCESS_TOKEN_EXPIRE_MINUTES":30
    },
    "jwt_secret":{
        "SECRET_KEY":"random strings"
    }
}
"""

with open(".secrets.json", "r") as f:
    json_secrets = json.load(f)

SECRET_KEY = json_secrets["jwt_secret"]["SECRET_KEY"]
ALGORITHM = json_secrets["jwt_env"]["ALGORITHM"]
ACCESS_TOKEN_EXPIRE_MINUTES = json_secrets["jwt_env"]["ACCESS_TOKEN_EXPIRE_MINUTES"]

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}
# "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",

# DB connect:
db_path = os.path.join(Path(os.path.dirname(os.path.abspath(__file__))),"testdb.sqlite3")
engine = create_engine(f"sqlite:///{db_path}")
global con
con = engine.connect()

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()

# これでパスワードの整合性を確認している。 login時に使用
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ユーザーを登録作成するときに必要
def get_password_hash(password):
    return pwd_context.hash(password)

# ユーザー名が正しいかどうかの確認
def get_user(username: str):
    df = pd.read_sql(f"SELECT * FROM users WHERE user_name = '{username}'")    
    if username in df.user_name.values:
        return {"user_hashed_pw":df.pw[0]} # hashed pwを返す

# ユーザー情報の確認
def authenticate_user(fake_db, username: str, password: str): # fake_dbは後で消す
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    print(get_password_hash(form_data.password))
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]


@app.post("/create_user/")
async def create_user(body=Body(...)):
    # body = body.decode()
    # body = json.loads(body)
    print()