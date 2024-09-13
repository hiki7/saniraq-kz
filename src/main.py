from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Session, select, Field
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from .config.db_connect import engine

from .models import (
        User, UserCreate, UserBase,
        Token, TokenData, Shanyrak,
        ShanyrakBase, Comment, CommentBase
    )

app = FastAPI()

SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(username: str):
    with Session(engine) as session:
        return session.exec(select(User).where(User.username == username)).first()

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user or not verify_password(password, user.password):
        return False
    return user

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
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
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
    return {"access_token": access_token, "token_type": "bearer"}


# Маршруты
@app.post("/auth/users/", response_model=UserBase)
def create_user(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, phone=user.phone, name=user.name, city=user.city, password=hashed_password)
    with Session(engine) as session:
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
    return db_user

@app.post("/auth/users/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.patch("/auth/users/me", response_model=UserBase)
async def update_user(user_data: UserBase, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        db_user = session.get(User, current_user.id)
        if db_user:
            db_user.phone = user_data.phone
            db_user.name = user_data.name
            db_user.city = user_data.city
            session.commit()
            session.refresh(db_user)
        return db_user

@app.get("/auth/users/me", response_model=UserBase)
async def get_user_info(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/shanyraks/", response_model=Shanyrak)
async def create_shanyrak(shanyrak: ShanyrakBase, current_user: User = Depends(get_current_user)):
    db_shanyrak = Shanyrak(**shanyrak.dict(), user_id=current_user.id)
    with Session(engine) as session:
        session.add(db_shanyrak)
        session.commit()
        session.refresh(db_shanyrak)
    return db_shanyrak

@app.get("/shanyraks/{id}", response_model=Shanyrak)
async def get_shanyrak(id: int):
    with Session(engine) as session:
        shanyrak = session.get(Shanyrak, id)
        if shanyrak:
            return shanyrak
        raise HTTPException(status_code=404, detail="Shanyrak not found")

@app.patch("/shanyraks/{id}", response_model=Shanyrak)
async def update_shanyrak(id: int, shanyrak: ShanyrakBase, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        db_shanyrak = session.get(Shanyrak, id)
        if db_shanyrak and db_shanyrak.user_id == current_user.id:
            for key, value in shanyrak.dict().items():
                setattr(db_shanyrak, key, value)
            session.commit()
            session.refresh(db_shanyrak)
        return db_shanyrak

@app.delete("/shanyraks/{id}", response_model=dict)
async def delete_shanyrak(id: int, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        shanyrak = session.get(Shanyrak, id)
        if shanyrak and shanyrak.user_id == current_user.id:
            session.delete(shanyrak)
            session.commit()
        return {"message": "Shanyrak deleted"}

@app.post("/shanyraks/{id}/comments", response_model=Comment)
async def add_comment(id: int, comment: CommentBase, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        db_shanyrak = session.get(Shanyrak, id)
        if db_shanyrak:
            db_comment = Comment(**comment.dict(), user_id=current_user.id, shanyrak_id=id)
            session.add(db_comment)
            db_shanyrak.total_comments += 1
            session.commit()
            session.refresh(db_shanyrak)
            session.refresh(db_comment)
        return db_comment

@app.get("/shanyraks/{id}/comments", response_model=List[Comment])
async def get_comments(id: int):
    with Session(engine) as session:
        comments = session.exec(select(Comment).where(Comment.shanyrak_id == id)).all()
    return comments

@app.patch("/shanyraks/{id}/comments/{comment_id}", response_model=Comment)
async def update_comment(id: int, comment_id: int, new_comment: CommentBase, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        db_comment = session.get(Comment, comment_id)
        if db_comment and db_comment.user_id == current_user.id:
            db_comment.content = new_comment.content
            session.commit()
            session.refresh(db_comment)
        return db_comment

@app.delete("/shanyraks/{id}/comments/{comment_id}", response_model=dict)
async def delete_comment(id: int, comment_id: int, current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        db_comment = session.get(Comment, comment_id)
        if db_comment and db_comment.user_id == current_user.id:
            db_shanyrak = session.get(Shanyrak, id)
            if db_shanyrak:
                session.delete(db_comment)
                db_shanyrak.total_comments -= 1
                session.commit()
                session.refresh(db_shanyrak)
        return {"message": "Comment deleted"}
