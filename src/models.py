from sqlmodel import SQLModel, Field
from pydantic import BaseModel
from typing import Optional


class UserBase(SQLModel):
    username: str
    phone: str
    name: str
    city: str


class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    password: str


class UserCreate(UserBase):
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class ShanyrakBase(SQLModel):
    type: str
    price: int
    address: str
    area: float
    rooms_count: int
    description: str


class Shanyrak(ShanyrakBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int


class CommentBase(SQLModel):
    content: str


class Comment(CommentBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int
    shanyrak_id: int
