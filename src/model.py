from sqlmodel import SQLModel, Field, Column, TIMESTAMP
from datetime import datetime, UTC

# Пользовательские модели
class UsersEmail(SQLModel):
    email: str

class UsersLogin(UsersEmail):
    password: str

class UsersBase(UsersEmail):
    name: str

class UsersRegister(UsersBase):
    password: str
    telegram_id: int

class Users(UsersBase, table=True):
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    role: str
    date_joined: datetime = Field(
        default_factory=lambda: datetime.now(UTC), 
        sa_column=Column(TIMESTAMP(timezone=True))
    )
    hashed_password: str

class UsersPublic(UsersBase):
    id: int
    date_joined: datetime

class LoginHistory(SQLModel, table=True):
    __tablename__ = "login_history"

    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    login_time: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(TIMESTAMP(timezone=True))
    )
