import bcrypt
from fastapi import FastAPI, Depends, HTTPException, Cookie, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from sqlmodel import SQLModel, select
from . import model
from .db import Session, engine, get_session
from .model import UsersRegister, UsersPublic, Users
from .telega import send_telegram_message
from src.config import SECRET_KEY, ALGORITHM
from .auth import create_tokens
from .yandex import router as oauth_router

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(oauth_router, prefix="/auth", tags=["oauth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

@app.on_event("shutdown")
async def shutdown_event():
    await engine.dispose()

@app.post('/register/', response_model=UsersPublic)
async def register(user: UsersRegister, session: Session = Depends(get_session)):
    # Проверка существования пользователя
    query = select(Users).where(Users.email == user.email)
    result = await session.execute(query)
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Хэширование пароля
    hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())

    telegram_id = user.telegram_id
    user_data = user.dict(exclude={"password", "telegram_id"})
    user_data["hashed_password"] = hashed_password
    user_data["role"] = 'user'
    db_user = Users(**user_data)

    # Валидация данных
    try:
        db_user = Users.model_validate(db_user)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid user data")

    # Отправка приветственного сообщения в Telegram
    send_telegram_message.delay(telegram_id, "Добро пожаловать в приложение!")

    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)
    return db_user


@app.post('/login/')
async def login(
    user_input: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
    response: Response = None  # Для установки cookies
):
    # Поиск пользователя в базе данных
    query = select(Users).where(Users.email == user_input.username)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not bcrypt.checkpw(user_input.password.encode(), user.hashed_password.encode()):
        raise HTTPException(status_code=400, detail='Wrong password')

    # Запись времени входа
    new_login_history = models.LoginHistory(user_id=user.id)
    session.add(new_login_history)
    await session.commit()
    await session.refresh(new_login_history)

    access_token, refresh_token = create_tokens(user.email, user.role)

    # Установка Refresh Token в httpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax"
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@app.post('/refresh/')
async def refresh(
    refresh_token: str = Cookie(None),  # Получаем Refresh Token из cookies
    session: Session = Depends(get_session)
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail='Refresh token missing')

    try:
        # Декодируем Refresh Token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload['email']
        role = payload['role']

        # Генерация нового Access Token
        access_token, _ = create_tokens(email, role)

        # Возврат нового Access Token
        return {
            "access_token": access_token,
            "token_type": "bearer"
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Refresh token expired')
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail='Invalid refresh token')

@app.post('/change_user/')
async def change_role(user_id: int, new_role: str, token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        role = payload.get('role')
        if role != 'admin':
            raise HTTPException(status_code=401, detail='Invalid token or not enough rights')
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail='Invalid token')

    query = select(Users).where(Users.id == user_id)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = new_role  # Предположим, что у модели Users есть поле role
    session.add(user)
    await session.commit()
    await session.refresh(user)

    return {"message": "User role updated successfully", "user": user}
