import httpx
import logging
from fastapi import APIRouter, Response, Depends
from fastapi.responses import RedirectResponse
from sqlmodel import select
from src.auth import create_tokens
from src.config import YANDEX_CLIENT_ID, YANDEX_CLIENT_SECRET, YANDEX_REDIRECT_URL
from src.db import Session, get_session
from src.model import Users, LoginHistory
from .telega import send_telegram_message

router = APIRouter()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_yandex_auth_url():
    return (
        "https://oauth.yandex.ru/authorize?"
        "response_type=code&"
        f"client_id={YANDEX_CLIENT_ID}&"
        f"redirect_uri={YANDEX_REDIRECT_URL}"
    )

@router.get("/yandex/")
async def auth_yandex():
    return RedirectResponse(get_yandex_auth_url())

@router.get("/yandex/callback")
async def auth_yandex_callback(code: str, telegram_id: int, resp: Response, session: Session = Depends(get_session)):
    token_url = "https://oauth.yandex.ru/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": YANDEX_CLIENT_ID,
        "client_secret": YANDEX_CLIENT_SECRET
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
    response_data = response.json()
    logger.info(response_data)

    access_token = response_data.get("access_token")
    if not access_token:
        return {"error": "Не удалось получить токен"}

    user_info_url = "https://login.yandex.ru/info"
    async with httpx.AsyncClient() as client:
        response = await client.get(user_info_url, params={"format": "json", "oauth_token": access_token})
    user_info = response.json()
    
    logger.info(user_info)

    email = user_info.get("default_email")
    if not email:
        return {"error": "Не удалось получить email"}

    query = select(Users).where(Users.email == email)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        new_user = Users(email=email, role="user")
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)

        new_history = LoginHistory(user_id=new_user.id)
        session.add(new_history)
        await session.commit()
        await session.refresh(new_history)

        role = new_user.role
    else:
        new_history = LoginHistory(user_id=user.id)
        session.add(new_history)
        await session.commit()
        await session.refresh(new_history)

        role = user.role

    send_telegram_message.delay(telegram_id, "Добро пожаловать в приложение!\nУРА УРА УРАААААА, РАБОТАЕТ\nОНО РАБОТАЕТ!!!!")

    access_token, refresh_token = create_tokens(email, role)

    resp.set_cookie(
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
