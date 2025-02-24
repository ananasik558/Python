from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


def create_tokens(email: str, role: str):
    expire_time = datetime.utcnow() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {"role": role, "email": email, "exp": expire_time}

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    refresh_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return access_token, refresh_token
