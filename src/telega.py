from celery import Celery
import telebot
from src.config import CELERY_BROKER_URL, TELEGRAM_BOT_TOKEN, CELERY_RESULT_BACKEND

app = Celery(
    "tasks",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND
)

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

@app.task
def send_telegram_message(chat_id: int, message: str):
    try:
        bot.send_message(chat_id=chat_id, text=message)
    except Exception as e:
        app.logger.error(f"Ошибка при отправке сообщения в Telegram: {e}")
