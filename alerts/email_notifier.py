import os
import smtplib
import ssl
from email.message import EmailMessage

from alerts.outputs import format_alert
from models import Alert

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465


def email_output(alert: Alert) -> None:
    user = os.environ.get("EMAIL_USER")
    password = os.environ.get("EMAIL_APP_PASSWORD")
    to = os.environ.get("EMAIL_TO")

    if not user or not password or not to:
        print("[email] Faltan variables EMAIL_*; alerta no enviada.")
        return

    message = EmailMessage()
    message["Subject"] = (
        f"[SIEM] {alert.severity.upper()} - {alert.rule} desde {alert.src_ip}"
    )
    message["From"] = user
    message["To"] = to
    message.set_content(format_alert(alert))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
            server.login(user, password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as error:
        print(f"[email] No se pudo enviar la alerta: {type(error).__name__}")