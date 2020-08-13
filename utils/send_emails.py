from flask import current_app
from flask_mail import Mail, Message



mail = Mail()

def send_email(to, subject, body, template):
    msg = Message(
        subject,
        recipients=[to],
        body=body,
        html=template,
        sender=current_app.config.get["MAIL_DEFAULT_SENDER"],
    )
    mail.send(msg)
