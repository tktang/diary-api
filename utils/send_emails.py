
from flask_mail import Mail, Message




mail = Mail()


def send_email(to_email, subject, body):
  msg = Message(subject, recipients=[to_email])
  msg.html = body
  mail.send(msg)
    

# def send_email(from_email,to_email,subject, content):
#   try:
#     sg = sendgrid.SenderGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
#     mail = Mail(from_email, subject, to_email, content)
#     response = sg.client.mail.send.post(request_body=mail.get())
#     return response.status_code
#   except Exception as e:
#     return (str(e))

