import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

sender = os.getenv("EMAIL_ADDRESS")
password = os.getenv("EMAIL_PASSWORD")

msg = EmailMessage()
msg["From"] = sender
msg["To"] = sender
msg["Subject"] = "SecureGuard Email Test"
msg.set_content("SecureGuard email notification test.")

print("Connecting...")

with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
    smtp.login(sender, password)
    print("Login successful")
    smtp.send_message(msg)
    print("Email sent successfully")

print("DONE")