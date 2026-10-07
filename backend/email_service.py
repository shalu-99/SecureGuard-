import os
import requests
from dotenv import load_dotenv

load_dotenv()


def send_security_alert(to_email: str, subject: str, message: str):

    api_key = os.getenv("RESEND_API_KEY")

    if not api_key:
        print("RESEND API KEY MISSING")
        return False

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "from": "onboarding@resend.dev",
                "to": [to_email],
                "subject": subject,
                "text": message
            },
            timeout=30
        )

        print("RESEND STATUS:", response.status_code)
        print("RESEND RESPONSE:", response.text)

        if response.ok:
            print("EMAIL SENT SUCCESSFULLY")
            return True

        print("EMAIL SENDING FAILED")
        return False

    except Exception as e:
        print("EMAIL ERROR:", repr(e))
        return False