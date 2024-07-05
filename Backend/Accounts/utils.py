import uuid
from django.conf import settings
from django.core.mail import EmailMessage
from .models import User,OneTimePassword


def generateOTP():
    while True:
        otp = str(uuid.uuid4().int)[:6]
        if not OneTimePassword.objects.filter(code=otp).exists():
            return otp


def send_code_to_user(email):
    Subject = "One time passcode for Email verification"
    otp_code = generateOTP()
    print(otp_code)
    user = User.objects.get(email=email)
    current_site = "Mentors.com"
    email_body = f"Hi thanks for signing up on {current_site},please verify your email with \n the one time passcode: {otp_code}"
    from_email = settings.DEFAULT_FROM_EMAIL

    OneTimePassword.objects.create (user=user,code=otp_code)

    d_email = EmailMessage(subject=Subject,body=email_body,from_email=from_email,to=[email])
    d_email.send(fail_silently=True)

def send_normal_email(data):
    email = EmailMessage(
        subject=data['email_subject'],
        body = data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to = [data['to_email']]
    )
    email.send()