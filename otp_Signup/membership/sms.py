import random
from .models import User
from sms import send_sms

def generate_otp():
    otp = random.randint(100000, 999999)
    return str(otp)

def send_otp_sms(phone):
    otp = generate_otp()
    send_sms(otp,
               'آچاره',
               [phone]
               )
    user_obj = User.objects.get(phone = phone)
    user_obj.otp = otp
    user_obj.save()
