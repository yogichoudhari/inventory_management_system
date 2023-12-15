import pdb
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache
import random
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def send_email(subject, to_email, template_name, context):
    html_message = render_to_string(template_name, context)
    text_message = strip_tags(html_message)
    
    email = EmailMultiAlternatives(subject, text_message, to=[to_email])
    email.attach_alternative(html_message, 'text/html')
    email.send()


def generate_otp():
    return str(random.randint(100000,999999))

def otp_temp_storage(otp,user):
    cache_key = f"otp_{user.id}"
    cache.set(cache_key,otp,timeout=900)
    cache.set(str(otp),user.id,timeout=900)
    
def send_otp_via_email(user):
    otp = generate_otp()
    otp_temp_storage(otp,user)
    subject = "Account Verification"
    to_email = user.user.email
    context = {'otp':otp,"username":user.user.username,
               "account":user.account.name}
    send_email(subject,to_email,"email_otp_template.html",context)


def get_tokens_for_user(user):

    '''This view is used to create token for user'''
    
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }



