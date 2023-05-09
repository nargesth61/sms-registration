from  datetime import datetime, timedelta
import random
from django.conf import settings
from django.core import exceptions
from django.db import transaction, IntegrityError
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer 
import django.contrib.auth.password_validation as validators
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken ,TokenError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
User = get_user_model()
from .sms import *

class RegisterSerializer(serializers.ModelSerializer):
    default_error_messages = {

        'cannot_create_user': ('Unable to create account')
    }
    phone=serializers.CharField()  
    class Meta:
        model = User
        fields = ['phone']
    
    def validate_phone(self, phone):
        try:
            user = User.objects.get(phone = phone)
            self.user = user
        except User.DoesNotExist:
            self.user = None
        return phone
    
    def create(self, validated_data):
        
        if self.user:
            return self.user
        try:
            with transaction.atomic():
                user = User.objects.create(phone=validated_data['phone'], otp=generate_otp(), 
                                           otp_expiry=datetime.now() + timedelta(minutes = 2) ,
                                           otp_try=settings.MAX_OTP_TRY,otp_try_2=settings.MAX_OTP_TRY , is_registered=False)
        except IntegrityError:
            self.fail('cannot_create_user')
        return user

class VerifySerializer(serializers.Serializer):
    otp=serializers.CharField()

class RegenerateVerifySerializer(serializers.Serializer):
    phone=serializers.CharField()  


class ProfileSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True, style={'input_type': 'password'}) 
    first_name=serializers.CharField()
    email=serializers.EmailField()     
    class Meta:
        model = User
        fields = ['first_name', 'email','password']
    def validate_password(self, value):
        try:    
            validators.validate_password(password=value, user=self.instance)
        except exceptions.ValidationError as error:
            raise serializers.ValidationError(list(error.messages))
        return value

    
class LoginSerializer(serializers.ModelSerializer):
    phone=serializers.CharField()  
    password = serializers.CharField(style={'input_type': 'password'},write_only=True)
    class Meta:
        model = User
        fields = ['phone','password']
 


class Logoutserializer(serializers.Serializer) :
    refresh = serializers.CharField()
    default_error_message = {
        'bad_token': ('Token is expired or invalid')
     }
  
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')
