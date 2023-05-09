from django.shortcuts import render
import datetime
import random
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status ,permissions
from django.conf import settings
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import User
from .serializers import *
from .sms import send_otp_sms
from django.contrib import auth
from django.shortcuts import redirect
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken ,TokenError
from django.contrib.auth import get_user_model
User = get_user_model()


def ip_address(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class RegisterAPI(APIView):
    permission_classes = (
        permissions.AllowAny,
    )
    serializer_class = RegisterSerializer
    
    def post(self, request):
            serializer = RegisterSerializer(data = request.data)
            if serializer.is_valid(raise_exception=True):                 
               serializer.save()   
               phone = serializer.data['phone']
               user = User.objects.get(phone = phone )
               instance = user
               if instance.is_registered:  
                   return redirect("http://127.0.0.1:8000/api/login/")           
               if phone == instance.phone :
                if int(instance.otp_try) == 0 and timezone.now() < instance.otp_max_out:
                    return Response("Max OTP try reached, try after an hour",status=status.HTTP_400_BAD_REQUEST,)
                
                otp_try = int(instance.otp_try) - 1
                instance.otp_expiry = timezone.now() + timedelta(minutes=10)
                instance.otp_try = otp_try
                if otp_try == 0:
            # Set cool down time
                     otp_max_out = timezone.now() + timedelta(hours=1)
                     instance.otp_max_out = otp_max_out
                elif otp_try == -1:
                     instance.otp_try = settings.MAX_OTP_TRY
                else:
                    instance.otp_max_out = None
                    instance.otp_try = otp_try
                instance.user_ip = ip_address(request)
                instance.save()
                send_otp_sms(phone)
                return Response("Successfully generate new OTP.", status=status.HTTP_200_OK)  
               user_obj = User.objects.get(phone = serializer.data['phone'])
               user_obj.user_ip = ip_address(request)
               user_obj.save()
               send_otp_sms(serializer.data['phone'])
               return Response(serializer.data, status=status.HTTP_201_CREATED)
                   
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
   
class VerifyOtp(APIView):
    permission_classes = (
        permissions.AllowAny,
    )
    serializer_class = VerifySerializer
    def post(self, request, pk=None):
        serializer = VerifySerializer(data = request.data)
        if serializer.is_valid(raise_exception=True):
            otp = serializer.data['otp']
            user = User.objects.get(user_ip = ip_address(request) )
            instance = user
            if (
                not instance.is_active
                and instance.otp == otp
                and instance.otp_expiry
                and timezone.now() < instance.otp_expiry
                ):
                instance.is_active = True
                instance.otp_expiry = None
                instance.max_otp_try = settings.MAX_OTP_TRY
                instance.otp_max_out = None
                instance.save()
                return Response("Successfully verified the user.", status=status.HTTP_200_OK)
            elif (
                not instance.is_active
                and instance.otp != otp
                and instance.otp_expiry
                and timezone.now() < instance.otp_expiry
                ):
                if int(instance.otp_try_2) == 0 and timezone.now() < instance.otp_max_out:
                    return Response("Max OTP try reached, try after an hour",status=status.HTTP_400_BAD_REQUEST,)
                
                otp_try_2 = int(instance.otp_try_2) - 1
                instance.otp_expiry = timezone.now() + timedelta(minutes=2)
                instance.otp_try_2 = otp_try_2
                if otp_try_2 == 0:
                     otp_max_out = timezone.now() + timedelta(hours=1)
                     instance.otp_max_out = otp_max_out
                     instance.save()
                elif otp_try_2 == -1:
                     instance.otp_try_2 = settings.MAX_OTP_TRY
                     instance.save()
                else:
                    instance.otp_max_out = None
                    instance.otp_try_2 = otp_try_2
                instance.save()
                return Response("The entered code is not correct.", status=status.HTTP_400_BAD_REQUEST)   
       
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)      

class RegenerateVerifyOtp(APIView):
    permission_classes = (
             permissions.AllowAny,
            )
    serializer_class = RegenerateVerifySerializer
    def post(self, request, pk=None):
        serializer = RegenerateVerifySerializer(data = request.data)
        user = User.objects.get(user_ip = ip_address(request))
        instance = user
        if serializer.is_valid():
            phone = serializer.data['phone']
            if phone == instance.phone :
                if int(instance.otp_try) == 0 and timezone.now() < instance.otp_max_out:
                    return Response("Max OTP try reached, try after an hour",status=status.HTTP_400_BAD_REQUEST,)
                
                otp_try = int(instance.otp_try) - 1
                instance.otp_expiry = timezone.now() + timedelta(minutes=10)
                instance.otp_try = otp_try
                if otp_try == 0:
            # Set cool down time
                     otp_max_out = timezone.now() + timedelta(hours=1)
                     instance.otp_max_out = otp_max_out
                elif otp_try == -1:
                     instance.otp_try = settings.MAX_OTP_TRY
                else:
                    instance.otp_max_out = None
                    instance.otp_try = otp_try
                instance.save()
                send_otp_sms(phone)
                return Response("Successfully generate new OTP.", status=status.HTTP_200_OK)   

class ProfileView(APIView):
    permission_classes = (
        permissions.AllowAny,
    )
    
    def get_token(self, user):
               refresh = RefreshToken.for_user(user)
               return {
               'refresh': str(refresh),
               'access': str(refresh.access_token)
                   }
    serializer_class = ProfileSerializer  
    def post(self, request, *args, **kwargs):
        serializer = ProfileSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
           user = User.objects.get(user_ip = ip_address(request))
           user.set_password(serializer.validated_data['password'])
           user.is_registered = True
           user.first_name =serializer.data['first_name']
           user.email =serializer.data['email']
           user.save(update_fields=['first_name','email','password', 'is_registered'])
           phone = user.phone
           password = serializer.validated_data['password']
           user =auth.authenticate(phone=phone, password=password)
           user.last_login = timezone.now()
           user.save(update_fields=['last_login'])
           token=self.get_token(user)
           print(token)
           return Response('Your authentication process is complete', status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer
    def get_token(self, user):
               refresh = RefreshToken.for_user(user)
               return {
               'refresh': str(refresh),
               'access': str(refresh.access_token)
                   }
    def post(self,request):
        serializers =LoginSerializer(data=request.data)
        if serializers.is_valid(raise_exception=True):      
           user1 =User.objects.filter(phone = serializers.validated_data['phone']) 
           if not user1:
               raise AuthenticationFailed('Invalid credentials, try again')
           
           user =User.objects.get(phone = serializers.validated_data['phone']) 
           if not user.is_active:
                raise AuthenticationFailed('Account disabled, contact admin')
           
           password = serializers.validated_data['password']
           try_pas=user.password_try
           
           if user.password != password  :
               if user.password_try == 0 and  timezone.now() < user.otp_max_out:
                    return Response("Max password try reached, try after an hour",status=status.HTTP_400_BAD_REQUEST,)
               
               try_pas = user.password_try - 1
               user.password_try = try_pas
               user.save()
               
               if user.password_try == 0 :
                    otp_max_out = timezone.now() + timedelta(hours=1)
                    user.otp_max_out = otp_max_out
                    user.save()
                    raise AuthenticationFailed('Max password try reached, try after an hour')
               elif user.password_try == -1:
                     user.password_try = 3
               user.save()
               return Response("The password is not correct.", status=status.HTTP_400_BAD_REQUEST)   
          
           if user.password == password :
              user.otp_expiry = None
              user.max_otp_try = 3
              user.last_login = timezone.now()
              user.save(update_fields=['last_login'])
              token=self.get_token(user)
              print(token)
              return Response('Your authentication process is complete', status=status.HTTP_200_OK)
        return Response('Your authentication process is not complete',status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    serializer_class = Logoutserializer
    permission_classes = (permissions.AllowAny,)
     
    def post (self,request):
        serializers =self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        serializers.save()

        return Response(status=status.HTTP_204_NO_CONTENT )
