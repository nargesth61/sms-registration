from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager , PermissionsMixin
from django.core.validators import RegexValidator , validate_email

class UserManager(BaseUserManager):
    def create_user(self,phone,password=None):
        if not phone:
             raise ValueError("Enter your phone number.")
        user = self.model(
            phone=phone
            )
        user.set_password(password)
        user.save(using=self._db)
        return user
 
    def create_superuser(self,phone,password=None):
        user=self.create_user(phone,password=password)
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.is_registered = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser,PermissionsMixin):
    phone_regex = RegexValidator(regex =r"^\d{10}",message="The phone number must be 10 digits.")
    phone = models.CharField(validators=[phone_regex], max_length=14, unique=True,blank = False, null = False)
    email = models.EmailField(max_length=50,blank=True,null=True,validators=[validate_email])
    first_name = models.CharField(max_length =20,blank=True,null=True)
    otp = models.CharField(max_length=6)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    password_try = models.IntegerField(max_length=2, default=4)
    otp_try = models.CharField(max_length=2, default=settings.MAX_OTP_TRY)
    otp_try_2 = models.CharField(max_length=2, default=settings.MAX_OTP_TRY)
    otp_max_out = models.DateTimeField(blank=True, null=True)
    user_ip = models.CharField(max_length = 500,blank=True,null=True)
    is_registered = models.BooleanField(default=False, editable=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "phone"
    
    objects = UserManager()

    def __str__(self):
        return self.phone
    
    def save(self, *args, **kwargs):
        # prevent staff members access_token hijacking through registration API
        if self.is_staff or self.is_superuser:
            self.is_active = True
            self.is_registered = True
        super(User, self).save(*args, **kwargs)