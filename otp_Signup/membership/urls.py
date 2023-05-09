from django.contrib import admin
from django.urls import path ,include
from membership.views import *
from . import views
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('register/', views.RegisterAPI.as_view(), name='auth-register'),
    path('verify/', views.VerifyOtp.as_view(), name='verify-register'),
    path('reverify/', views.RegenerateVerifyOtp.as_view(), name='reverify-register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    
    path('token/refresh/', TokenRefreshView.as_view(), name='auth-token-refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='auth-token-verify'),

]