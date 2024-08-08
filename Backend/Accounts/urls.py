from django.urls import path
from .views import RegisterUserView,VerifyUserEmail,LoginUserView,PasswordResetConfirm,PasswordResetRequestView,SetNewPassword,LogoutUserView,TestView

urlpatterns =[
    path('register/',RegisterUserView.as_view(),name='register'),
    path('verify-email/',VerifyUserEmail.as_view(),name='verify'),
    path('login/',LoginUserView.as_view(),name='login'),
    path('password-reset/',PasswordResetRequestView.as_view(),name='password-reset'),
    path('password-reset-confirm/<str:uidb64>/<str:token>/',PasswordResetConfirm.as_view(),name='password-reset-confirm'),
    path('set-new-password/',SetNewPassword.as_view(),name='set-new-password'),
    path('logout/',LogoutUserView.as_view(),name='logout'),
    path('test/',TestView.as_view(),name='test'),
]