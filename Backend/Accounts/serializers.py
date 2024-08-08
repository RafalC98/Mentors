from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed,ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_bytes,force_str
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken,TokenError

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=9,write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=9,write_only=True)

    class Meta:
        model=User
        fields=['email','password','password2']

    def validate(self,attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("passwords do not match")

        return attrs

    def create(self,validated_data):
        user = User.objects.create_user(
            email = validated_data['email'],
            password=validated_data.get('password')
        )

        return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(max_length=68,write_only=True)
    access_token = serializers.CharField(max_length=255,read_only=True)
    refresh_token = serializers.CharField(max_length=255,read_only=True)
    message = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'password','access_token','refresh_token', 'message']

    def get_message(self, obj):
        return 'You are successfully logged in'

    def validate(self,attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request,email=email,password=password)
        if not user:
            raise AuthenticationFailed("invalide credentials try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        user_tokens = user.tokens()
        return {
            'email':user.email,
            'access_token':str(user_tokens.get('access')),
            'refresh_token':str(user_tokens.get('refresh')),
        }

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=6)

    class Meta:
        fields = ['email']

    def validate(self,attrs):
        email = attrs.get('email')
        if not User.objects.filter(email=email).exists():
            raise ValidationError({"detail": "User with this email does not exist."},401)

        else:
            user = User.objects.get(email = email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            abslink = f"http://127.0.0.1:5501/password-reset-confirm.html?uidb64={uidb64}&token={token}"
            email_body = f"Hi use the link below to reset your password \n {abslink}"
            data = {
                'email_body':email_body,
                'email_subject' : 'Reset your Password',
                'to_email':user.email
            }
            send_normal_email(data)

        return super().validate(attrs)

class SetNewPasswordSerializzer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=6,write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=6,write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    class Meta:
        fields = ["password", "confirm_password", "uidb64", "token"]

    def validate(self,attrs):
        token = attrs.get('token')
        uidb64 = attrs.get('uidb64')
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise AuthenticationFailed('The reset link is invalid or has expired123')


        if not PasswordResetTokenGenerator().check_token(user, token):
            raise AuthenticationFailed('The reset link is invalid or has expired')

        if password != confirm_password:
            raise AuthenticationFailed('Passwords do not match')

        user.set_password(password)
        user.save()

        return attrs

class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    default_error_messages = {
        'bad_token':('Token is invalid or has expired')
    }
    def validate(self,attrs):
        self.token = attrs.get('refresh_token')
        return attrs

    def save(self,**kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')