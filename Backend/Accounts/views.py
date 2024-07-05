from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from .serializers import UserRegisterSerializer,LoginSerializer,SetNewPasswordSerializzer,LogoutUserSerializer,PasswordResetRequestSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .utils import send_code_to_user
from .models import OneTimePassword,User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# Create your views here.


class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self,request):
        user_data = request.data
        serializer = self.serializer_class(data = user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            send_code_to_user(user['email'])

            return Response({
                'data':user,
                'message': 'thanks for signing up a passcode has be sent to verify your email'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class VerifyUserEmail(GenericAPIView):
    def post(self,request):
        otecode = request.get('otp')
        try:
            user_codee_obj = OneTimePassword.objects.get(code=otpcode)
            user = user_codee_obj.user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({
                    'message':'account email verified successfully'
                },status=status.HTTP_200_OK)
            return Response({
                'message':'code is invalid,user already verified'
            },status=status.HTTP_204_NO_CONTENT)

        except OneTimePassword.DoesNotExist:
            return Response({
                'message':'passcode not provided'
            },status=status.HTTP_404_NOT_FOUND)

class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer
    def post(self,request):
        serializer = self.serializer_class(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response (serializer.data,status=status.HTTP_200_OK)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    def post(self,request):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'message':"a link has been sent to your email to reset your password"},status=status.HTTP_200_OK)

class PasswordResetConfirm(GenericAPIView):
    def get(self,request,uidb64,token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'message':'token is invalid or has expired'},status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success':True,'message':'credentials is valid','uidb64':uidb64,'token':token},status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({'message':'token is invalid or has expired'},status=status.HTTP_401_UNAUTHORIZED)

class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializzer
    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message':'password reset successfull'},status=status.HTTP_200_OK)

class LogoutUserView(GenericAPIView):
    serializer_class = LogoutUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TestView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        password2 = request.data.get('password2')

        # Sprawdź poprawność logowania (przykład, dodaj własną logikę)
        if email == "user@example.com" and password == "password123":
            return Response({'message': 'Login successful'},
                            status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid credentials'},
                            status=status.HTTP_401_UNAUTHORIZED)