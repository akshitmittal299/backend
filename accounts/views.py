from rest_framework import viewsets, status, generics
from rest_framework.views import APIView
from rest_framework.permissions import *
from .serializers import *
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from .models import *
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from .utils import send_forgot_password_email, verify_google_token
from rest_framework.exceptions import ValidationError
from rest_framework import permissions

class RegisterUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({
            "success":True,
            "message":"user registered successfully",
            'user': UserSerializer(user).data,
            'stripe_customer_id': stripe_customer.id,
        })


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        response_data = {
            "status": "success",
            "message": "Login successful",  
            "data": response.data  
        }
        
        return Response(response_data, status=status.HTTP_200_OK)    


class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        token = request.GET.get("token")
        try:
            user = User.objects.get(verification_code = token)
            if user.is_expired():
                return Response({"success":False, "response_data":"token is expired"}, status=400)
            elif user:
                user.is_verified = True
                user.is_active = True
                user.verification_code = ""
                user.token_created = None
                user.save()
                return Response({"success":True, "response_data":"email successfully verified"}, status = status.HTTP_200_OK)
        except:
            return Response({"success":False, "response_data":"Invalid Verification token"}, status = status.HTTP_404_NOT_FOUND)
        
class UserProfileViewset(viewsets.ModelViewSet):
    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.all()
    permission_classes = [permissions.AllowAny]

class UserAddressViewset(viewsets.ModelViewSet):
    serializer_class = UserAddressSerializer
    queryset = UserAddress.objects.all()
    permission_classes =[permissions.AllowAny]

class GetUserProfile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user 
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)
    

class ForgotPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"success": False, "message": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        token = default_token_generator.make_token(user)
        reset_link = f"{settings.FRONTEND_URL}reset-password/{token}/" 
        
        try:
            send_forgot_password_email(user, token)
        except Exception as e:
            return Response({"success": False, "message": f"Error sending email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"success": True, "message": "Password reset email has been sent."}, status=status.HTTP_200_OK)


class ResetPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    def get_user_from_token(self, token):
        for user in User.objects.all():
            if default_token_generator.check_token(user, token):
                return user
        return None

    def post(self, request, token):
        new_password = request.data.get("new_password")

        if not new_password:
            return Response({"detail": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)
        user = self.get_user_from_token(token)

        if not user:
            raise ValidationError("The password reset token is invalid or has expired.")

        user.set_password(new_password)
        user.save()

        return Response({"success": True, "message": "Password has been successfully reset."}, status=status.HTTP_200_OK)

class ChangePasswordView(APIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            if not user.check_password(old_password):
                raise serializers.ValidationError("Old password is incorrect.")
            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            user.save()
            return Response({"success": True, "message": "Password changed successfully"}, status=status.HTTP_200_OK)
        return Response({"success":False, "error":serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken

class CustomLoginView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        login_type = request.data.get("type")  # 'email' or 'google'
        if login_type == "google":
            id_token_str = request.data.get("id_token")
            user_info = verify_google_token(id_token_str)
            if not user_info:
                return Response({"error": "Invalid Google token"}, status=status.HTTP_400_BAD_REQUEST)

            # Check if user already exists
            email = user_info.get("email")
            user = User.objects.filter(email=email).first()
            if not user:
                # Create a new user if they don't exist
                user = User.objects.create(
                    email=email,
                    first_name=user_info.get("given_name", ""),
                    last_name=user_info.get("family_name", ""),
                    is_active=True,
                )
                user.set_unusable_password()  # User won't log in with a password

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            })

        elif login_type == "email":
            # Handle normal email/password login (your existing logic)
            ...
        else:
            return Response({"error": "Invalid login type"}, status=status.HTTP_400_BAD_REQUEST)


import requests
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model

User = get_user_model()

class GoogleLoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        access_token = request.data.get('access_token')

        if not access_token:
            return Response({'error': 'Access token is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Get current site (if using django.contrib.sites)
        try:
            current_site = Site.objects.get_current()
            social_app = SocialApp.objects.get(provider='google', sites=current_site)
        except (Site.DoesNotExist, SocialApp.DoesNotExist):
            # fallback if no sites framework or no matching SocialApp
            social_app = SocialApp.objects.filter(provider='google').first()
            if not social_app:
                return Response({'error': 'Google social app is not configured.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        google_client_id = social_app.client_id

        # Verify token with Google
        google_token_info_url = 'https://oauth2.googleapis.com/tokeninfo'
        params = {'id_token': access_token}
        token_info_response = requests.get(google_token_info_url, params=params)

        if token_info_response.status_code != 200:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        token_info = token_info_response.json()

        # Validate client ID
        if token_info.get('aud') != google_client_id:
            return Response({'error': 'Token client ID does not match.'}, status=status.HTTP_400_BAD_REQUEST)

        # Extract user info
        email = token_info.get('email')
        first_name = token_info.get('given_name', '')
        last_name = token_info.get('family_name', '')
        email_verified = token_info.get('email_verified', 'false') == 'true'

        if not email_verified:
            return Response({'error': 'Email not verified by Google.'}, status=status.HTTP_400_BAD_REQUEST)

        # Get or create user
        user, created = User.objects.get_or_create(email=email, defaults={
            'first_name': first_name,
            'last_name': last_name,
            'is_verified': True,
            'is_active': True,
        })

        if not created and not user.is_verified:
            user.is_verified = True
            user.save()

        # Create JWT tokens
        refresh = RefreshToken.for_user(user)

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        })

