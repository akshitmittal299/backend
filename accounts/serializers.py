from rest_framework import serializers
from .models import *
from .utils import send_welcome_email
import uuid

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'phone_no','role', 'password', "is_verified")
        extra_kwargs={"password":{"write_only":True},"password_confirm":{"write_only":True}, "is_verified":{"read_only":True}}

    
    def create(self, validated_data):
        password = validated_data.pop('password')
        user= User.objects.create_user(**validated_data)
        user.set_password(password)
        user.verification_code = uuid.uuid4()
        user.save()
        send_welcome_email(user)
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('user',"profile_picture", 'bio','date_of_birth')


class UserAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAddress
        fields = ('user', 'st_address', 'city', 'state', 'country', 'postal_code')


class UserAccountSerializer(serializers.ModelSerializer):
    address = serializers.SerializerMethodField()
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_no', 'role','password', 'is_active', 'is_verified', 'address', 'profile']
        extra_kwargs ={
            "password":{"write_only":True}, 
        }
    def get_address(self, obj):
        # Check if the user has an address
        if hasattr(obj, 'useraddress'):
            return UserAddressSerializer(obj.useraddress).data
        return None

    def get_profile(self, obj):
        # Check if the user has a profile
        if hasattr(obj, 'userprofile'):
            return UserProfileSerializer(obj.userprofile).data
        return None
    

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()