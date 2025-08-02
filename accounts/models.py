from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .manager import UserManager
from django.utils import timezone

class TimeStamp(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class User(AbstractBaseUser, PermissionsMixin, TimeStamp):
    ROLE_CHOICES =[
        ('user', "user"),
        ('admin', 'admin')
    ]
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    phone_no = models.IntegerField(null=True, blank=True)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default="user")
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    verification_code = models.CharField(max_length=100, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    token_created = models.DateTimeField(default=timezone.now, null=True, blank=True)    
    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email} {self.first_name} {self.last_name}"
    
    def is_expired(self):
        expiration_time=self.token_created + timezone.timedelta(hours=1)
        return timezone.now() > expiration_time
    

class UserAddress(TimeStamp):
    user = models.OneToOneField(User, on_delete = models.CASCADE)
    st_address = models.CharField(max_length = 255)
    city = models.CharField(max_length = 50)
    state = models.CharField(max_length = 50)
    country = models.CharField(max_length=50)
    postal_code = models.CharField(max_length=20)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pictures', blank=True, null=True)
    bio = models.TextField(max_length=500, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
