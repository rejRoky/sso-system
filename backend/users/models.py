import uuid
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

from annotation.models import Annotation


class UserManager(BaseUserManager):
    def create_user(self, mobile_number, password=None, **extra_fields):
        if not mobile_number:
            raise ValueError('The Mobile Number field must be set')
        user = self.model(mobile_number=mobile_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, mobile_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(mobile_number, password, **extra_fields)


Roles = (
    ('Admin', 'Admin'),
    ('Manager', 'Manager'),
    ('Annotator', 'Annotator'),
    ('Validator', 'Validator'),
    ('User', 'User'),
)

class User(AbstractBaseUser, PermissionsMixin):  # Inherit PermissionsMixin
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    mobile_number = models.CharField(max_length=20, unique=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(unique=True, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    office = models.CharField(max_length=50, blank=True, null=True)
    designation = models.CharField(max_length=50, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=Roles, default='User', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, editable=False, null=True, blank=True)
    objects = UserManager()

    USERNAME_FIELD = 'mobile_number'
    REQUIRED_FIELDS = []

    def __str__(self):
        return f'{self.full_name}' + ' - ' + f'{self.mobile_number}'


class UserActionLog(models.Model):
    ACTION_TYPES = (
        ('LOGIN', 'Login'),
        ('REGISTER', 'Register'),
        ('UPDATE', 'Profile Update'),
        ('LOGOUT', 'Logout'),
        ('REQUEST', 'Request'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action_type = models.CharField(max_length=200, null=True, blank=True)
    action_description = models.TextField(null=True, blank=True)
    ip_address = models.CharField(max_length=45, null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.user.mobile_number} - {self.action_type} - {self.timestamp}'


class UserGroup(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, blank=True, null=True, unique=True)
    description = models.TextField(blank=True, null=True)
    annotation = models.ForeignKey(Annotation, on_delete=models.CASCADE, related_name='annotation_group', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    users = models.ManyToManyField(User, related_name='user_groups', blank=True)

    def __str__(self):
        return self.name