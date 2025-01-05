import logging
from operator import truediv

from django.contrib.auth import authenticate
from django.utils.timezone import now
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import viewsets
from .models import User, Roles, UserGroup
from .serializers import UserSerializer, UserGroupSerializer
from rest_framework.pagination import PageNumberPagination

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Helper function to get the client IP address."""
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
    if ip_address:
        ip_address = ip_address.split(',')[0]
    else:
        ip_address = request.META.get('REMOTE_ADDR', '0.0.0.0')
    return ip_address


class RegisterUser(APIView):

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile_number': openapi.Schema(type=openapi.TYPE_STRING,
                                                description='Mobile number of the user, must be 11 digits long and start with 01 and contain only digits'),
                'password': openapi.Schema(type=openapi.TYPE_STRING,
                                           description='Password of the user, must be at least 8 characters long and contain at least one digit, one alphabet, one uppercase letter, one lowercase letter, and one special character'),
                'email': openapi.Schema(type=openapi.TYPE_STRING,
                                        description='Email of the user, must be a valid email address'),
                'full_name': openapi.Schema(type=openapi.TYPE_STRING, description='Full name of the user'),
                'designation': openapi.Schema(type=openapi.TYPE_STRING, description='Designation of the user'),

            },
            required=['mobile_number', 'password', 'email', 'first_name', 'last_name', 'designation'],

        ),
        responses={201: 'Success'},
    )
    def post(self, request):
        mobile_number = request.data.get('mobile_number')
        password = request.data.get('password')
        email = request.data.get('email')
        full_name = request.data.get('full_name')
        designation = request.data.get('designation')

        # Null validation
        if mobile_number is None:
            return Response({'error': 'Mobile number is required'}, status=status.HTTP_400_BAD_REQUEST)

        if email is None:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        if full_name is None:
            return Response({'error': 'Full name is required'}, status=status.HTTP_400_BAD_REQUEST)

        if password is None:
            return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Mobile number validation
        if mobile_number == '' or email == '' or full_name == '' or password == '':
            return Response({'error': 'Fields cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)

        if mobile_number is not None and len(mobile_number) != 11:
            return Response({'error': 'Mobile number must be 11 digits long'}, status=status.HTTP_400_BAD_REQUEST)

        if not mobile_number.isdigit():
            return Response({'error': 'Mobile number must contain only digits'}, status=status.HTTP_400_BAD_REQUEST)

        if not mobile_number.startswith('01'):
            return Response({'error': 'Mobile number must start with 01'}, status=status.HTTP_400_BAD_REQUEST)

        # Email validation
        if '@' not in email:
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        if '.' not in email:
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        at_index = email.find('@')
        dot_index = email.rfind('.')

        # Check if '@' comes before the last '.'
        if not (at_index < dot_index):
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if '.' is not the last character
        if dot_index == len(email) - 1:
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if '@' is not the first character
        if at_index == 0:
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if there is at least one character between '@' and '.'
        if not (dot_index > at_index + 1):
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        # User validation
        if User.objects.filter(mobile_number=mobile_number).exists():
            return Response({'error': 'User with this mobile number already exists'},
                            status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Password validation
        if password is None or len(password) < 8:
            return Response({'error': 'Password must be at least 8 characters long'},
                            status=status.HTTP_400_BAD_REQUEST)

        if not any(char.isdigit() for char in password):
            return Response({'error': 'Password must contain at least one digit'}, status=status.HTTP_400_BAD_REQUEST)

        if not any(char.isalpha() for char in password):
            return Response({'error': 'Password must contain at least one alphabet'},
                            status=status.HTTP_400_BAD_REQUEST)

        if not any(char.isupper() for char in password):
            return Response({'error': 'Password must contain at least one uppercase letter'},
                            status=status.HTTP_400_BAD_REQUEST)

        if not any(char.islower() for char in password):
            return Response({'error': 'Password must contain at least one lowercase letter'},
                            status=status.HTTP_400_BAD_REQUEST)

        if not any(char in ['@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '='] for char in password):
            return Response({'error': 'Password must contain at least one special character'},
                            status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(mobile_number, password)
        user.email = email
        user.full_name = full_name
        user.designation = designation
        user.is_staff = True
        user.save()
        serializer = UserSerializer(user)

        # Log user registration
        logger.info(f"User {user.mobile_number} registered at {now()}.")
        # UserActionLog.objects.create(user=user, action_type='REGISTER', action_description='User registered', ip_address=get_client_ip(request))

        return Response(serializer.data)


class LoginUser(APIView):

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile_number': openapi.Schema(type=openapi.TYPE_STRING, description='Mobile number of the user'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password of the user'),
            },
            required=['username', 'password'],
        ),
        responses={200: 'Success'},
    )
    def post(self, request):
        mobile_number = request.data.get('mobile_number')
        password = request.data.get('password')

        if mobile_number is None:
            return Response({'error': 'Mobile number is required'}, status=status.HTTP_400_BAD_REQUEST)

        if password is None:
            return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)

        if mobile_number == '' or password == '':
            return Response({'error': 'Fields cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)

        if not User.objects.filter(mobile_number=mobile_number).exists():
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if not User.objects.get(mobile_number=mobile_number).is_active:
            return Response({'error': 'User is not active'}, status=status.HTTP_401_UNAUTHORIZED)

        if not authenticate(mobile_number=mobile_number, password=password):
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(mobile_number=mobile_number, password=password)
        if user:
            refresh = RefreshToken.for_user(user)

            # Log user login
            logger.info(f"User {user.mobile_number} logged in at {now()}.")
            # UserActionLog.objects.create(user=user, action_type='LOGIN', action_description='User logged in', ip_address=get_client_ip(request))
            return Response({
                'token':
                    {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'token_type': 'Bearer',
                        'expires_in': refresh.access_token.lifetime.total_seconds(),  # seconds
                    },
                'user': UserSerializer(user).data,

            })
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutUser(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token of the user'),
            },
            required=['refresh'],
        ),
        responses={200: 'Success'},
    )
    def post(self, request):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get('refresh')

            if not refresh_token:
                return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Decode and revoke the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            # Log the user logout
            logger.info(f"User {request.user.mobile_number} logged out.")

            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error logging out user: {e}")
            return Response({'error': 'Invalid token or error processing request'}, status=status.HTTP_400_BAD_REQUEST)


class Profile(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={200: 'Success'},
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'full_name': openapi.Schema(type=openapi.TYPE_STRING, description='Full name of the user'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email of the user'),
                'designation': openapi.Schema(type=openapi.TYPE_STRING, description='Designation of the user'),
                'office': openapi.Schema(type=openapi.TYPE_STRING, description='Office of the user'),
                'address': openapi.Schema(type=openapi.TYPE_STRING, description='Address of the user'),
            },
            required=['full_name', 'email', 'designation', 'address'],
        ),
        responses={200: 'Success'},
    )
    def put(self, request):
        user = request.user
        data = request.data
        user.full_name = data.get('full_name', user.full_name)
        user.email = data.get('email', user.email)
        user.designation = data.get('designation', user.designation)
        user.office = data.get('office', user.office)
        user.address = data.get('address', user.address)
        user.save()
        serializer = UserSerializer(user)

        # Log user profile update
        logger.info(f"User {user.mobile_number} updated profile at {now()}.")
        # UserActionLog.objects.create(user=request.user, action_type='UPDATE', action_description='User updated profile', ip_address=get_client_ip(request))
        return Response(serializer.data)


class UserList(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_active is False:
            return Response({'error': 'User is not active'}, status=status.HTTP_401_UNAUTHORIZED)

        users = User.objects.all()

        # Apply pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10  # Set your desired page size
        result_page = paginator.paginate_queryset(users, request)
        serializer = UserSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)


class ChangeUserRole(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Mobile number of the user whose role is to be changed'
                ),
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='New role to be assigned to the user'
                ),
            },
            required=['mobile_number', 'role'],
        ),
        responses={200: 'Success', 400: 'Bad request', 401: 'Unauthorized', 404: 'User not found', 403: 'Forbidden'},
    )
    def put(self, request):
        mobile_number = request.data.get('mobile_number')
        role = request.data.get('role')

        # Validate required fields
        if not mobile_number:
            return Response({'error': 'Mobile number is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not role:
            return Response({'error': 'Role is required'}, status=status.HTTP_400_BAD_REQUEST)
        if mobile_number == '' or role == '':
            return Response({'error': 'Fields cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the user exists
        if not User.objects.filter(mobile_number=mobile_number).exists():
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # If the request user is not an admin, they can only assign roles below their level
        if request.user.role != 'Admin':
            if role in ['Admin', 'Manager']:
                return Response(
                    {'error': 'You are not authorized to assign Admin or Manager roles'},
                    status=status.HTTP_403_FORBIDDEN
                )

        # Retrieve the user to be updated
        user = User.objects.get(mobile_number=mobile_number)

        # Update the role of the user
        user.role = role
        user.save()
        serializer = UserSerializer(user)

        # Log the role change
        logger.info(
            f"User {request.user.mobile_number} changed the role of user {user.mobile_number} to {role} at {now()}.")
        # UserActionLog.objects.create(
        #     user=request.user,
        #     action_type='UPDATE',
        #     action_description=f'Changed role of user {user.mobile_number} to {role}',
        #     ip_address=get_client_ip(request)
        # )

        return Response(serializer.data)


class AddUser(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Mobile number of the user, must be 11 digits long and start with 01 and contain only digits'
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Password of the user, must be at least 8 characters long and contain at least one digit, one alphabet, one uppercase letter, one lowercase letter, and one special character'
                ),
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Email of the user, must be a valid email address'
                ),
                'full_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Full name of the user'
                ),
                'designation': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Designation of the user'
                ),
                'office': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Office of the user'
                ),
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Role of the user'
                ),
            },
            required=['mobile_number', 'password', 'email', 'full_name', 'designation'],
        ),
        responses={201: 'Success'},
    )
    def post(self, request):
        # Check if the user is an admin
        if request.user.role != 'Admin' and request.data.get('role') in ['Manager', 'Admin']:
            return Response(
                {'error': 'Unauthorized : Only Admin can add Manager and Admin users'},
                status=status.HTTP_403_FORBIDDEN
            )

        mobile_number = request.data.get('mobile_number')
        password = request.data.get('password')
        email = request.data.get('email')
        full_name = request.data.get('full_name')
        designation = request.data.get('designation')
        office = request.data.get('office')
        role = request.data.get('role')

        # Null validation
        if not mobile_number:
            return Response({'error': 'Mobile number is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not full_name:
            return Response({'error': 'Full name is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Mobile number validation
        if len(mobile_number) != 11:
            return Response({'error': 'Mobile number must be 11 digits long'}, status=status.HTTP_400_BAD_REQUEST)
        if not mobile_number.isdigit():
            return Response({'error': 'Mobile number must contain only digits'}, status=status.HTTP_400_BAD_REQUEST)
        if not mobile_number.startswith('01'):
            return Response({'error': 'Mobile number must start with 01'}, status=status.HTTP_400_BAD_REQUEST)

        # Email validation
        if '@' not in email or '.' not in email or email.find('@') > email.rfind('.'):
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)

        # User existence validation
        if User.objects.filter(mobile_number=mobile_number).exists():
            return Response({'error': 'User with this mobile number already exists'},
                            status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Password validation
        if len(password) < 8:
            return Response({'error': 'Password must be at least 8 characters long'},
                            status=status.HTTP_400_BAD_REQUEST)
        if not any(char.isdigit() for char in password):
            return Response({'error': 'Password must contain at least one digit'}, status=status.HTTP_400_BAD_REQUEST)
        if not any(char.isalpha() for char in password):
            return Response({'error': 'Password must contain at least one alphabet'},
                            status=status.HTTP_400_BAD_REQUEST)
        if not any(char.isupper() for char in password):
            return Response({'error': 'Password must contain at least one uppercase letter'},
                            status=status.HTTP_400_BAD_REQUEST)
        if not any(char.islower() for char in password):
            return Response({'error': 'Password must contain at least one lowercase letter'},
                            status=status.HTTP_400_BAD_REQUEST)
        if not any(char in ['@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '='] for char in password):
            return Response({'error': 'Password must contain at least one special character'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create the user
        user = User.objects.create_user(mobile_number, password)
        user.email = email
        user.full_name = full_name
        user.designation = designation
        user.is_staff = True
        user.office = office
        user.role = role
        user.save()

        serializer = UserSerializer(user)
        logger.info(f"User {user.mobile_number} added at {now()}.")
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class DeleteUser(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Mobile number of the user to delete'
                ),
            },
            required=['mobile_number'],
        ),
        responses={
            200: 'User successfully deleted',
            400: 'Invalid input',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'User not found',
        },
    )
    def delete(self, request):
        # Ensure mobile_number is provided
        mobile_number = request.data.get('mobile_number')
        if not mobile_number:
            return Response({'error': 'Mobile number is required'}, status=status.HTTP_400_BAD_REQUEST)
        if mobile_number.strip() == '':
            return Response({'error': 'Mobile number cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate mobile_number format
        if not mobile_number.isdigit() or len(mobile_number) != 11 or not mobile_number.startswith('01'):
            return Response({'error': 'Invalid mobile number format'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists
        try:
            user_to_delete = User.objects.get(mobile_number=mobile_number)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Role-based deletion rules
        if request.user.role != 'Admin':
            if user_to_delete.role in ['Admin', 'Manager']:
                return Response(
                    {'error': 'You are not authorized to delete Admin or Manager users'},
                    status=status.HTTP_403_FORBIDDEN
                )

        # Prevent admins from deleting themselves
        if request.user == user_to_delete:
            return Response({'error': 'You cannot delete yourself'}, status=status.HTTP_400_BAD_REQUEST)

        # Delete the user
        user_to_delete.delete()

        # Log user deletion
        logger.info(f"User {request.user.mobile_number} deleted user {mobile_number} at {now()}.")

        return Response({'message': 'User successfully deleted'}, status=status.HTTP_200_OK)


class UserRoleList(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    @staticmethod
    def list(request):
        # Returning the Annotation_Type choices as a response
        annotation_types = [
            {'code': code, 'name': name} for code, name in Roles
        ]
        return Response(annotation_types)


class TokenAuthentication(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={200: 'Success'},
    )
    def get(self, request):
        return Response({'message': 'Token is valid',
                         'expires_in': request.auth.lifetime.total_seconds()
                         }, status=status.HTTP_200_OK)
