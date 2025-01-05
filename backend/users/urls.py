from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt import views as jwt_views
from .views import RegisterUser, LogoutUser, LoginUser, Profile, UserList, ChangeUserRole, AddUser, UserRoleList, \
    UserGroupViewSet, DeleteUser

router = DefaultRouter()
router.register(r'users/roles/list', UserRoleList, basename='roles')

urlpatterns = [
    path('', include(router.urls)),

    path('users/register/', RegisterUser.as_view(), name='register'),
    path('users/login/', LoginUser.as_view(), name='login'),
    path('users/logout/', LogoutUser.as_view(), name='logout'),
    path('users/profile/', Profile.as_view(), name='profile'),
    path('users/', UserList.as_view(), name='users'),
    path('users/change-role/', ChangeUserRole.as_view(), name='change-role'),
    path('users/add-user/', AddUser.as_view(), name='add-user'),
    path('users/delete-user/', DeleteUser.as_view(), name='delete-user'),

    # path('users/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('users/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),

]
