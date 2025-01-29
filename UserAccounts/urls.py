
from django.urls import path
from . import views
#from django.contrib.auth import views as auth_views


urlpatterns = [
    path('login_user', views.login_user, name='login_user'),
    path('logout_user', views.logout_user, name='logout_user'),
    path('register_user', views.register_user, name='register_user'),
    path('manage_users', views.manage_users, name='manage_users'),
    path('delete_user/<t_User_ID>', views.delete_user, name='delete_user'),
    path('update_user/<t_User_ID>', views.update_user, name='update_user'),
    path('change_password/', views.change_password, name='change_password'),
    #path('password/', auth_views.PasswordChangeView.as_view(), name='change_password'),
]
