from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from .forms import RegisterUserForm, UpdateUserForm, My_PasswordChangeForm
from django.contrib.auth.models import User, Group
from app.models import WTF_Log
from django.utils import timezone
import os

from django.db import models
from app.models import My_Devices, Global_Settings, Devices_Model, Default_Credentials

# Create your views here.
def login_user(request):
    
    # Ensure Global_Settings has a default row
    if not Global_Settings.objects.exists():
        Global_Settings.objects.create()  # Default values are used
        #initialize Users Groups
        Group.objects.get_or_create(name='Admin')
        Group.objects.get_or_create(name='Guest')
    if not Devices_Model.objects.filter(Device_Vendor='Cisco', Device_Model='ASA').exists():
        Devices_Model.objects.create(
            Device_Vendor='Cisco',
            Device_Model='ASA',
            Default_Username='',
            Default_Password=''
        )
    if not Default_Credentials.objects.exists():
        Default_Credentials.objects.create()  # Default credentials line for connecting to devices

    # Ensure a superuser exists
    if not User.objects.filter(is_superuser=True).exists():
        Django_username = os.getenv('DJANGO_SUPERUSER_USERNAME', 'django_admin')
        Django_password = os.getenv('DJANGO_SUPERUSER_PASSWORD', 'django_admin_pwd')
        Django_email    = os.getenv('DJANGO_SUPERUSER_EMAIL',    'dj-admin@trash.me')
        User.objects.create_superuser(
            username=Django_username,
            email=Django_email,
            password=Django_password
        )
        print("Superuser created successfully!")
    
    if request.method == 'POST':
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            Log_MSG = f"User '{request.user}' Logged in"
            WTF_Log.objects.create( TimeStamp = timezone.now(),
                                    Level = 'INFO',
                                    Message = Log_MSG,)
            # Redirect to a success page.
            return redirect('home')
        else:
            # Return an 'invalid login' error message.
            messages.success(request, ("Wrong Username or Password!")) 
            return redirect('login_user')
    else:
        return render(request, 'login.html', {})
    

def logout_user(request):
    logout(request)
    Log_MSG = f"User '{request.user}' Logged out"
    WTF_Log.objects.create( TimeStamp = timezone.now(),
                            Level = 'INFO',
                            Message = Log_MSG,)
    #messages.success(request, ("User Logged Out!")) 
    return redirect('login_user')


def manage_users(request):
    Devices_list = My_Devices.objects.all().order_by('HostName')
    try:
        c_group = request.user.groups.all()[0] # This is the group of the user that is making the request
    except:
        c_group = None
    #print(c_group.name)
    
    if request.user.is_authenticated:
        try:
            if ('Guest'in c_group.name):
                Users_list = User.objects.filter(id=request.user.id)
            elif ('Admin'in c_group.name):
                Users_list = User.objects.all().order_by('first_name')
            else:
                messages.success(request, f"User's Group is not Allowed!")
                logout(request)
                return redirect('login_user')
            return render (request, 'manage_users.html', 
                {
                    'Users_list':   Users_list,
                    'Devices_list': Devices_list,
                    })
        except: #manage the superuser with no group membership
            if request.user.is_superuser:
                Users_list = User.objects.all().order_by('first_name')
                return render (request, 'manage_users.html', 
                    {
                        'Users_list':   Users_list,
                        'Devices_list': Devices_list,
                     })
            else:
                logout(request)
                return redirect('login_user')
    else:
        messages.success(request, f"You Must Login!")
        return redirect('login_user')
    
'''
def manage_users(request):
    if request.user.is_authenticated:
        Users_list = User.objects.all().order_by('first_name')
        return render (request, 'manage_users.html', 
            {
            'Users_list'  : Users_list,
            })
    else:
        messages.success(request, f"You Must Login!")
        return redirect('manage_users')
'''    

#this page has to be locked to Guest users    !!!!!!
def register_user(request):
    Devices_list = My_Devices.objects.all().order_by('HostName')
    try:
        c_group = request.user.groups.all()[0] # This is the group of the user that is making the request
    except:
        c_group = None
        
    if request.user.is_authenticated:
        try:
            if ('Admin'in c_group.name):
                if request.method == 'POST':
                    form = RegisterUserForm(request.POST)
                    if form.is_valid():
                        form.save()
                        username = form.cleaned_data['username']
                        Log_MSG = f"User '{username}' created by '{request.user}'"
                        WTF_Log.objects.create( TimeStamp = timezone.now(),
                                                Level = 'INFO',
                                                Message = Log_MSG,)                        
                        #password = form.cleaned_data['password1']
                        #user = authenticate(username=username, password=password)
                        messages.success(request, f'User "{username}" Added')
                        return redirect('manage_users')
                    else:
                        # Return even if form is invalid
                        #messages.success(request, f"Form is not Valid!")
                        return render(request, 'register_user.html', {
                            'form': form,
                            'Devices_list': Devices_list,
                        })
                else:
                    form = RegisterUserForm()
                    return render(request, 'register_user.html', 
                        {
                            'form':         form,
                            'Devices_list': Devices_list,
                        })                    
            else:
                messages.success(request, f"You Are Not an Admin Member!")
                return redirect('manage_users')
        except: #manage the superuser with no group membership
            if request.user.is_superuser:
                if request.method == 'POST':
                    form = RegisterUserForm(request.POST)
                    if form.is_valid():
                        form.save()
                        username = form.cleaned_data['username']
                        #password = form.cleaned_data['password1']
                        #user = authenticate(username=username, password=password)
                        messages.success(request, f'User "{username}" Added')
                        return redirect('manage_users')
                else:
                    form = RegisterUserForm()
                    return render(request, 'register_user.html', 
                        {
                            'form':         form,
                            'Devices_list': Devices_list,
                        })      
            else:
                logout(request)
                messages.success(request, f"You Are Not an Admin Member!")
                return redirect('login_user')
    else:
        messages.success(request, f"You Must Login!")
        return redirect('login_user')

'''
def register_user(request):
    if request.method == 'POST':
        form = RegisterUserForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user = authenticate(username=username, password=password)
            messages.success(request, f"User '{username}' Added.")
            return redirect('manage_users')
    else:
        form = RegisterUserForm()
    return render(request, 'register_user.html', {'form':form,})
'''

def delete_user(request, t_User_ID):
    user = get_object_or_404(User, id=t_User_ID)
    try:
        c_group = request.user.groups.all()[0] # This is the group of the user that is making the request
    except:
        c_group = None
    if request.user.is_authenticated:
        try:
            if ('Admin'in c_group.name) or (request.user == user):  # you are 'Admin' or a 'Guest' on your own youser profile
                user.delete()
                Log_MSG = f"User '{user.username}' has been deleted by '{request.user}'"
                WTF_Log.objects.create( TimeStamp = timezone.now(),
                                        Level = 'INFO',
                                        Message = Log_MSG,)
                messages.success(request, f'User "{user.username}" has been deleted!')
                return redirect('manage_users')
            else: # Guest user on another user's id
                messages.success(request, f"You Can't Delte Users!")
                return redirect('manage_users')
        except:
            if request.user.is_superuser:
                user.delete()
                messages.success(request, f'User "{user.username}" has been deleted!')
                return redirect('manage_users')            
            else: #who are you???
                logout(request)
                return redirect('login_user')
    else:
        return redirect('login_user')


    
def update_user(request, t_User_ID):
    Devices_list = My_Devices.objects.all().order_by('HostName')
    if request.user.is_authenticated:
        current_user = User.objects.get(id=request.user.id) #to underestaned who is logged in
        user_to_edit = User.objects.get(id=t_User_ID)       #the one to modify
        try:
            c_group = request.user.groups.all()[0].name # This is the group of the user that is making the request
            if ('Admin'in c_group) or (user_to_edit.pk == current_user.pk):
                form = UpdateUserForm(request.POST or None, instance=user_to_edit, logged_user=current_user) 
                if request.method == 'POST':
                    if form.is_valid():
                        form.save()
                        Log_MSG = f"User '{user_to_edit.username}' has been updated '{request.user}'"
                        WTF_Log.objects.create( TimeStamp = timezone.now(),
                                                Level = 'INFO',
                                                Message = Log_MSG,)
                        messages.success(request, f"User Profile Updated...")
                        return redirect('manage_users')
                return render(request, 'update_user.html', 
                    {
                        'form':         form,
                        'Devices_list': Devices_list,
                    })
            else:
                messages.success(request, f"You Can't Edit Users!")
                return redirect('manage_users')
        except:
            if request.user.is_superuser:
                form = UpdateUserForm(request.POST or None, instance=user_to_edit, logged_user=current_user) 
                if request.method == 'POST':
                    if form.is_valid():
                        form.save()
                        Log_MSG = f"User '{user_to_edit.username}' has been updated '{request.user}'"
                        WTF_Log.objects.create( TimeStamp = timezone.now(),
                                                Level = 'INFO',
                                                Message = Log_MSG,)
                        messages.success(request, f"User Profile Updated...")
                        return redirect('manage_users')
                return render(request, 'update_user.html', 
                    {
                        'form':         form,
                        'Devices_list': Devices_list,
                    })
            else:
                messages.success(request, f"You Must Login!")
                return redirect('manage_users')
        
        
        
        current_user = User.objects.get(id=request.user.id) #to underestaned who is logged in
        user_to_edit = User.objects.get(id=t_User_ID)       #the one to modify
        try:
            c_group = request.user.groups.all()[0] # This is the group of the user that is making the request
        except:
            c_group = None        
        if user_to_edit.pk == current_user.pk:
            print('USER MATCH')
        else:
            print('USER MISMATCH...')
        if 'Admin'in c_group.name or request.user.is_superuser or request.user == user:  # Ensure the current user has permission to delete
            form = UpdateUserForm(request.POST or None, instance=user_to_edit, logged_user=current_user) 
            if request.method == 'POST':
                if form.is_valid():
                    form.save()
                    messages.success(request, f"User Profile Updated...")
                    return redirect('manage_users')
            return render(request, 'update_user.html', {'form':form})
        else:
            messages.success(request, f"You Can't Edit Users!")
            return redirect('manage_users')
    else:
        messages.success(request, f"You Must be Logged In...")
        return redirect('login_user')
    
    
def change_password(request):
    Devices_list = My_Devices.objects.all().order_by('HostName')
    if request.user.is_authenticated:
        if request.method == 'POST':
            form = My_PasswordChangeForm(request.user, request.POST)
            if form.is_valid():
                user = form.save()
                # Keeps the user logged in after changing their password
                update_session_auth_hash(request, user)
                messages.success(request, f"User Password Updated...")
                return redirect('manage_users')
            else:
                for error in list(form.errors.values()):
                    messages.error(request, error)
        else:
            form = My_PasswordChangeForm(request.user)
        return render(request, 'change_password.html', 
            {
                'form':         form,
                'Devices_list': Devices_list,
            })
    else:
        messages.success(request, f"You Must be Logged In...")
        return redirect('login_user')