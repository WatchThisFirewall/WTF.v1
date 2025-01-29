from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm
from django.contrib.auth.models import User, Group
from django import forms


class RegisterUserForm(UserCreationForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control'}))
    first_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class':'form-control'}))
    last_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class':'form-control'}))
    group = forms.ModelChoiceField(
        queryset=Group.objects.all(),
        required=True,
        widget=forms.Select(attrs={'class': 'form-control'}),
        label="Select Group"
    )    
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2','group')
        
    def __init__(self, *args, **kwargs):
        super(RegisterUserForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['class'] = 'form-control'
        self.fields['password1'].widget.attrs['class'] = 'form-control'
        self.fields['password2'].widget.attrs['class'] = 'form-control'
        
    def save(self, commit=True):
            user = super(RegisterUserForm, self).save(commit=False)
            user.save()  # Save the user first
            group = self.cleaned_data['group']
            user.groups.set([group])  # Set the user's groups
            return user


class UpdateUserForm(UserChangeForm):
    password = None
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class':'form-control'}))
    first_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class':'form-control'}))
    last_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class':'form-control'}))
    group = forms.ModelChoiceField(
        queryset=Group.objects.all(),
        required=True,
        widget=forms.Select(attrs={'class': 'form-control'}),
        label="Select Group"
    )    
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'group')
        #print(user.groups.all()[0])
        #print('TEST')
        
    def __init__(self, *args, **kwargs):
        
        logged_user = kwargs.pop('logged_user', None)  # Get the logged in user instance passed to the form
        t_user = kwargs.get('instance', None)   # Get the user instance passed to the form
        
        super(UpdateUserForm, self).__init__(*args, **kwargs)
        
        #print (user.id)
        #print(t_user.id)
        
        self.fields['username'].widget.attrs['class'] = 'form-control'
        #self.fields['group'].queryset = Group.objects.filter(name__in=['Guest'])

        if t_user:
            # Set the queryset of 'group' to only the current group of the user
            if logged_user and logged_user.groups.filter(name='Guest').exists():
                self.fields['group'].queryset = Group.objects.filter(user=t_user)
                self.fields['group'].help_text = "Admin users only can change groups."
            # Set the initial value of 'group' to the user's current group
            if t_user.groups.exists():
                self.fields['group'].initial = t_user.groups.first()
        
       
        # Example: Dynamically change the help text based on the user's group
#        if user and user.groups.filter(name='Guest').exists():
#            self.fields['group'].help_text = "Admin users only can change groups."
#            self.fields['group'].widget.attrs['disabled'] = 'disabled'
                    
    def save(self, commit=True):
            user = super(UpdateUserForm, self).save(commit=False)
            user.save()  # Save the user first
            group = self.cleaned_data['group']
            user.groups.set([group])  # Set the user's groups
            return user


class My_PasswordChangeForm(PasswordChangeForm):
    
    class Meta:
        model = User
        fields = ('old_password', 'new_password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        super(My_PasswordChangeForm, self).__init__(*args, **kwargs)
        self.fields['old_password'].widget.attrs.update({'class': 'form-control'})
        self.fields['new_password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['new_password2'].widget.attrs.update({'class': 'form-control'})
        
