from django import forms
from django.forms import ModelForm
from .models import My_Devices, Global_Settings, Default_Credentials
from django.utils.safestring import mark_safe


# create a MY_Device form
class Add_Device_Form(ModelForm):
    class Meta:
        model = My_Devices
        fields = (
            'HostName', 
            'IP_Address', 
            'Username', 
            'Password', 
            'Type',
            'Enabled',
            'RUN_Day_of_Week',
            'RUN_Time_of_Day',
            'RUN_Enabled',            
        )
        labels = {
            'HostName'  : 'Hostname',
            'IP_Address': 'IP Address',
            'Username'  : 'Username',
            'Password'  : 'Password',
            'Type'      : 'Type',
            'Enabled'   : 'Device Enabled',
            'RUN_Day_of_Week'   : 'Auto Check Every',
            'RUN_Time_of_Day'   : 'Auto Check At',
            'RUN_Enabled    '   : 'Auto Check Enabled',
        }
        widgets = {
            'HostName': forms.TextInput(attrs={'class':'form-control', 'placeholder':'Hostname'}),
            'IP_Address': forms.TextInput(attrs={'class':'form-control','placeholder':'IP Address'}),
            'Username': forms.TextInput(attrs={'class':'form-control','placeholder':'Username'}),
            'Password': forms.PasswordInput(attrs={'class':'form-control','placeholder':'Password'}),
            'Type': forms.Select(attrs={'class':'form-control','placeholder':'Type'}),
            'Enabled'   : forms.CheckboxInput(attrs={'class':'form-control','placeholder':'Device Enabled'}),
            'RUN_Day_of_Week'   : forms.Select(attrs={'class':'form-control','placeholder':'Auto Check Every'}),
            'RUN_Time_of_Day'   : forms.Select(attrs={'class':'form-control','placeholder':'Auto Check At'}),
            'RUN_Enabled'       : forms.CheckboxInput(attrs={'class':'form-control','placeholder':'Auto Check Enabled'}),
        }
        help_texts = {
            'HostName'  : 'Hostname. (Replace every "/" with "___")',
            'IP_Address': 'IP Address to connect to',
            'Username'  : 'Username (if not provided in "Global Settings" or different)',
            'Password'  : 'Password (if not provided in "Global Settings" or different)',
            'Type'      : 'Device Type',
            'Enabled'   : 'Device Enabled or Disabled',
            'RUN_Day_of_Week'   : 'Auto Check the Device on this day',
            'RUN_Time_of_Day'   : 'Auto Check the Device at this time',
            'RUN_Enabled'       : 'Auto Check Enabled',
        }        

class Edit_Device_Form(ModelForm):
    class Meta:
        model = My_Devices
        fields = (
            'HostName', 
            'IP_Address', 
            'Username', 
            'Password', 
            'Type',
            'Enabled',
            'RUN_Day_of_Week',
            'RUN_Time_of_Day',
            'RUN_Enabled',
        )
        labels = {
            'HostName'  : 'Hostname',
            'IP_Address': 'IP Address',
            'Username'  : 'Username',
            'Password'  : 'Password',
            'Type'      : 'Type',
            'Enabled'   : 'Device Enabled',
            'RUN_Day_of_Week'   : 'Auto Check Every',
            'RUN_Time_of_Day'   : 'Auto Check At',
            'RUN_Enabled'       : 'Auto Check Enabled',
        }
        widgets = {
            'HostName'  : forms.TextInput(attrs={'class':'form-control','placeholder':'Hostname'}),
            'IP_Address': forms.TextInput(attrs={'class':'form-control','placeholder':'IP Address'}),
            'Username'  : forms.TextInput(attrs={'class':'form-control','placeholder':'Username'}),
            'Password'  : forms.PasswordInput(attrs={'class':'form-control','placeholder':'Password'}),
            'Type'      : forms.Select(attrs={'class':'form-control','placeholder':'Type'}),
            'Enabled'   : forms.CheckboxInput(attrs={'class':'form-control','placeholder':'Device Enabled'}),
            'RUN_Day_of_Week'   : forms.Select(attrs={'class':'form-control','placeholder':'Auto Check Every'}),
            'RUN_Time_of_Day'   : forms.Select(attrs={'class':'form-control','placeholder':'Auto Check At'}),
            'RUN_Enabled'       : forms.CheckboxInput(attrs={'class':'form-control','placeholder':'Auto Check Enabled'}),
        }
        help_texts = {
            'HostName'  : 'Hostname. (Replace every "/" with "___")',
            'IP_Address': 'IP Address to connect to',
            'Username'  : 'Username (if not provided in "Global Settings" or different)',
            'Password'  : 'Password (if not provided in "Global Settings" or different)',
            'Type'      : 'Device Type',
            'Enabled'   : 'Device Enabled or Disabled',
            'RUN_Day_of_Week'   : 'Auto Check the Device on this day',
            'RUN_Time_of_Day'   : 'Auto Check the Device at this time',
            'RUN_Enabled'       : 'Auto Check Enabled',
        }

        

class Global_Settings_Form(ModelForm):
    class Meta:
        model = Global_Settings
        fields = (
            'Max_Capture_Age',
            'Max_Port_Range',
            'Max_IPv4_Range',
            'Min_Hitcnt_Threshold',
            'Max_ACL_HitCnt0_Age',
            'Max_ACL_Inactive_Age',
            'Max_ACL_Expand_Ratio',
            'N_ACL_Most_Triggered',
            'Min_NAT_Hitcnt_Threshold',
            'Max_NAT_ZeroHit_Age',
            'Max_NAT_Inactive_Age',
            'N_NAT_Most_Triggered',
            'WTFLog_Duration_Days',
        )
        '''
        labels = {
            'Max_Capture_Age'           : 'Max Capture Age',
            'Min_Hitcnt_Threshold'      : 'Min ACL HitCnt Threshold',
            'Max_ACL_HitCnt0_Age'       : 'Max ACL HitCnt0 Age',
            'Max_ACL_Inactive_Age'      : 'Max ACL Inactive Age',
            'Max_ACL_Expand_Ratio'      : 'Max ACL Expand Ratio',
            'N_ACL_Most_Triggered'      : 'N ACL Most Triggered',
            'Max_NAT_ZeroHit_Age'       : 'Max NAT ZeroHit Age',
            'Max_NAT_Inactive_Age'      : 'Max NAT Inactive Age',
            'Min_NAT_Hitcnt_Threshold'  : 'Min NAT HitCnt Threshold',
            'N_NAT_Most_Triggered'      : 'N NAT Most Triggered',
            'WTFLog_Duration_Days'      : 'WTFLog_Duration_Days',
        }
        '''
        help_texts = {
            'Max_Capture_Age'           : 'After X days, the Capture can be deleted',
            'Max_Port_Range'            : 'Warn if a range has more than X ports',
            'Max_IPv4_Range'            : 'Warn if a range has more than X IPs',
            'Min_Hitcnt_Threshold'      : 'Under this number, the ACL is in doubt',
            'Max_ACL_HitCnt0_Age'       : 'After X days not triggered, the ACL can be turned "inactive"',
            'Max_ACL_Inactive_Age'      : 'After X days an inactive ACL can be deleted',
            'Max_ACL_Expand_Ratio'      : 'Warn if an ACL expands more than X lines',
            'N_ACL_Most_Triggered'      : 'Number of Top triggered ACL to be reordered',
            'Max_NAT_ZeroHit_Age'       : 'After X days not triggered, the NAT can be turned "inactive"',
            'Max_NAT_Inactive_Age'      : 'After X days, an inactive NAT can be removed',
            'Min_NAT_Hitcnt_Threshold'  : 'Under this number the NAT is in doubt',
            'N_NAT_Most_Triggered'      : 'Number of Top triggered NAT to be reordered',
            'WTFLog_Duration_Days'      : 'Delete the log after X Days',
        }
        
        widgets = {
            'Max_Capture_Age': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 10'}),
            'Max_Port_Range': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 10'}),
            'Max_IPv4_Range': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 10'}),
            'Min_Hitcnt_Threshold': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 20'}),
            'Max_ACL_Inactive_Age': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 180'}),
            'Max_ACL_HitCnt0_Age': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 180'}),
            'Max_ACL_Expand_Ratio': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 100'}),
            'N_ACL_Most_Triggered': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 10'}),
            'Max_NAT_Inactive_Age': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 180'}),
            'Max_NAT_ZeroHit_Age': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 180'}),
            'Min_NAT_Hitcnt_Threshold': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 20'}),
            'N_NAT_Most_Triggered': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 20'}),
            'WTFLog_Duration_Days': forms.NumberInput(attrs={'class':'form-control','placeholder':'Suggested is 30'}),
        }

    '''
    def __init__(self, *args, **kwargs):
        super(Global_Settings_Form, self).__init__(*args, **kwargs)
        tooltips = {
            'Max_Capture_Age'           : '',
            'Min_Hitcnt_Threshold'      : '',
            'Max_ACL_Inactive_Age'      : '',
            'Max_ACL_HitCnt0_Age'       : '',
            'Max_ACL_Expand_Ratio'      : '',
            'N_ACL_Most_Triggered'      : '',
            'Max_NAT_Inactive_Age'      : '',
            'Max_NAT_ZeroHit_Age'       : '',
            'Min_NAT_Hitcnt_Threshold'  : '',
            'N_NAT_Most_Triggered'      : '',
            'WTFLog_Duration_Days'      : '',
        }  
            
        for field_name, field in self.fields.items():
            field.widget.attrs.update({'class': 'form-control'})
            field.widget.attrs.update({'data-toggle': 'tooltip', 'data-placement': 'top', 'title': tooltips.get(field_name, '')})
    '''
    def __init__(self, *args, **kwargs):
        logged_user = kwargs.pop('logged_user', None)  # Get the logged in user instance passed to the form
        super(Global_Settings_Form, self).__init__(*args, **kwargs)

        # Define custom labels with HTML
        custom_labels = {
            'Max_Capture_Age'           : '<strong>Max</strong> Capture Age',
            'Max_Port_Range'            : '<strong>Max</strong> Port Range',
            'Max_IPv4_Range'            : '<strong>Max</strong> IPv4 Range',
            'Min_Hitcnt_Threshold'      : '<strong>Min</strong> ACL HitCnt Threshold',
            'Max_ACL_HitCnt0_Age'       : '<strong>Max</strong> ACL Zero HitCnt Age',
            'Max_ACL_Inactive_Age'      : '<strong>Max</strong> ACL Inactive Age',
            'Max_ACL_Expand_Ratio'      : '<strong>Max</strong> ACL Expand Ratio',
            'N_ACL_Most_Triggered'      : '<strong>N°</strong> ACL Most Triggered',
            'Max_NAT_ZeroHit_Age'       : '<strong>Max</strong> NAT Zero HitCnt Age',
            'Max_NAT_Inactive_Age'      : '<strong>Max</strong> NAT Inactive Age',
            'Min_NAT_Hitcnt_Threshold'  : '<strong>Min</strong> NAT HitCnt Threshold',
            'N_NAT_Most_Triggered'      : '<strong>N°</strong> NAT Most Triggered',
            'WTFLog_Duration_Days'      : '<strong>N°</strong> Days Log Lasting',
        }

        # Apply the custom labels
        for field_name, custom_label in custom_labels.items():
            if field_name in self.fields:
                self.fields[field_name].label = mark_safe(custom_label)
        if logged_user and not logged_user.groups.filter(name='Admin').exists():
            for field in self.fields.values():
                field.widget.attrs['disabled'] = 'disabled'


class Default_Credentials_Form(ModelForm):
    class Meta:
        model = Default_Credentials
        fields = (
            'Username',
            'Password',
        )
        help_texts = {
            'Username'                  : 'The default Username if not specified in the device',
            'Password'                  : 'The default Password if not specified in the device',
        }
        
        widgets = {
            'Username': forms.TextInput(attrs={'class': 'form-control','placeholder':'Username'}),
            'Password': forms.PasswordInput(attrs={'class': 'form-control','placeholder':'Password'}),
        }
    def __init__(self, *args, **kwargs):
        logged_user = kwargs.pop('logged_user', None)  # Get the logged in user instance passed to the form
        super(Default_Credentials_Form, self).__init__(*args, **kwargs)

        custom_labels = {
            'Username'           : '<strong></strong> Default Username',
            'Password'           : '<strong></strong> Device Password',
        }

        # Apply the custom labels
        for field_name, custom_label in custom_labels.items():
            if field_name in self.fields:
                self.fields[field_name].label = mark_safe(custom_label)
        if logged_user and not logged_user.groups.filter(name='Admin').exists():
            for field in self.fields.values():
                field.widget.attrs['disabled'] = 'disabled'