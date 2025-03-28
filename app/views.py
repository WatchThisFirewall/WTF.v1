from django.shortcuts import render, redirect
from .models import My_Devices,ACL_GROSS,ACL_Summary,Global_Settings,Active_Capture,Show_NAT_DB, Default_Credentials, WTF_Log, Devices_Model,ACL_Most_Expanded
from .models import Top_IP_Range,Top_ICMP_Open_Detail,Top_TCP_Open_Detail,Top_UDP_Open_Detail,Top_IP_Open_Detail
from django.db.models import Max,Q,Sum
from django.utils import timezone
from django.utils.timezone import make_aware, utc
from django.http import HttpResponse,JsonResponse,StreamingHttpResponse
from django.contrib import messages
import datetime
from .forms import Add_Device_Form, Edit_Device_Form, Global_Settings_Form, Default_Credentials_Form
from django.contrib.auth.models import User, Group

# test for background task START -------------
# from .models import TaskStatus

#=================================================================================================================
def wtf_logs(request):
    if request.user.is_authenticated:
        
        log_level = request.GET.get('level', None)
        # Filter logs based on the level, or show all logs
        if log_level:
            logs = WTF_Log.objects.filter(Q(Level=log_level)).order_by('TimeStamp')
        else:
            logs = WTF_Log.objects.all().order_by('TimeStamp')
        
        N_Crit_Logs = WTF_Log.objects.filter(Q(Level='CRITICAL')).count()
        N_Erro_Logs = WTF_Log.objects.filter(Q(Level='ERROR')).count()
        N_Warn_Logs = WTF_Log.objects.filter(Q(Level='WARNING')).count()
        N_Info_Logs = WTF_Log.objects.filter(Q(Level='INFO')).count()
        #All_Logs = WTF_Log.objects.all().order_by('TimeStamp')
        
        Devices_list = My_Devices.objects.all().order_by('HostName')
        return render (request, 'wtf_logs.html', 
            {
            'Devices_list'  : Devices_list,
            'N_Crit_Logs'   : N_Crit_Logs,
            'N_Erro_Logs'   : N_Erro_Logs,
            'N_Warn_Logs'   : N_Warn_Logs,
            'N_Info_Logs'   : N_Info_Logs,
            'All_Logs'      : logs,
            'log_level'     : log_level,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def test_table(request):
    if request.user.is_authenticated:
        Devices_list = My_Devices.objects.all().order_by('HostName')
        Max_N_ACL_Lines = list(My_Devices.objects.all().aggregate(Max('N_ACL_Lines')).values())[0]
        Max_N_ACL_Lines_Expanded = list(My_Devices.objects.all().aggregate(Max('N_ACL_Lines_Expanded')).values())[0]
        Max_N_Capture = list(My_Devices.objects.all().aggregate(Max('N_Capture')).values())[0]
        Max_N_NAT_Lines = list(My_Devices.objects.all().aggregate(Max('N_NAT_Lines')).values())[0]
        Max_Config_Total_Lines = list(My_Devices.objects.all().aggregate(Max('Config_Total_Lines')).values())[0]
        MAX_SUM_OBJ_Declared = list(My_Devices.objects.all().aggregate(Max('SUM_OBJ_Declared')).values())[0]
        MAX_UpTime = list(My_Devices.objects.all().aggregate(Max('UpTime')).values())[0]
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'test_table.html', 
            {
            'Devices_list'              : Devices_list,
            'Max_N_ACL_Lines'           : Max_N_ACL_Lines,
            'Max_N_ACL_Lines_Expanded'  : Max_N_ACL_Lines_Expanded,
            'Max_N_Capture'             : Max_N_Capture,
            'Max_N_NAT_Lines'           : Max_N_NAT_Lines,
            'Max_Config_Total_Lines'    : Max_Config_Total_Lines,
            'MAX_SUM_OBJ_Declared'      : MAX_SUM_OBJ_Declared,
            'My_Global_Settings'        : My_Global_Settings,
            'MAX_UpTime'                : MAX_UpTime,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def capture(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        t_Max_Capture_Age = My_Global_Settings['Max_Capture_Age']
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        This_Capture = Active_Capture.objects.all().filter(HostName=FW_NAME_slash)
        n_capture_old = This_Device.N_Capture_Old
        n_capture = This_Device.N_Capture
        Prct_N_Capture_old = round(100*n_capture_old/n_capture,1) if not (n_capture==0) else 0    
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        Watch_FName   = '%s/%s-Capture-Watch.html' %(FW_NAME,FW_NAME)
        Fix_FName     = '%s/%s-Capture-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'capture.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Capture'  : This_Capture,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Fix_FName'     : Fix_FName,
            'My_Global_Settings' : My_Global_Settings,
            'N_Capture_old'      : n_capture_old,
            'Prct_N_Capture_old' : Prct_N_Capture_old,
            't_Max_Capture_Age'  : t_Max_Capture_Age,        
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def confdiff(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        confdiff_Fname = '%s/%s.CFG.Delta.html' %(FW_NAME,FW_NAME)
        return render (request, 'confdiff.html', 
            {
            'FW_NAME'        : FW_NAME,
            'FW_NAME_slash'  : FW_NAME_slash,
            'Devices_list'   : Devices_list,
            'confdiff_Fname' : confdiff_Fname,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def config_range(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        config_range_Fname = '%s/%s-Config_Range.html' %(FW_NAME,FW_NAME)
        return render (request, 'config_range.html', 
            {
            'FW_NAME'            : FW_NAME,
            'FW_NAME_slash'      : FW_NAME_slash,
            'This_Device'        : This_Device,
            'Devices_list'       : Devices_list,
            'config_range_Fname' : config_range_Fname,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def dashboard(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        t_Max_Capture_Age = My_Global_Settings['Max_Capture_Age']
        #given_date = timezone.now() - timezone.timedelta(days=t_Max_Capture_Age)
        #filtered_objects = Active_Capture.objects.filter(Q(First_Seen__lt=given_date) & Q(HostName=FW_NAME_slash))
        This_Device = My_Devices.objects.get(HostName=FW_NAME)
        Devices_list = My_Devices.objects.all().order_by('HostName')
        ACL_Report = ACL_Summary.objects.all().filter(HostName=FW_NAME).order_by('ACL_Name')
        Max_N_ACL_Lines = list(ACL_Summary.objects.all().filter(HostName=FW_NAME).aggregate(Max('ACL_Length')).values())[0]
        This_Capture = Active_Capture.objects.all().filter(HostName=FW_NAME_slash)
        #print(f"This_Device = {This_Device.N_Capture}")
        n_capture_old = This_Device.N_Capture_Old
        n_capture = This_Device.N_Capture
        Prct_N_Capture_old = round(100*n_capture_old/n_capture,1) if not (n_capture==0) else 0
        Chart_url = '%s/chart-area1.js' %FW_NAME
        Sankey_url = '%s/Sankey_ACL_Chart.js' %FW_NAME
        LogReport_FName        = '%s/_CONFIG_%s.txt' %(FW_NAME,FW_NAME)
        OutReport_FName        = '%s/%s.OutLog.txt'  %(FW_NAME,FW_NAME)
        ErrReport_FName        = '%s/%s.ErrLog.txt'  %(FW_NAME,FW_NAME)
        Prct_TCP_Space_Sum = My_Devices.objects.filter(HostName=FW_NAME).values('Prct_ACL_Space_TCP').values_list('Prct_ACL_Space_TCP', flat=True).first()
        Prct_UDP_Space_Sum = My_Devices.objects.all().filter(HostName=FW_NAME).values('Prct_ACL_Space_UDP').values_list('Prct_ACL_Space_UDP', flat=True).first()
        Prct_ICMP_Space_Sum = My_Devices.objects.all().filter(HostName=FW_NAME).values('Prct_ACL_Space_ICMP').values_list('Prct_ACL_Space_ICMP', flat=True).first()
        Top_IP_Open_Details = Top_IP_Open_Detail.objects.all().filter(HostName=FW_NAME)
        MAX_IP_Open_Val = list(Top_IP_Open_Detail.objects.all().filter(HostName=FW_NAME).aggregate(Max('IP_Open_Val')).values())[0]
        for t_line in Top_IP_Open_Details:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.ACL_Name = (t_line.ACL_Line).split()[1]
            #t_line.IP_Open_Val = round(100*t_line.IP_Open_Val/MAX_IP_Open_Val, 10) if not (MAX_IP_Open_Val==0) else 0
            t_line.IP_Open_Val = t_line.IP_Open_Val
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)        
        
        return render (request, 'dashboard.html', 
            {
            'FW_NAME'           : FW_NAME,
            'FW_NAME_slash'     : FW_NAME_slash,
            'This_Device'       : This_Device,
            'Devices_list'      : Devices_list,
            'ACL_Report'        : ACL_Report,
            'LogReport_FName'   : LogReport_FName,
            'OutReport_FName'   : OutReport_FName,
            'ErrReport_FName'   : ErrReport_FName,
            'Max_N_ACL_Lines'   : Max_N_ACL_Lines,
            'This_Capture'      : This_Capture,
            'Chart_url'         : Chart_url,
            'My_Global_Settings' : My_Global_Settings,
            'Sankey_url'         : Sankey_url,
            'N_Capture_old'      : n_capture_old,
            'Prct_N_Capture_old' : Prct_N_Capture_old,
            't_Max_Capture_Age'  : t_Max_Capture_Age,
            'Prct_TCP_Space_Sum' : Prct_TCP_Space_Sum,
            'Prct_UDP_Space_Sum' : Prct_UDP_Space_Sum,
            'Prct_ICMP_Space_Sum' : Prct_ICMP_Space_Sum,
            'Top_IP_Open_Details': Top_IP_Open_Details,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def deltahitcnt0acl(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-Deltahitcnt0_ACL-Watch.html' %(FW_NAME,FW_NAME)
        Watch_FName_2 = '%s/%s-Deltahitcnt0_ACL-Watch_2.html' %(FW_NAME,FW_NAME)
        Fix_FName     = '%s/%s-Deltahitcnt0_ACL-Fix.html'   %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'deltahitcnt0acl.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Watch_FName_2' : Watch_FName_2,
            'Fix_FName'     : Fix_FName,
            'My_Global_Settings' : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def deltahitcnt0nat(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-Deltahitcnt0_NAT-Watch.html' %(FW_NAME,FW_NAME)
        Watch_FName_2 = '%s/%s-Deltahitcnt0_NAT-Watch_2.html' %(FW_NAME,FW_NAME)
        Fix_FName     = '%s/%s-Deltahitcnt0_NAT-Fix.html'   %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        #print('N_NAT_HitCnt_Zero_Aging = %s' %This_Device.N_NAT_HitCnt_Zero_Aging())
        #print('N_NAT_HitCnt_Zero = %s' %This_Device.N_NAT_HitCnt_Zero)
        #print('N_NAT_HitCnt_Zero_toDel = %s' %This_Device.N_NAT_HitCnt_Zero_toDel)
        #print('N_NAT_Lines = %s' %This_Device.N_NAT_Lines)
        return render (request, 'deltahitcnt0nat.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Watch_FName_2' : Watch_FName_2,
            'Fix_FName'     : Fix_FName,
            'My_Global_Settings' : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def acl_too_open(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-acl_too_open-Watch.html' %(FW_NAME,FW_NAME) 
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'acl_too_open.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'My_Global_Settings' : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def drill_down_acls(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-drill_down_acls-Watch.html' %(FW_NAME,FW_NAME) 
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'drill_down_acls.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'My_Global_Settings' : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def Most_Hitted_ACL(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-Most_Hitted_ACL-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-Most_Hitted_ACL-Think.html' %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'Most_Hitted_ACL.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'My_Global_Settings'    : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def deny_acl_triggered(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        deny_acl_triggered_Fname_htm = '%s/%s-Deny_ACL_Triggering_TooMuch-Watch.html' %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'deny_acl_triggered.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'deny_acl_triggered_Fname_htm' : deny_acl_triggered_Fname_htm,
            'My_Global_Settings'    : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def expandedacl(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        expandedacl_Fname_htm = '%s/%s-X_Expanded_ACL-Watch.html' %(FW_NAME,FW_NAME)
        expandedacl_FIXFname_htm = '%s/%s-X_Expanded_ACL-Fix.html' %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'expandedacl.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Fix_FName'     : expandedacl_FIXFname_htm,        
            'expandedacl_Fname_htm' : expandedacl_Fname_htm,
            'My_Global_Settings'    : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def inactiveacl(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-Inactive_ACL-Watch.html' %(FW_NAME,FW_NAME)
        Watch_FName_2 = '%s/%s-Inactive_ACL-Watch_2.html' %(FW_NAME,FW_NAME)
        Fix_FName     = '%s/%s-Inactive_ACL-Fix.html'   %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'inactiveacl.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Watch_FName_2' : Watch_FName_2,
            'Fix_FName'     : Fix_FName,
            'My_Global_Settings' : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def inactivenat(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-Inactive_NAT-Watch.html' %(FW_NAME,FW_NAME)
        Watch_FName_2 = '%s/%s-Inactive_NAT-Watch_2.html' %(FW_NAME,FW_NAME)
        Fix_FName     = '%s/%s-Inactive_NAT-Fix.html'   %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'inactivenat.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Watch_FName_2' : Watch_FName_2,
            'Fix_FName'     : Fix_FName,
            'My_Global_Settings' : My_Global_Settings,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def index(request):
            
    if request.user.is_authenticated:
        Devices_list = My_Devices.objects.all().order_by('HostName')
        Max_N_ACL_Lines = list(My_Devices.objects.all().aggregate(Max('N_ACL_Lines')).values())[0]
        Max_N_ACL_Lines_Expanded = list(My_Devices.objects.all().aggregate(Max('N_ACL_Lines_Expanded')).values())[0]
        Max_N_Capture = list(My_Devices.objects.all().aggregate(Max('N_Capture')).values())[0]
        Max_N_NAT_Lines = list(My_Devices.objects.all().aggregate(Max('N_NAT_Lines')).values())[0]
        Max_Config_Total_Lines = list(My_Devices.objects.all().aggregate(Max('Config_Total_Lines')).values())[0]
        MAX_SUM_OBJ_Declared = list(My_Devices.objects.all().aggregate(Max('SUM_OBJ_Declared')).values())[0]
        MAX_UpTime = list(My_Devices.objects.all().aggregate(Max('UpTime')).values())[0]
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        N_Crit_Logs = WTF_Log.objects.filter(Q(Level='CRITICAL')).count()
        N_Erro_Logs = WTF_Log.objects.filter(Q(Level='ERROR')).count()
        N_Warn_Logs = WTF_Log.objects.filter(Q(Level='WARNING')).count()
        N_Info_Logs = WTF_Log.objects.filter(Q(Level='INFO')).count()
        Top_Size = 300
        Top_100_HitCnt = ACL_GROSS.objects.order_by('-Delta_HitCnt')[:Top_Size]
        for t_line in Top_100_HitCnt:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.ACL_Line = f'{t_line.Name} {t_line.Line} {t_line.Type} {t_line.Action} {t_line.Service} {t_line.Source} {t_line.S_Port} {t_line.Dest} {t_line.D_Port} {t_line.Rest} (hitcnt={t_line.Hitcnt}) {t_line.Hash}'
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)
        Top_100_Expand = ACL_Most_Expanded.objects.order_by('-ACL_ELength')[:Top_Size]
        for t_line in Top_100_Expand:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)
        Top_100_Deny = ACL_GROSS.objects.filter(Action='deny').order_by('-Delta_HitCnt')[:Top_Size]
        for t_line in Top_100_Deny:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.ACL_Line = f'{t_line.Name} {t_line.Line} {t_line.Type} {t_line.Action} {t_line.Service} {t_line.Source} {t_line.S_Port} {t_line.Dest} {t_line.D_Port} {t_line.Rest} (hitcnt={t_line.Hitcnt}) {t_line.Hash}'
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)
        Top_IP_Ranges = Top_IP_Range.objects.order_by('-IP_Range_Length')[:Top_Size]
        for t_line in Top_IP_Ranges:
            t_line.HostName = t_line.HostName.replace("___", "/")
        Top_ICMP_Open_Details = Top_ICMP_Open_Detail.objects.order_by('-ICMP_Open_Val')[:Top_Size]
        MAX_ICMP_Open_Val = list(Top_ICMP_Open_Detail.objects.all().aggregate(Max('ICMP_Open_Val')).values())[0]
        for t_line in Top_ICMP_Open_Details:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.ICMP_Open_Val = round(100*t_line.ICMP_Open_Val/MAX_ICMP_Open_Val, 2) if not (MAX_ICMP_Open_Val==0) else 0
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)
        Top_TCP_Open_Details = Top_TCP_Open_Detail.objects.order_by('-TCP_Open_Val')[:Top_Size]
        MAX_TCP_Open_Val = list(Top_TCP_Open_Detail.objects.all().aggregate(Max('TCP_Open_Val')).values())[0]
        for t_line in Top_TCP_Open_Details:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.TCP_Open_Val = round(100*t_line.TCP_Open_Val/MAX_TCP_Open_Val, 2) if not (MAX_TCP_Open_Val==0) else 0
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)
        Top_UDP_Open_Details = Top_UDP_Open_Detail.objects.order_by('-UDP_Open_Val')[:Top_Size]
        MAX_UDP_Open_Val = list(Top_UDP_Open_Detail.objects.all().aggregate(Max('UDP_Open_Val')).values())[0]
        for t_line in Top_UDP_Open_Details:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.UDP_Open_Val = round(100*t_line.UDP_Open_Val/MAX_UDP_Open_Val, 2) if not (MAX_UDP_Open_Val==0) else 0
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)
        Top_IP_Open_Details = Top_IP_Open_Detail.objects.order_by('-IP_Open_Val')[:Top_Size]
        MAX_IP_Open_Val = list(Top_IP_Open_Detail.objects.all().aggregate(Max('IP_Open_Val')).values())[0]
        for t_line in Top_IP_Open_Details:
            t_line.HostName = t_line.HostName.replace("___", "/")
            t_line.IP_Open_Val = round(100*t_line.IP_Open_Val/MAX_IP_Open_Val, 2) if not (MAX_IP_Open_Val==0) else 0
            t_line.ACL_Line = Color_Line(t_line.ACL_Line)
    
        return render (request, 'index.html',
                       
            {
            'Devices_list'              : Devices_list,
            'Max_N_ACL_Lines'           : Max_N_ACL_Lines,
            'Max_N_ACL_Lines_Expanded'  : Max_N_ACL_Lines_Expanded,
            'Max_N_Capture'             : Max_N_Capture,
            'Max_N_NAT_Lines'           : Max_N_NAT_Lines,
            'Max_Config_Total_Lines'    : Max_Config_Total_Lines,
            'MAX_SUM_OBJ_Declared'      : MAX_SUM_OBJ_Declared,
            'My_Global_Settings'        : My_Global_Settings,
            'MAX_UpTime'                : MAX_UpTime,
            'N_Crit_Logs'               : N_Crit_Logs,
            'N_Erro_Logs'               : N_Erro_Logs,
            'N_Warn_Logs'               : N_Warn_Logs,
            'N_Info_Logs'               : N_Info_Logs,
            'Top_100_HitCnt'            : Top_100_HitCnt,
            'Top_100_Expand'            : Top_100_Expand,
            'Top_100_Deny'              : Top_100_Deny,
            'Top_IP_Ranges'             : Top_IP_Ranges,
            'Top_ICMP_Open_Details'     : Top_ICMP_Open_Details,
            'Top_TCP_Open_Details'      : Top_TCP_Open_Details,
            'Top_UDP_Open_Details'      : Top_UDP_Open_Details,
            'Top_IP_Open_Details'       : Top_IP_Open_Details,
            })
    else:
        return redirect('login_user')        

#=================================================================================================================
def logdisabledacl(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        logdisabledacl_Fname_htm = '%s/%s.logdisabledacl_Fix.html' %(FW_NAME,FW_NAME)
        return render (request, 'logdisabledacl.html', 
            {
            'FW_NAME': FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device' : This_Device,
            'Devices_list': Devices_list,
            'logdisabledacl_Fname_htm' : logdisabledacl_Fname_htm,
            })
    else:
        return redirect('login_user') 

#=================================================================================================================
def most_triggered_nat(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list  = My_Devices.objects.all().order_by('HostName')
        This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-Most_Triggered_NAT-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName   = '%s/%s-Most_Triggered_NAT-Think.html' %(FW_NAME,FW_NAME)
        Fix_FName     = '%s/%s-Most_Triggered_NAT-Fix.html'   %(FW_NAME,FW_NAME)
        My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
        return render (request, 'most_triggered_nat.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'Fix_FName'     : Fix_FName,
            'My_Global_Settings' : My_Global_Settings,
            })
    else:
        return redirect('login_user') 

#=================================================================================================================
def notappacl(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-Unused_ACL-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-Unused_ACL-Think.html' %(FW_NAME,FW_NAME)
        Fix_FName   = '%s/%s-Unused_ACL-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'notappacl.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'Fix_FName'     : Fix_FName,
            })
    else:
        return redirect('login_user') 

#=================================================================================================================
def nologacl(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        nologacl_Fname_htm = '%s/%s.nologacl_Fix.html' %(FW_NAME,FW_NAME)
        return render (request, 'nologacl.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'nologacl_Fname_htm' : nologacl_Fname_htm,
            })
    else:
        return redirect('login_user') 

#=================================================================================================================
def not_ascii(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-Not_Ascii-Watch.html' %(FW_NAME,FW_NAME)
        return render (request, 'Not_Ascii.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            })
    else:
        return redirect('login_user') 

#=================================================================================================================
def objnet_not_applied(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjNet_Not_Applied-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-ObjNet_Not_Applied-Think.html' %(FW_NAME,FW_NAME)
        Fix_FName   = '%s/%s-ObjNet_Not_Applied-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'ObjNet_Not_Applied.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'Fix_FName'     : Fix_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def objnet_duplicated(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjNet_Duplicated-Watch.html' %(FW_NAME,FW_NAME)
        return render (request, 'ObjNet_Duplicated.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def objgrpnet_not_applied(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjGrpNet_Not_Applied-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-ObjGrpNet_Not_Applied-Think.html' %(FW_NAME,FW_NAME)
        Fix_FName   = '%s/%s-ObjGrpNet_Not_Applied-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'ObjGrpNet_Not_Applied.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'Fix_FName'     : Fix_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def objgrpnet_duplicated(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjGrpNet_Duplicated-Watch.html' %(FW_NAME,FW_NAME)
        return render (request, 'ObjGrpNet_Duplicated.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def objsvc_not_applied(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjSvc_Not_Applied-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-ObjSvc_Not_Applied-Think.html' %(FW_NAME,FW_NAME)
        Fix_FName   = '%s/%s-ObjSvc_Not_Applied-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'ObjSvc_Not_Applied.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'Fix_FName'     : Fix_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def objsvc_duplicated(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjSvc_Duplicated-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-ObjSvc_Duplicated-Think.html' %(FW_NAME,FW_NAME)
        return render (request, 'ObjSvc_Duplicated.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def objgrpsvc_not_applied(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjGrpSvc_Not_Applied-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-ObjGrpSvc_Not_Applied-Think.html' %(FW_NAME,FW_NAME)
        Fix_FName   = '%s/%s-ObjGrpSvc_Not_Applied-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'ObjGrpSvc_Not_Applied.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'Fix_FName'     : Fix_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def objgrpsvc_duplicated(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-ObjGrpSvc_Duplicated-Watch.html' %(FW_NAME,FW_NAME)
        return render (request, 'ObjGrpSvc_Duplicated.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def redundant_routes(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Fix_FName   = '%s/%s-redundant_routes-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'redundant_routes.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Fix_FName'     : Fix_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def dst_vs_routing(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName   = '%s/%s-DST_vs_Route-Watch.html'   %(FW_NAME,FW_NAME)
        return render (request, 'dst_vs_routing.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def use_declared_obj(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        UseDeclaredObj = '%s/%s-UseDeclaredObj-Watch.html'   %(FW_NAME,FW_NAME)
        netobjused = '%s/%s-netobjused-Watch.html'   %(FW_NAME,FW_NAME)
        ObjGrpNet_1Entry = '%s/%s-ObjGrpNet_1Entry-Watch.html'   %(FW_NAME,FW_NAME)
        return render (request, 'use_declared_obj.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'UseDeclaredObj': UseDeclaredObj,
            'netobjused'    : netobjused,
            'ObjGrpNet_1Entry': ObjGrpNet_1Entry,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def src_vs_routing(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        WR4ACLCounting = '%s/%s-WR4ACLCounting-Watch.html'   %(FW_NAME,FW_NAME)
        ACLWiderRoute = '%s/%s-ACL_WiderThanRouting-Watch.html'   %(FW_NAME,FW_NAME)
        TotWrongRouteACL = '%s/%s-TotWrongRouteACL-Watch.html'   %(FW_NAME,FW_NAME)
        PtlyWrongRouteACL = '%s/%s-PtlyWrongRouteACL-Watch.html'   %(FW_NAME,FW_NAME)
        return render (request, 'src_vs_routing.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'WR4ACLCounting': WR4ACLCounting,
            'ACLWiderRoute' : ACLWiderRoute,
            'TotWrongRouteACL': TotWrongRouteACL,
            'PtlyWrongRouteACL':PtlyWrongRouteACL,
            })
    else:
        return redirect('login_user')

#=================================================================================================================
def unprotected_if(request, FW_NAME):
    if request.user.is_authenticated:
        FW_NAME_slash = FW_NAME.replace('___','/')
        Devices_list = My_Devices.objects.all().order_by('HostName')
        This_Device  = My_Devices.objects.get(HostName=FW_NAME)
        Watch_FName = '%s/%s-Unprotected_IF-Watch.html' %(FW_NAME,FW_NAME)
        Think_FName = '%s/%s-Unprotected_IF-Think.html' %(FW_NAME,FW_NAME)
        Fix_FName   = '%s/%s-Unprotected_IF-Fix.html'   %(FW_NAME,FW_NAME)
        return render (request, 'unprotected_if.html', 
            {
            'FW_NAME'       : FW_NAME,
            'FW_NAME_slash' : FW_NAME_slash,
            'This_Device'   : This_Device,
            'Devices_list'  : Devices_list,
            'Watch_FName'   : Watch_FName,
            'Think_FName'   : Think_FName,
            'Fix_FName'     : Fix_FName,
            })
    else:
        return redirect('login_user')
    
#=================================================================================================================
def default_credentials(request):
    try:
        c_group = request.user.groups.all()[0] # This is the group of the user that is making the request
    except:
        c_group = None
    if request.user.is_authenticated:
        current_user = User.objects.get(id=request.user.id) #to underestaned who is logged in
        Devices_list = My_Devices.objects.all().order_by('HostName')
        t_settings = Default_Credentials.objects.get(Name='Default_Credentials')
        try:
            if ('Admin'in c_group.name):
                if request.method == "POST":
                    form = Default_Credentials_Form(request.POST or None, instance=t_settings, logged_user=current_user)
                    if form.is_valid():
                        form.save()
                        Log_MSG = f"User '{request.user}' Updated - Default Credentials"
                        WTF_Log.objects.create( TimeStamp = timezone.now(),
                                                Level = 'INFO',
                                                Message = Log_MSG,)                          
                        messages.success(request, ('Credentials Updated'))
                        return redirect('global_settings')
                    else:
                        return render (request, 'default_credentials.html',
                        {
                        'form' : form,
                        'Devices_list'  : Devices_list,
                        })
                else:
                    form = Default_Credentials_Form(instance=t_settings, logged_user=current_user)
                    return render (request, 'default_credentials.html',
                        {
                        'form' : form,
                        'Devices_list'  : Devices_list,
                })
            else: # Guest user
                messages.success(request, f"You Do Not Have Admin Rights!")
                return redirect('global_settings')
        except:
            messages.success(request, f"You Do Not Have Admin Rights!")
            return redirect('global_settings')
    else:
        return redirect('login_user')

#=================================================================================================================
def global_settings(request):
    if request.user.is_authenticated:
        current_user = User.objects.get(id=request.user.id) #to underestaned who is logged in
        Devices_list = My_Devices.objects.all().order_by('HostName')
        t_settings = Global_Settings.objects.get(Name='Global_Settings')
        if request.method == "POST":
            form = Global_Settings_Form(request.POST or None, instance=t_settings, logged_user=current_user)
            if form.is_valid():
                form.save()
                Log_MSG = f"User '{request.user}' Updated - Global Settings"
                WTF_Log.objects.create( TimeStamp = timezone.now(),
                                        Level = 'INFO',
                                        Message = Log_MSG,)  
                messages.success(request, ('Values Updated'))
                return redirect('global_settings')
            else:
                return render (request, 'global_settings.html',
                {
                'form' : form,
                'Devices_list'  : Devices_list,
                })
        else:
            form = Global_Settings_Form(instance=t_settings, logged_user=current_user)
            return render (request, 'global_settings.html',
                {
                'form' : form,
                'Devices_list'  : Devices_list,
                })
    else:
        return redirect('login_user')
 
#=================================================================================================================
def submask_table(request):
    a = [['/0'  ,    '0.0.0.0'      ,    '255.255.255.255' ,   '&nbsp;'   ],
        ['/1'   ,    '128.0.0.0'    ,    '127.255.255.255' ,   '&nbsp;'   ],
        ['/2'   ,    '192.0.0.0'    ,    '63.255.255.255'  ,   '&nbsp;'   ],
        ['/3'   ,    '224.0.0.0'    ,    '31.255.255.255'  ,   '&nbsp;'   ],
        ['/4'   ,    '240.0.0.0'    ,    '15.255.255.255'  ,   '&nbsp;'   ],
        ['/5'   ,    '248.0.0.0'    ,    '7.255.255.255'   ,   '&nbsp;'   ],
        ['/6'   ,    '252.0.0.0'    ,    '3.255.255.255'   ,   '&nbsp;'   ],
        ['/7'   ,    '254.0.0.0'    ,    '1.255.255.255'   ,   '&nbsp;'   ],
        ['/8'   ,    '255.0.0.0'    ,    '0.255.255.255'   ,'256x65536'   ],
        [ '&nbsp;','&nbsp;' ,'&nbsp;' ,  '&nbsp;'                         ],
        ['/9' ,     '255.128.0.0'   ,    '0.127.255.255'   ,'256x32768'   ],
        ['/10' ,    '255.192.0.0'   ,    '0.63.255.255'    ,'256x16384'   ],
        ['/11' ,    '255.224.0.0'   ,    '0.31.255.255'    ,'256x8192'    ],
        ['/12' ,    '255.240.0.0'   ,    '0.15.255.255'    ,'256x4096'    ],
        ['/13' ,    '255.248.0.0'   ,    '0.7.255.255'     ,'256x2048'    ],
        ['/14' ,    '255.252.0.0'   ,    '0.3.255.255'     ,'256x1024'    ],
        ['/15' ,    '255.254.0.0'   ,    '0.1.255.255'     ,'256x512'     ],
        ['/16' ,    '255.255.0.0'   ,    '0.0.255.255'     ,'256x256'     ],
        [ '&nbsp;','&nbsp;' ,'&nbsp;' ,  '&nbsp;'                         ],
        ['/17' ,    '255.255.128.0'     ,    '0.0.127.255'     ,'256x128' ],
        ['/18' ,    '255.255.192.0'     ,    '0.0.63.255'      ,'256x64'  ],
        ['/19' ,    '255.255.224.0'     ,    '0.0.31.255'      ,'256x32'  ],
        ['/20' ,    '255.255.240.0'     ,    '0.0.15.255'      ,'256x16'  ],
        ['/21' ,    '255.255.248.0'     ,    '0.0.7.255'       ,'256x8'   ],
        ['/22' ,    '255.255.252.0'     ,    '0.0.3.255'       ,'256x4'   ],
        ['/23' ,    '255.255.254.0'     ,    '0.0.1.255'       ,'256x2'   ],
        ['/24' ,    '255.255.255.0'     ,    '0.0.0.255'       ,'256x1'   ],
        [ '&nbsp;','&nbsp;' ,'&nbsp;' ,  '&nbsp;'                         ],
        ['/25' ,    '255.255.255.128' , '0.0.0.127'        ,'128'         ],
        ['/26' ,    '255.255.255.192' , '0.0.0.63'         ,'64'          ],
        ['/27' ,    '255.255.255.224' , '0.0.0.31'        ,'32'           ],
        ['/28' ,    '255.255.255.240' , '0.0.0.15'         ,'16'          ],
        ['/29' ,    '255.255.255.248' , '0.0.0.7'          ,'8'           ],
        ['/30' ,    '255.255.255.252' , '0.0.0.3'          ,'4'           ],
        ['/31' ,    '255.255.255.254' , '0.0.0.1'          ,'2'           ],
        ['/32' ,    '255.255.255.255' , '0.0.0.0'          ,'1'           ]]
    if request.user.is_authenticated:
        Devices_list = My_Devices.objects.all().order_by('HostName')
        return render (request, 'submask_table.html', 
            {
            'Devices_list'  : Devices_list,
            'sub_table' : a,
            })
    else:
        return redirect('login_user')
    
#=================================================================================================================
def subnetting(request):
    if request.user.is_authenticated:
        Devices_list = My_Devices.objects.all().order_by('HostName')
        return render (request, 'subnetting.html', 
            {
            'Devices_list'  : Devices_list,
            })
    else:
        return redirect('login_user')
   
#=================================================================================================================
def db_settings(request):
    if request.user.is_authenticated:
        #current_user = User.objects.get(id=request.user.id) #to underestaned who is logged in
        #t_settings = db_settings.objects.get(Name='db_settings')
        if request.method == "POST":
            pass
    else:
        return redirect('login_user')

#=================================================================================================================
def manage_devices(request):
    if request.user.is_authenticated:
        Devices_list = My_Devices.objects.all().order_by('HostName')
        return render (request, 'manage_devices.html', 
            {
            'Devices_list'  : Devices_list,
            })
    else:
        return redirect('login_user')
    
#=================================================================================================================
def delete_device(request, t_IP_Address):
    try:
        c_group = request.user.groups.all()[0].name # This is the group of the user that is making the request
    except:
        c_group = None
    if request.user.is_authenticated:
        try:
            if ('Admin'in c_group):
                t_Device = My_Devices.objects.get(IP_Address=t_IP_Address)
                t_Device.delete()
                Log_MSG = f"User '{request.user}' Deleted device '{t_Device.HostName}' with IP '{t_Device.IP_Address}'"
                WTF_Log.objects.create( TimeStamp = timezone.now(),
                                        Level = 'INFO',
                                        Message = Log_MSG,)
                messages.success(request, f"Device {t_IP_Address} has been deleted!")
                return redirect('manage_devices')
            else: # Guest user
                messages.success(request, f"You Do Not Have Admin Rights to Delte Devices!")
                return redirect('manage_devices')
        except:
            messages.success(request, f"You Do Not Have Admin Rights to Delte Devices!")
            return redirect('manage_devices')
    else:
        return redirect('login_user')

#=================================================================================================================
def edit_device(request, t_IP_Address):
    try:
        c_group = request.user.groups.all()[0].name # This is the group of the user that is making the request
    except:
        c_group = None
        
    if request.user.is_authenticated:
        Devices_list = My_Devices.objects.all().order_by('HostName')
        if c_group:
            if ('Admin'in c_group):
                t_Device = My_Devices.objects.get(pk=t_IP_Address)
                form = Edit_Device_Form(request.POST or None, instance=t_Device)
                if request.method == "POST":
                    if form.is_valid():
                        form.save()
                        Log_MSG = f"User '{request.user}' Updated device '{t_Device.HostName}' with IP '{t_Device.IP_Address}'"
                        WTF_Log.objects.create( TimeStamp = timezone.now(),
                                                Level = 'INFO',
                                                Message = Log_MSG,)                          
                        #return redirect('manage_devices')
                        messages.success(request, f"Device Updated!")
                        return render (request, 'edit_device.html', 
                        {
                        't_Device'  : t_Device,
                        'Devices_list'  : Devices_list,
                        'form' : form,
                        })
                    return render (request, 'edit_device.html', 
                        {
                        't_Device'  : t_Device,
                        'Devices_list'  : Devices_list,
                        'form' : form,
                        })
                else:
                    return render (request, 'edit_device.html', 
                        {
                        't_Device'  : t_Device,
                        'Devices_list'  : Devices_list,
                        'form' : form,
                        })
            else:
                messages.success(request, f"You Do Not Have Admin Rights to Edit Devices!")
                return redirect('manage_devices')   
        else:
            if request.user.is_superuser:
                t_Device = My_Devices.objects.get(pk=t_IP_Address)
                form = Edit_Device_Form(request.POST or None, instance=t_Device)
                if form.is_valid():
                    form.save()
                    return redirect('manage_devices')
                return render (request, 'edit_device.html', 
                    {
                    't_Device'  : t_Device,
                    'Devices_list'  : Devices_list,
                    'form' : form,
                    })
            else:
                messages.success(request, f"You Do Not Have Admin Rights to Edit Devices!")
                return redirect('manage_devices')
    else:
        return redirect('login_user')

#=================================================================================================================
def add_device(request):
    try:
        c_group = request.user.groups.all()[0].name # This is the group of the user that is making the request
    except:
        c_group = None
        
    Devices_list = My_Devices.objects.all().order_by('HostName')
    if request.user.is_authenticated:
        try:
            #print(c_group)
            if ('Admin'in c_group):
                if request.method == "POST":
                    form = Add_Device_Form(request.POST)
                    if form.is_valid():
                        device = form.save()
                        Log_MSG = f"User '{request.user}' Added device '{device.HostName}' with IP '{device.IP_Address}'"
                        WTF_Log.objects.create( TimeStamp = timezone.now(),
                                                Level = 'INFO',
                                                Message = Log_MSG,)
                        messages.success(request, ('Device Added!'))
                        print(device.IP_Address)
                        return redirect('edit_device', device.IP_Address) 
                    else:
                        return render (request, 'add_device.html', 
                        {
                        'form' : form,
                        'Devices_list'  : Devices_list,
                        })
                else:
                    form = Add_Device_Form
                    return render (request, 'add_device.html', 
                        {
                        'form' : form,
                        'Devices_list'  : Devices_list,
                        })
            else:
                messages.success(request, f"You Are Not an Admin User!")
                return redirect('manage_devices')
        except:
            print('@except:' + c_group)
            messages.success(request, f"You Are Not an Admin User!")
            return redirect('manage_devices')
    else:
        return redirect('login_user')

#=================================================================================================================
#import subprocess
import asyncio
import threading
from queue import Queue, Empty
from pathlib import Path

def run_scriptASA_Test_Conn(request, t_IP_Address):
    queue = Queue()
    if request.user.is_authenticated:
        async def async_subprocess(queue):
            python_path = get_python_path()
            #python_path = Path("./../venv311/Scripts/python.exe")
            script_path = Path("./app/Scripts/ASA_Test_Connection.py")
            args = ['-d', t_IP_Address]
            process = await asyncio.create_subprocess_exec(
                python_path, 
                script_path,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                while True:
                    line_stdout = await process.stdout.readline()
                    line_stderr = await process.stderr.readline()
                    if line_stdout:
                        queue.put(line_stdout.decode())
                    if line_stderr:
                        queue.put(line_stderr.decode())
                    if not line_stdout and not line_stderr:
                        break
                await process.wait()
            finally:
                queue.put(None)  # Signal that the subprocess is done

        def start_async_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(async_subprocess(queue))
            loop.close()

        threading.Thread(target=start_async_loop, daemon=True).start()

        def generator():
            while True:
                try:
                    line = queue.get(timeout=10)  # Adjust timeout as needed
                    if line is None:
                        break
                    yield line
                except Empty:
                    continue

        response = StreamingHttpResponse(generator(), content_type='text/plain')
        response['Cache-Control'] = 'no-cache'
        return response
    else:
        return redirect('login_user')

#=================================================================================================================
def run_Script_WTF(request, t_IP_Address):
    if request.user.is_authenticated:
        queue = Queue()
        This_Device  = My_Devices.objects.get(IP_Address=t_IP_Address)
        t_HostName = This_Device.HostName
        
        async def async_subprocess(queue):
            python_path = get_python_path()
            #python_path = Path("./../venv311/Scripts/python.exe")
            script_path = Path("./app/Scripts/ASA_Check_Config.v.1.py")
            args = ['-d', t_HostName]  # Separate arguments from script path
            process = await asyncio.create_subprocess_exec(
                python_path, 
                script_path,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )        

            try:
                while True:
                    line_stdout = await process.stdout.readline()
                    line_stderr = await process.stderr.readline()
                    if line_stdout:
                        queue.put(line_stdout.decode())
                    if line_stderr:
                        queue.put(line_stderr.decode())
                    if not line_stdout and not line_stderr:
                        break
                await process.wait()
            finally:
                queue.put(None)  # Signal that the subprocess is done

        def start_async_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(async_subprocess(queue))
            loop.close()

        threading.Thread(target=start_async_loop, daemon=True).start()

        def generator():
            while True:
                try:
                    line = queue.get(timeout=10)  # Adjust timeout as needed
                    if line is None:
                        break
                    yield line
                except Empty:
                    continue

        response = StreamingHttpResponse(generator(), content_type='text/plain')
        response['Cache-Control'] = 'no-cache'
        return response
    else:
        return redirect('login_user')

#=================================================================================================================
def run_Script_WTF_Shell(request, t_IP_Address):
    if request.user.is_authenticated:
        queue = Queue()
        This_Device  = My_Devices.objects.get(IP_Address=t_IP_Address)
        t_HostName = This_Device.HostName

        async def async_subprocess(queue):
            output_path = Path("./_Log_FW_")
            python_path = get_python_path()
            #python_path = Path("./../venv311/Scripts/python.exe")
            script_path = Path("./app/Scripts/ASA_Check_Config.v.1.py")

            # Use shell to call the Python script and pass arguments directly
            command = f'{python_path} {script_path} -d {t_HostName} > {output_path}{t_HostName}_runlog.txt 2>&1'

            # Create subprocess using create_subprocess_shell
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                while True:
                    line_stdout = await process.stdout.readline()
                    line_stderr = await process.stderr.readline()
                    if line_stdout:
                        queue.put(line_stdout.decode())
                    if line_stderr:
                        queue.put(line_stderr.decode())
                    if not line_stdout and not line_stderr:
                        break                
                await process.wait()
            finally:
                queue.put(None)  # Signal that the subprocess is done

        def start_async_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(async_subprocess(queue))
            loop.close()

        # Start a new thread for the async event loop
        threading.Thread(target=start_async_loop, daemon=True).start()

        # Generator to stream the log output
        def generator():
            while True:
                try:
                    line = queue.get(timeout=10)  # Adjust timeout as needed
                    if line is None:
                        break
                    yield line
                except Empty:
                    continue

        # Create a StreamingHttpResponse to stream the log
        response = StreamingHttpResponse(generator(), content_type='text/plain')
        response['Cache-Control'] = 'no-cache'
        return response
    else:
        return redirect('login_user')

#=================================================================================================================
def get_Fetching_Config_Spinner_status(request, FW_NAME):
    spinner_status = My_Devices.objects.filter(HostName=FW_NAME).values('Fetching_Config_Spinner').values_list('Fetching_Config_Spinner', flat=True).first()
    return JsonResponse({'is_visible': spinner_status})

#=================================================================================================================
def get_Processing_Conf_Spinner_status(request, FW_NAME):
    spinner_status = My_Devices.objects.filter(HostName=FW_NAME).values('Processing_Conf_Spinner').values_list('Processing_Conf_Spinner', flat=True).first()
    return JsonResponse({'is_visible': spinner_status})

#=================================================================================================================
""" 
def Test_Streaming(request, FW_NAME):
    #Devices_list = My_Devices.objects.all().order_by('HostName')

    FW_NAME_slash = FW_NAME.replace('___','/')
    Devices_list = My_Devices.objects.all().order_by('HostName')
    This_Device  = My_Devices.objects.get(HostName=FW_NAME)
    Watch_FName = '%s/%s-ObjNet_Not_Applied-Watch-Copy.html' %(FW_NAME,FW_NAME)
    Think_FName = '%s/%s-ObjNet_Not_Applied-Think.html' %(FW_NAME,FW_NAME)
    Fix_FName   = '%s/%s-ObjNet_Not_Applied-Fix-Copy.html'   %(FW_NAME,FW_NAME)
    Merge_FName = '%s/%s-ObjNet_Not_Applied-Merge.txt'  %(FW_NAME,FW_NAME)
    return render (request, 'Test_Streaming.html', 
        {
        'FW_NAME'       : FW_NAME,
        'FW_NAME_slash' : FW_NAME_slash,
        'This_Device'   : This_Device,
        'Devices_list'  : Devices_list,
        'Watch_FName'   : Watch_FName,
        'Think_FName'   : Think_FName,
        'Fix_FName'     : Fix_FName,
        'Merge_FName'   : Merge_FName,
        }) 
"""

#=================================================================================================================
# Generate Inactive NAT Text File
'''
def inactivenat_txt(request, FW_NAME):
    FW_NAME_slash = FW_NAME.replace('___','/')
    My_Global_Settings = list(Global_Settings.objects.all().filter(Name='Global_Settings').values())[0]
    t_Max_NAT_Inactive_Age = My_Global_Settings['Max_NAT_Inactive_Age']
    t_Days_Delta = timezone.now() - timezone.timedelta(days=t_Max_NAT_Inactive_Age)
    Filtered_NAT1 = Show_NAT_DB.objects.filter(Q(Last_Seen__lt=t_Days_Delta) & Q(HostName=FW_NAME_slash) & Q(inactive='inactive'))
    This_Device   = My_Devices.objects.get(HostName=FW_NAME)
        
    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=inactivenat_dyn.txt'
    
    #---Watch---
    lines = []
    lines.append('\n %s NAT over %s (%s%%) have been inactive for more than %s days and can be deleted\n\n' %(This_Device.N_NAT_Inactive_toDel,
                                                                                                       This_Device.N_NAT_Inactive, 
                                                                                                       This_Device.Prct_N_NAT_Inactive_toDel(),
                                                                                                       t_Max_NAT_Inactive_Age))
    lines.append(f'|{"Days":^6}|{"Section":^9}|{" NAT"}\n')
    lines.append('|------|---------|---------\n')
    
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    t_today = datetime.date(int(today.split('-')[0]),int(today.split('-')[1]),int(today.split('-')[2]))
    for t_NAT in Filtered_NAT1:
        t_Days = (t_today-t_NAT.Last_Seen).days
        t_Section = '[%s|%s]' %(t_NAT.Section,t_NAT.Line_N)
        lines.append(f'|{t_Days:^6}|{t_Section:^9}|{t_NAT.Nat_Line}\n')
        
    #---Think---
    Filtered_NAT2 = Show_NAT_DB.objects.filter(Q(Last_Seen__gte=t_Days_Delta) & Q(HostName=FW_NAME_slash) & Q(inactive='inactive'))
    if len(Filtered_NAT2) > 0:
        lines.append('\n\nThe following are still aging...\n\n')
        lines.append(f'|{"Days":^6}|{"Section":^9}|{" NAT"}\n')
        lines.append('|------|---------|---------\n')
        for t_NAT in Filtered_NAT2:
            t_Days = (t_today-t_NAT.Last_Seen).days
            t_Section = '[%s|%s]' %(t_NAT.Section,t_NAT.Line_N)
            lines.append(f'|{t_Days:^6}|{t_Section:^9}|{t_NAT.Nat_Line}\n')
            
    # ---Fix---
    lines.append('\n\nRemove Old Lines:\n\n')
    for t_NAT in Filtered_NAT1:
        t_Section = t_NAT.Section
        if t_Section == 1:
            lines.append('no nat %s\n' %t_NAT.Nat_Line.replace(') to (',','))
        elif t_Section == 2:
            lines.append('to be implemented --- remove object nat for\n %s\n' %t_NAT.Nat_Line)
        elif t_Section == 3:
            temp = ('no nat %s\n' %t_NAT.Nat_Line.replace(') to (',','))
            lines.append(temp.replace(') ',') after-auto '))        

    response.writelines(lines)
    return response
'''

#=================================================================================================================
import os
import platform
from pathlib import Path

def get_python_path():
    """
    Dynamically determine the Python executable path based on the system.
    """
    if platform.system() == "Windows":
        python_path = Path("./../venv311/Scripts/python.exe")
    elif platform.system() == "Linux":
        # Linux system (e.g., Docker, local Linux)
        if "DOCKER" in os.environ:
            python_path = Path("./../venv311/bin/python")  # Typical Python path in Docker
        else:
            python_path = Path("./../venv311/bin/python")  # Local Linux virtual environment
    else:
        # MacOS or other systems
        python_path = Path("./../venv311/bin/python")
    
    print(f"Using Python path: {python_path}")
    return python_path


#=================================================================================================================
def Color_Line(IN_Line):
    Red_Words    = ['no', 'NEW','|','i','ip','any','any4','clear','tcp','udp','ip','icmp','deny','(hitcnt=0)','inactive','shutdown','address','standby','route','ssh','circular-buffer','[Capturing','0']
    Blu_Words    = ['interface','access-group','access-list','host','network','nat','route','show','run','unidirectional']
    Green_Words  = ['in','log','description','logging','permit']
    Purple_Words = ['configure', 'extended', 'service','protocol','capture']
    Brown_Words  = ['network-object','source','dynamic','static','destination','object-group','object','port-object','policy-map','match','to','eq','line','range']
    Red_Color    = '#ba1e28'
    Blu_Color    = '#1e25ba'
    Green_Color  = '#1cb836'
    Purple_Color = '#8f1489'
    Brown_Color  = '#995c00'

    OUT_Line = ''
    for t_word in IN_Line.split():
        if t_word in Blu_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Blu_Color, t_word)
        elif t_word in Red_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Red_Color, t_word)
        elif t_word in Green_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Green_Color, t_word)
        elif t_word in Purple_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Purple_Color, t_word)
        elif t_word in Brown_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Brown_Color, t_word)
        else:
            OUT_Line = OUT_Line + '%s ' %t_word
    return OUT_Line
