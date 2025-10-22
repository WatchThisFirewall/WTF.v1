from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import Sum, Max
from django.utils import timezone
from datetime import timedelta, datetime
from django.core.validators import validate_slug
import datetime

# Create your models here.
#----------------------------------------------------------------------------------------------------------
class Devices_Model(models.Model):
    Cisco = 'Cisco'
    PaloAlto = 'PaloAlto'
    Vendors__ = [
        (Cisco, 'Cisco'),
        (PaloAlto, 'PaloAlto'),
    ]
    #Device_Vendor    = models.CharField('Vendor Name', max_length=120)
    Device_Vendor    = models.CharField('Vendor Name', max_length=20, choices=Vendors__, default=Cisco)
    Device_Model     = models.CharField('Device Model', max_length=120)
    Default_Username = models.CharField(max_length=120, blank=True)
    Default_Password = models.CharField(max_length=120, blank=True)

    class Meta:
        managed = True
        db_table = 'Devices_Model'
        verbose_name = 'Devices_Model'
        verbose_name_plural = 'Devices_Model'

    def __str__(self):
        return '%s - %s' % (self.Device_Vendor, self.Device_Model)

#----------------------------------------------------------------------------------------------------------
class Default_Credentials(models.Model):
    Name                 = models.CharField(max_length=20, default='Default_Credentials', editable=False)
    Username             = models.CharField(max_length=120, null=True, blank=True, default='')
    Password             = models.CharField(max_length=120, null=True, blank=True, default='')

    class Meta:
        managed = True
        db_table = 'Default_Credentials'
        verbose_name = 'Default_Credentials'
        verbose_name_plural = 'Default_Credentials'

    def __str__(self):
        return str(self.Name)

#----------------------------------------------------------------------------------------------------------
class Global_Settings(models.Model):
    Name                 = models.CharField(max_length=16, default='Global_Settings', editable=False)
        
    Max_Capture_Age      = models.IntegerField(default=20)
    Max_Port_Range       = models.IntegerField(default=10)
    Max_IPv4_Range       = models.IntegerField(default=10)
    Min_Hitcnt_Threshold = models.IntegerField(default=20)
    Max_ACL_HitCnt0_Age  = models.IntegerField(default=180)
    Max_ACL_Inactive_Age = models.IntegerField(default=180)
    Max_ACL_Expand_Ratio = models.IntegerField(default=100)
    N_ACL_Most_Triggered = models.IntegerField(default=10)
    
    Max_NAT_ZeroHit_Age  = models.IntegerField(default=180)
    Max_NAT_Inactive_Age = models.IntegerField(default=180)
    Min_NAT_Hitcnt_Threshold = models.IntegerField(default=20)
    N_NAT_Most_Triggered = models.IntegerField(default=10)
    
    WTFLog_Duration_Days = models.IntegerField(default=100)

    class Meta:
        managed = True
        db_table = 'Global_Settings'
        verbose_name = 'Global_Settings'
        verbose_name_plural = 'Global_Settings'

    def __str__(self):
        return str(self.Name)

#----------------------------------------------------------------------------------------------------------
class My_Devices(models.Model):
    #ID          = models.SmallAutoField(primary_key=True)
    HostName    = models.CharField(max_length=120, unique=True, validators=[validate_slug])
    IP_Address  = models.GenericIPAddressField(primary_key=True)
    Username    = models.CharField(max_length=120, null=True, blank=True)
    Password    = models.CharField(max_length=120, null=True, blank=True)
    Enabled     = models.BooleanField(default=True)
    Type        = models.ForeignKey(Devices_Model, on_delete=models.CASCADE)
    Hardware    = models.CharField(max_length=120, null=True, blank=True)
    SW_Version  = models.CharField(max_length=120, null=True, blank=True)
    # -------------- dashboard variables start ----------------
    Last_Check               = models.DateField(null=True, blank=True, default=datetime.date(2000, 1, 1))
    TimeStamp_t0             = models.DateTimeField(null=True, blank=True, default=datetime.datetime(2000, 1, 1, 1, 0))
    TimeStamp_t1             = models.DateTimeField(null=True, blank=True, default=datetime.datetime(2000, 1, 1, 1, 0))
    Delta_TimeStamps         = models.CharField(max_length=120, null=False, blank=False, default='')
    UpTime                   = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Check_Duration           = models.DurationField(default=timedelta(0))
    Fetching_Config_Spinner  = models.BooleanField(default=False)
    Processing_Conf_Spinner  = models.BooleanField(default=False)

    Config_Diff_Added_Lines  = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Config_Diff_Remvd_Lines  = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Config_Total_Lines       = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_Not_Ascii              = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Unused_ACL               = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Declared_ACL             = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Percent_Unused_ACL       = models.FloatField  (null=True, blank=True, default=0)
    Declared_NAT             = models.PositiveBigIntegerField(null=True, blank=True, default=0)

    N_Interfaces             = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_Interfaces_NoACL       = models.PositiveBigIntegerField(null=True, blank=True, default=0)

    N_Capture                = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_Capture_CircBuff       = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_Capture_Active         = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_Capture_Old            = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    
    N_OBJ_NET_Declared       = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_NET_Unapplied      = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_NET_Duplicated     = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_GRP_NET_Declared   = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_GRP_NET_Unapplied  = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_GRP_NET_Duplicated = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_SVC_Declared       = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_SVC_Unapplied      = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_SVC_Duplicated     = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_GRP_SVC_Declared   = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_GRP_SVC_Unapplied  = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_OBJ_GRP_SVC_Duplicated = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    SUM_OBJ_Declared         = models.PositiveBigIntegerField(null=True, blank=True, default=0)

    N_ACL_Lines              = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Lines_Expanded     = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_NoLog              = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_LogDisabled        = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_HitCnt_Zero        = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_HitCnt_Zero_toDel  = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Inactive           = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Inactive_toDel     = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Active             = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Remarks            = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Oversize           = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Oversize_Expanded  = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Prct_ACL_Space_TCP       = models.FloatField  (default=0)
    Prct_ACL_Space_UDP       = models.FloatField  (default=0)
    Prct_ACL_Space_ICMP      = models.FloatField  (default=0)

    Max_Range_IP             = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    Max_Range_Port           = models.PositiveBigIntegerField(null=True, blank=True, default=0)

    N_NAT_Lines              = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_TrHit_0            = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_UnHit_0            = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_HitCnt_Zero        = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_HitCnt_Zero_toDel  = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_Inactive           = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_Inactive_toDel     = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_Average_Position   = models.FloatField  (null=True, blank=True, default=0)
    N_NAT_Incremented        = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_Resetted           = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_Deleted            = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_New                = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_Sum_Delta          = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_NAT_Sum_Delta_sorted   = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    
    N_Total_Routes           = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_Redun_Routes           = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    
    #RUN_Time_CHOICES         = [(f"{hour:02}:00", f"{hour:02}:00") for hour in range(24)]
    RUN_Time_CHOICES         = [(f"{hour:02}:{minute:02}", f"{hour:02}:{minute:02}") for hour in range(24) for minute in (0, 30)]
    RUN_Last_Run_Time        = models.DateTimeField(null=True, blank=True)
    RUN_Day_of_Week          = models.CharField(
        max_length=20,
        choices=[
            ('MON', 'Monday'),
            ('TUE', 'Tuesday'),
            ('WED', 'Wednesday'),
            ('THU', 'Thursday'),
            ('FRI', 'Friday'),
            ('SAT', 'Saturday'),
            ('SUN', 'Sunday')
        ],
        default='MON',
    )
    RUN_Time_of_Day = models.CharField(
        max_length=5, 
        choices=RUN_Time_CHOICES,
        default="00:30"
    )
    RUN_Enabled     = models.BooleanField(default=True)
    # -------------- dashboard variables end ------------------

    class Meta:
        managed = True
        db_table = 'My_Devices'
        verbose_name = 'My_Devices'
        verbose_name_plural = 'My_Devices'

    def __str__(self):
        #return self.HostName
        return '%s | %s | %s' % (self.HostName, self.Type, self.IP_Address)
    
    def t_Last_Check(self):
        return self.Last_Check.strftime("%Y-%m-%d")
    
    def Check_Duration_display(self):
        total_seconds = int(self.Check_Duration.total_seconds())
        days, remainder = divmod(total_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        parts = []
        #if days > 0:
        #    parts.append(f'{days}d')
        #if hours > 0:
        #    parts.append(f'{hours}h')
        #if minutes > 0:
        #    parts.append(f'{minutes}m')
        #if seconds > 0 or not parts:  # Display seconds if no other parts or if seconds > 0
        #    parts.append(f'{seconds}s')
        
        parts.append(f'{days}d.')
        parts.append(f'{hours}h.')
        parts.append(f'{minutes}m')
        #parts.append(f'{seconds}s')
        return ''.join(parts)

    @property
  
    def HostName_slash(self):
        return self.HostName.replace('___','/')
    
    def Last_Check_Delta(self):
        difference = timezone.now().date() - self.Last_Check
        days_difference = difference.days
        return days_difference
    
    def UpTime_Year(self):
        temp = round(self.UpTime/365,2)
        return temp
    
    def SUM_OBJ_Unapplied(self):
        temp = self.N_OBJ_NET_Unapplied+self.N_OBJ_GRP_NET_Unapplied+self.N_OBJ_SVC_Unapplied+self.N_OBJ_GRP_SVC_Unapplied
        return temp
    
    def Prct_OBJ_NET_Unapplied(self):
        temp = round(self.N_OBJ_NET_Unapplied/self.N_OBJ_NET_Declared*100,1) if self.N_OBJ_NET_Declared else 0
        return temp
            
    def Prct_N_Interfaces_NoACL(self):
        temp = round(self.N_Interfaces_NoACL/self.N_Interfaces*100,1) if self.N_Interfaces else 0
        return temp

    def Prct_N_Capture_Old(self):
        temp = round(self.N_Capture_Old/self.N_Capture*100,1) if self.N_Capture else 0
        return temp
    
    def Prct_N_OBJ_NET_Duplicated(self):
        temp = round(self.N_OBJ_NET_Duplicated/self.N_OBJ_NET_Declared*100,1) if self.N_OBJ_NET_Declared else 0
        return temp

    def Prct_N_OBJ_GRP_NET_Unapplied(self):
        temp = round(self.N_OBJ_GRP_NET_Unapplied/self.N_OBJ_GRP_NET_Declared*100,1) if self.N_OBJ_GRP_NET_Declared else 0
        return temp
    def Prct_N_OBJ_GRP_NET_Duplicated(self):
        temp = round(self.N_OBJ_GRP_NET_Duplicated/self.N_OBJ_GRP_NET_Declared*100,1) if self.N_OBJ_GRP_NET_Declared else 0
        return temp

    def Prct_N_OBJ_SVC_Unapplied(self):
        temp = round(self.N_OBJ_SVC_Unapplied/self.N_OBJ_SVC_Declared*100,1) if self.N_OBJ_SVC_Declared else 0
        return temp
    def Prct_N_OBJ_SVC_Duplicated(self):
        temp = round(self.N_OBJ_SVC_Duplicated/self.N_OBJ_SVC_Declared*100,1) if self.N_OBJ_SVC_Declared else 0
        return temp

    def Prct_N_OBJ_GRP_SVC_Unapplied(self):
        temp = round(self.N_OBJ_GRP_SVC_Unapplied/self.N_OBJ_GRP_SVC_Declared*100,1) if self.N_OBJ_GRP_SVC_Declared else 0
        return temp
    def Prct_N_OBJ_GRP_SVC_Duplicated(self):
        temp = round(self.N_OBJ_GRP_SVC_Duplicated/self.N_OBJ_GRP_SVC_Declared*100,1) if self.N_OBJ_GRP_SVC_Declared else 0
        return temp

    def Prct_N_ACL_NoLog(self):
        temp = round(self.N_ACL_NoLog/self.N_ACL_Active*100,1) if self.N_ACL_Active else 0
        return temp
    def Prct_N_ACL_LogDisabled(self):
        temp = round(self.N_ACL_LogDisabled/self.N_ACL_Active*100,1) if self.N_ACL_Active else 0
        return temp
    def Prct_N_ACL_HitCnt_Zero(self):
        temp = round(self.N_ACL_HitCnt_Zero/self.N_ACL_Active*100,1) if self.N_ACL_Active else 0
        return temp
    def N_ACL_HitCnt_Zero_Aging(self):
        return (self.N_ACL_HitCnt_Zero - self.N_ACL_HitCnt_Zero_toDel)
    def Prct_N_ACL_HitCnt_Zero_toDel(self):
        temp = round(self.N_ACL_HitCnt_Zero_toDel/self.N_ACL_Active*100,1) if self.N_ACL_Active else 0
        return temp
    def Prct_N_ACL_Inactive(self):
        temp = round(self.N_ACL_Inactive/self.N_ACL_Lines*100,1) if self.N_ACL_Lines else 0
        return temp
    def Prct_N_ACL_Inactive_toDel(self):
        temp = round(self.N_ACL_Inactive_toDel/self.N_ACL_Lines*100,1) if self.N_ACL_Lines else 0
        return temp
    def Prct_N_ACL_Oversize(self):
        temp = round(self.N_ACL_Oversize/self.N_ACL_Active*100,1) if self.N_ACL_Lines else 0
        return temp
    def Prct_N_ACL_Oversize_Expanded(self):
        temp = round(self.N_ACL_Oversize_Expanded/self.N_ACL_Lines_Expanded*100,1) if self.N_ACL_Lines_Expanded else 0
        return temp

    def Prct_N_NAT_TrHit_0(self):
        temp = round(self.N_NAT_TrHit_0/self.N_NAT_Lines*100,1) if self.N_NAT_Lines else 0
        return temp
    def Prct_N_NAT_UnHit_0(self):
        temp = round(self.N_NAT_UnHit_0/self.N_NAT_Lines*100,1) if self.N_NAT_Lines else 0
        return temp
    def Prct_N_NAT_Inactive(self):
        temp = round(self.N_NAT_Inactive/self.N_NAT_Lines*100,1) if self.N_NAT_Lines else 0
        return temp
    def Prct_N_NAT_Inactive_toDel(self):
        temp = round(self.N_NAT_Inactive_toDel/self.N_NAT_Lines*100,1) if self.N_NAT_Lines else 0
        return temp
    def Prct_N_NAT_HitCnt_Zero(self):
        temp = round(self.N_NAT_HitCnt_Zero/self.N_NAT_Lines*100,1) if self.N_NAT_Lines else 0
        return temp      
    def Prct_N_NAT_HitCnt_Zero_toDel(self):
        temp = round(self.N_NAT_HitCnt_Zero_toDel/self.N_NAT_Lines*100,1) if self.N_NAT_Lines else 0
        return temp
    def N_NAT_HitCnt_Zero_Aging(self):
        return (self.N_NAT_HitCnt_Zero - self.N_NAT_HitCnt_Zero_toDel)
    def Prct_N_NAT_Sum_Delta_sorted(self):
        temp = round(self.N_NAT_Sum_Delta_sorted/self.N_NAT_Sum_Delta*100,1) if self.N_NAT_Sum_Delta else 0
        return temp
    
    def Prct_N_Redun_Routes(self):
        temp = round(self.N_Redun_Routes/self.N_Total_Routes*100,1) if self.N_Total_Routes else 0
        return temp    
    

#----------------------------------------------------------------------------------------------------------
class Active_Capture(models.Model):
    ID          = models.SmallAutoField(primary_key=True)
    #t_Device    = models.ForeignKey(My_Devices, null=True, blank=True, on_delete=models.CASCADE)
    HostName    = models.CharField(max_length=120, null=True, blank=True, default='')
    Name        = models.CharField(max_length=120, null=True, blank=True, default='')
    First_Seen  = models.DateField()
    Content     = ArrayField(models.CharField(max_length=200, null=True, blank=True, default=''))

    class Meta:
        managed = True
        db_table = 'Active_Capture'
        verbose_name = 'Active_Capture'
        verbose_name_plural = 'Active_Capture'

    def __str__(self):
        #return self.HostName
        return '%s | %s | %s' % (self.HostName, self.First_Seen, self.Name)
    
    @property

    def Capture_Age(self):
        difference = timezone.now().date() - self.First_Seen
        days_difference = difference.days
        return days_difference
    
    #def HostName(self):
    #    return self.t_Device.HostName

#----------------------------------------------------------------------------------------------------------
class ACL_Summary(models.Model):
    HostName          = models.CharField(max_length=120)
    Nameif            = models.CharField(max_length=120, null=True, blank=True)
    ACL_Name          = models.CharField(max_length=120)
    ACL_Length        = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    ACL_ELength       = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_Inactive    = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_NoLog       = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    N_ACL_HitCnt_Zero = models.PositiveBigIntegerField(null=True, blank=True, default=0)
    ACL_Space_ICMP    = models.FloatField(null=True, blank=True, default=0)
    ACL_Space_TCP     = models.FloatField(null=True, blank=True, default=0)
    ACL_Space_UDP     = models.FloatField(null=True, blank=True, default=0)

    class Meta:
        managed = True
        db_table = 'ACL_Summary'
        verbose_name = 'ACL_Summary'
        verbose_name_plural = 'ACL_Summary'

    def __str__(self):
        return '%s' % (self.HostName)

    @property
    def ACL_ELength_X(self):
        temp = round(self.ACL_ELength/self.ACL_Length) if self.ACL_Length else 0
        return temp
    def ACL_Inactive_Percent(self):
        temp = round(self.N_ACL_Inactive/self.ACL_Length*100) if self.ACL_Length else 0
        return temp
    def ACL_NoLog_Percent(self):
        temp = round(self.N_ACL_NoLog/self.ACL_Length*100) if self.ACL_Length else 0
        return temp
    def ACL_HitCnt_Zero_Percent(self):
        temp = round(self.N_ACL_HitCnt_Zero/self.ACL_Length*100) if self.ACL_Length else 0
        return temp

    def ACL_Length_Total(self):
        temp = ACL_Summary.objects.aggregate(Sum('ACL_Length'))
        return temp

#----------------------------------------------------------------------------------------------------------
class Show_NAT_DB(models.Model):
    HostName        = models.CharField(max_length=120)
    Last_Seen       = models.DateField()
    Section         = models.PositiveSmallIntegerField()
    Line_N          = models.PositiveBigIntegerField()
    IF_IN           = models.CharField(max_length=120)
    IF_OUT          = models.CharField(max_length=120)
    StaDin          = models.CharField(max_length=120)
    SRC_IP          = models.CharField(max_length=120)
    SNAT_IP         = models.CharField(max_length=120)
    DST_IP          = models.CharField(max_length=120)
    DNAT_IP         = models.CharField(max_length=120)
    service         = models.CharField(max_length=120)
    SRVC            = models.CharField(max_length=120)
    DSRVC           = models.CharField(max_length=120)
    inactive        = models.CharField(max_length=120)
    Direction       = models.CharField(max_length=120)
    DESC            = models.CharField(max_length=120)
    Tr_Hit          = models.PositiveBigIntegerField()
    Un_Hit          = models.PositiveBigIntegerField()
    Delta_Tr_Hit    = models.PositiveBigIntegerField()
    Delta_Un_Hit    = models.PositiveBigIntegerField()
    Nat_Line        = models.CharField(max_length=3000)
    SRC_Origin      = ArrayField(models.CharField(max_length=120))
    SRC_Natted      = ArrayField(models.CharField(max_length=120))
    DST_Origin      = ArrayField(models.CharField(max_length=120))
    DST_Natted      = ArrayField(models.CharField(max_length=120))

    class Meta:
        managed = True
        db_table = 'Show_NAT_DB'
        verbose_name = 'Show_NAT_DB'
        verbose_name_plural = 'Show_NAT_DB'

    def __str__(self):
        #return self.HostName
        return '%s | %s | %s' % (self.HostName, self.Last_Seen, self.Nat_Line)

#----------------------------------------------------------------------------------------------------------
class ACL_GROSS(models.Model):
    ID          = models.BigAutoField(primary_key=True)  
    HostName    = models.TextField(db_index=True)  
    First_Seen  = models.DateField()
    Name        = models.TextField()
    Line        = models.TextField()
    Type        = models.TextField()
    Action      = models.TextField()
    Service     = models.TextField()
    Source      = models.TextField()
    S_Port      = models.TextField()
    Dest        = models.TextField()
    D_Port      = models.TextField()
    Rest        = models.TextField()
    Inactive    = models.TextField()
    Hitcnt      = models.TextField()
    Hash        = models.TextField()
    Delta_HitCnt = models.BigIntegerField()

    class Meta:
        managed = True
        db_table = 'ACL_GROSS'
        verbose_name = 'ACL_GROSS'
        verbose_name_plural = 'ACL_GROSS'

    def __str__(self):
        return str(self.Name)

#----------------------------------------------------------------------------------------------------------
class ACL_Most_Expanded(models.Model):
    HostName    = models.CharField(max_length=120, null=True, blank=True, default='')
    ACL_Line    = models.TextField()
    ACL_ELength = models.PositiveBigIntegerField(null=True, blank=True, default=0)

    class Meta:
        managed = True
        db_table = 'ACL_Most_Expanded'
        verbose_name = 'ACL_Most_Expanded'
        verbose_name_plural = 'ACL_Most_Expanded'

    def __str__(self):
        return str(self.ACL_Line)
    
#----------------------------------------------------------------------------------------------------------
class Top_IP_Range(models.Model):
    HostName    = models.CharField(max_length=120, null=True, blank=True, default='')
    Obj_Name    = models.CharField(max_length=130, null=True, blank=True, default='')
    IP_Range_Length = models.PositiveBigIntegerField(null=True, blank=True, default=0)

    class Meta:
        managed = True
        db_table = 'Top_IP_Range'
        verbose_name = 'Top_IP_Range'
        verbose_name_plural = 'Top_IP_Range'

    def __str__(self):
        return str(self.HostName + ' ' + self.Obj_Name)

#----------------------------------------------------------------------------------------------------------
class Top_ICMP_Open_Detail(models.Model):
    HostName      = models.CharField(max_length=120, null=True, blank=True, default='')
    ACL_Line      = models.TextField(null=True, blank=True, default='')
    ICMP_Open_Val = models.PositiveBigIntegerField(null=True, blank=True, default=0)

    class Meta:
        managed = True
        db_table = 'Top_ICMP_Open_Detail'
        verbose_name = 'Top_ICMP_Open_Detail'
        verbose_name_plural = 'Top_ICMP_Open_Detail'

    def __str__(self):
        return str(self.HostName + '|' + self.ACL_Line)

#----------------------------------------------------------------------------------------------------------
class Top_TCP_Open_Detail(models.Model):
    HostName      = models.CharField(max_length=120, null=True, blank=True, default='')
    ACL_Line      = models.TextField(null=True, blank=True, default='')
    TCP_Open_Val  = models.DecimalField(max_digits=50, decimal_places=0, null=True, blank=True, default=0)

    class Meta:
        managed = True
        db_table = 'Top_TCP_Open_Detail'
        verbose_name = 'Top_TCP_Open_Detail'
        verbose_name_plural = 'Top_TCP_Open_Detail'

    def __str__(self):
        return str(self.HostName + '|' + self.ACL_Line)

#----------------------------------------------------------------------------------------------------------
class Top_UDP_Open_Detail(models.Model):
    HostName      = models.CharField(max_length=120, null=True, blank=True, default='')
    ACL_Line      = models.TextField(null=True, blank=True, default='')
    UDP_Open_Val  = models.DecimalField(max_digits=50, decimal_places=0, null=True, blank=True, default=0)

    class Meta:
        managed = True
        db_table = 'Top_UDP_Open_Detail'
        verbose_name = 'Top_UDP_Open_Detail'
        verbose_name_plural = 'Top_UDP_Open_Detail'

    def __str__(self):
        return str(self.HostName + '|' + self.ACL_Line)

#----------------------------------------------------------------------------------------------------------
class Top_IP_Open_Detail(models.Model):
    HostName      = models.CharField(max_length=120, null=True, blank=True, default='')
    ACL_Line      = models.TextField(null=True, blank=True, default='')
    IP_Open_Val   = models.DecimalField(max_digits=50, decimal_places=0, null=True, blank=True, default=0)

    class Meta:
        managed = True
        db_table = 'Top_IP_Open_Detail'
        verbose_name = 'Top_IP_Open_Detail'
        verbose_name_plural = 'Top_IP_Open_Detail'

    def __str__(self):
        return str(self.HostName + '|' + self.ACL_Line)

#----------------------------------------------------------------------------------------------------------
class WTF_Log(models.Model):
    TimeStamp = models.DateTimeField(null=True, blank=True, default=datetime.datetime(2000, 1, 1, 1, 0))
    #TimeStamp = models.DateTimeField(auto_now_add=True)
    Level     = models.CharField(max_length=120)
    Message   = models.CharField(max_length=200, null=True, blank=True)

    class Meta:
        managed = True
        db_table = 'WTF_Log'
        verbose_name = 'WTF_Log'
        verbose_name_plural = 'WTF_Log'

    def __str__(self):
        return str(self.Message)

#----------------------------------------------------------------------------------------------------------
class Bad_News(models.Model):
    ID          = models.SmallAutoField(primary_key=True)
    HostName    = models.CharField(max_length=120, null=True, blank=True, default='')
    Tmiestamp   = models.DateField(null=True, blank=True, default=datetime.date(2000, 1, 1))
    Content     = models.TextField(null=True, blank=True, default='')
    Flag        = models.BooleanField(default=False)
    

    class Meta:
        managed = True
        db_table = 'Bad_News'
        verbose_name = 'Bad_News'
        verbose_name_plural = 'Bad_News'

    def __str__(self):
        #return self.HostName
        return '%s | %s | %s' % (self.HostName, self.Tmiestamp, self.Content)

    def t_Tmiestamp(self):
        return self.Tmiestamp.strftime("%Y-%m-%d")

    @classmethod
    def has_bad_news(cls):
        return cls.objects.filter(Flag=True).exists()

#----------------------------------------------------------------------------------------------------------
class TaskStatus(models.Model):
    progress = models.IntegerField(default=0)

    