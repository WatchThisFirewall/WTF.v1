db_Name = 'ASA_Check'
#db_Name = 'WhatchThisFirewall'
PostgreSQL_User = 'postgres'
PostgreSQL_PW = 'postgres'
import os
import platform

#on docker-compose.yml
##services:
##    wtf:
##        environment:
##            - DJANGO_ENV=docker
django_env = os.getenv('DJANGO_RUNTIME', 'local')
if platform.system() == "Windows":
    PostgreSQL_Host = 'localhost'
    PostgreSQL_Port = 5432
else:
    if os.getenv('DJANGO_RUNTIME') == 'docker':
        PostgreSQL_Host = 'db_postgres'
        PostgreSQL_Port = 5432
        db_Name         = os.getenv('POSTGRES_DB')
        PostgreSQL_User = os.getenv('POSTGRES_USER')
        PostgreSQL_PW   = os.getenv('POSTGRES_PASSWORD')
    else:
        PostgreSQL_Host = 'localhost'
        PostgreSQL_Port = 5432

    #engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))

VAR_max_workers = 20
#VAR_max_workers = 8

#log_folder = "../Log_FW"
#Log_Folder_Path = "../../app/templates/"
Log_Folder_Path = "../../"
Err_folder = Log_Folder_Path
log_folder = Log_Folder_Path + "_Log_FW_"
WTF_Error_FName = '__WTF_Error_Log.txt'
t_ErrFileFullName = "%s/%s"%(Err_folder,WTF_Error_FName)
WTF_Error_List = []

Max_Capture_Age      = 20 #days                                          ==> in Global_Settings
# Parameters for Config_Diff
Max_Diff_Log_Age     = 30 #days (Config_Diff older than X are deleted)
Conf_Length_History  = 24 #month to display config length history

# Parameters for Show_NAT_DB
Max_NAT_ZeroHit_Age      = 90 # after X days can be turned inactive      ==> in Global_Settings
Max_NAT_Inactive_Age     = 90 # after X days can be removed              ==> in Global_Settings
Min_NAT_Hitcnt_Threshold = 20 # under this number the NAT is in doubt    ==> in Global_Settings
N_NAT_Most_Triggered     = 20 # top triggered NAT to be moved            ==> in Global_Settings

# @ DB for ACL
Max_ACL_HitCnt0_Age  = 100 # after X days can be turned inactive         ==> in Global_Settings
Max_ACL_Inactive_Age = 100 # after X days can be removed                 ==> in Global_Settings
MIN_Hitcnt_Threshold = 20  # under this number the ACL is in doubt       ==> in Global_Settings
N_ACL_Most_Triggered = 10  # top triggered ACL to be moved               ==> in Global_Settings
Max_ACL_Expand_Ratio = 100 # warn if an ACL line expand greater than X   ==> in Global_Settings

# @ Check_Range
Max_Port_Range  = 10  # Notify when exceeding limit                      ==> in Global_Settings
Max_IPv4_Range  = 1   # Notify when exceeding limit                      ==> in Global_Settings


#=================================================================================================
Red_Words    = ['no', 'NEW','|','i','ip','any','any4','clear','tcp','udp','ip','icmp','range','deny','(hitcnt=0)','inactive','shutdown','address','standby','route','ssh','circular-buffer','[Capturing','0']
Blu_Words    = ['interface','access-group','access-list','host','network','nat','route','show','run','unidirectional']
Green_Words  = ['in','log','description','logging','permit']
Purple_Words = ['configure', 'extended', 'service','protocol','capture']
Brown_Words  = ['network-object','source','dynamic','static','destination','object-group','object','port-object','policy-map','match','to','eq','line','range']
Red_Color    = '#ba1e28'
Blu_Color    = '#1e25ba'
Green_Color  = '#1cb836'
Purple_Color = '#8f1489'
Brown_Color  = '#995c00'
