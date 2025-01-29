
VAR_max_workers = 20
#VAR_max_workers = 8

#log_folder = "../Log_FW"
#Log_Folder_Path = "../../app/templates/"
Log_Folder_Path = "../../"
Err_folder = Log_Folder_Path
log_folder = Log_Folder_Path + "_Log_FW_"
WTF_Error_FName = '__WTF_Error_Log.txt'
WTF_Error_List = []

Max_Capture_Age      = 20 #days                                          ==> in Global_Settings
# Parameters for Config_Diff
Max_Diff_Log_Age     = 30 #days (Config_Diff older than X are deleted)
Conf_Length_History  = 24 #month to display config length history

# Parameters for Show_NAT_DB
Max_NAT_ZeroHit_Age      = 90 # after X days can be turned inactive      ==> in Global_Settings
Max_NAT_Inactive_Age     = 90 # after X days can be removeed             ==> in Global_Settings
Min_NAT_Hitcnt_Threshold = 20 # under this number the NAT is in doubt    ==> in Global_Settings
N_NAT_Most_Triggered     = 20 # top triggered NAT to be moved            ==> in Global_Settings

# @ DB for ACL
Max_ACL_HitCnt0_Age  = 100 # after X days can be turned inactive         ==> in Global_Settings
Max_ACL_Inactive_Age = 100 # after X days can be removeed                ==> in Global_Settings
MIN_Hitcnt_Threshold = 20  # under this number the ACL is in doubt       ==> in Global_Settings
NUM_Most_Triggered   = 10  # top triggered ACL to be moved
Max_ACL_Expand_Ratio = 100 # warn if an ACL line expand greater than X   ==> in Global_Settings

# @ Check_Range
Max_Port_Range  = 10  # warn if higher
Max_IPv4_Range  = 1   # warn if higher


#=================================================================================================
Red_Words    = ['no', 'NEW','|','i','ip','any','clear','tcp','udp','ip','icmp','eq','range','deny','(hitcnt=0)','inactive','shutdown','address','standby','route','ssh','circular-buffer','[Capturing']
Blu_Words    = ['interface','access-group','access-list','host','network','nat','route','show','run','unidirectional']
Green_Words  = ['in','log','description','logging']
Purple_Words = ['configure', 'extended', 'permit','service','protocol','capture']
Brown_Words  = ['network-object','source','dynamic','static','destination','object-group','object','port-object','policy-map','match','to']
Red_Color    = '#ba1e28'
Blu_Color    = '#1e25ba'
Green_Color  = '#1cb836'
Purple_Color = '#8f1489'
Brown_Color  = '#995c00'
