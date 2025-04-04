import shelve
import re
import ipaddress
import html
import datetime
import utils_v2

from tabulate import tabulate
from Network_Calc import *
from ASA_Check_Config_PARAM import *

re_space = re.compile(r'  +')
re_empty = re.compile(r'^\s*$') # empty line
re1 = re.compile(r'(permit|deny) (tcp|icmp|udp|gre|ip|esp|ah|ipsec|ospf)', re.IGNORECASE)
re4 = re.compile(r'^  access-list .* line', re.IGNORECASE)
re11 = re.compile(r'^access-list .* line \d* extended', re.IGNORECASE)
re9 = re.compile(r'\(hitcnt=.*')
re3 = re.compile(r'^access-list .* line', re.IGNORECASE)
re5 = re.compile(r'^\s*$') # empty line
re2 = re.compile(r'access-list .* element', re.IGNORECASE)
re12 = re.compile(r'.*access-list .* line \d* extended')
re_nat = re.compile(r'\(.*\) |nat |after-auto |any |block-allocation |destination |dns |dynamic |extended |flat |inactive |interface |ipv6 |net-to-net |no-proxy-arp |round-robin |route-lookup |service |source |static |unidirectional |description .*')


#=============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _       _  _    __    __  __  ____  ____  ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )     ( \( )  /__\  (  \/  )( ___)(_  _)( ___)  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (  ___  )  (  /(__)\  )    (  )__)  _)(_  )__)    ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)(___)(_)\_)(__)(__)(_/\/\_)(____)(____)(__)    (___)(___)(_/
#=============================================================================================================================

def VAR_Show_Nameif(t_device, Config_Change, log_folder):
    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    log_folder = log_folder + '/' + hostname___
    global WTF_Error_FName

    try:
        with open("%s/%s___Show_Nameif.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            l = f.readlines()
    except:
        print('file %s/%s___Show_Nameif.log not found! @ VAR_Show_Nameif' %(log_folder,hostname___))
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('file %s/%s___Show_Nameif.log not found! @ VAR_Show_Nameif\n' %(log_folder,hostname___))
        exit(0)

    Nameif_List = []
    for n in range(1,len(l)):
        temp_l = l[n].split()
        if len(temp_l) > 2:
            if (temp_l[0] != 'Interface') and (temp_l[1] != 'Name') and (temp_l[2] != 'Security'):
                Nameif_List.append(temp_l[1])

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Nameif_List')
    retries = utils_v2.Shelve_Write_Try(tf_name,Nameif_List)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('Cannot write file %s/VAR_%s___%s! @ VAR_Show_Nameif\n' %(log_folder,hostname___,'Nameif_List'))

#=============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _       ____  __  __  _  _         __    ___  ___  ____  ___  ___        ___  ____  _____  __  __  ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )     (  _ \(  )(  )( \( )       /__\  / __)/ __)( ___)/ __)/ __) ___  / __)(  _ \(  _  )(  )(  )(  _ \  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (  ___  )   / )(__)(  )  (  ___  /(__)\( (__( (__  )__) \__ \\__ \(___)( (_-. )   / )(_)(  )(__)(  )___/   ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)(___)(_)\_)(______)(_)\_)(___)(__)(__)\___)\___)(____)(___/(___/      \___/(_)\_)(_____)(______)(__)    (___)(___)(_/
#
#=============================================================================================================================
def VAR_Show_Run_ACGR(t_device, Config_Change, log_folder):
    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    log_folder = log_folder + '/' + hostname___
    global WTF_Error_FName

    try:
        with open("%s/%s___Show_Run_Access-Group.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            l = f.readlines()
    except:
        print('file %s/%s___Show_Run_Access-Group.log not found! @ VAR_Show_Run_ACGR' %(log_folder,hostname___))
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('file %s/%s___Show_Run_Access-Group.log not found! @ VAR_Show_Run_ACGR\n' %(log_folder,hostname___))
        exit(0)

    Accessgroup_Dic_by_if = {}
    Accessgroup_Dic_by_ACL = {}
    Global_ACL_Dic = {}
    for n in range(1,len(l)):
        if l[n].startswith('access-group'):
            if l[n].split()[-1] not in ['global','per-user-override','control-plane'] :
                Accessgroup_Dic_by_if[l[n].split()[4]] = l[n].split()[1]
                Accessgroup_Dic_by_ACL[l[n].split()[1]] = l[n].split()[4]
            else:
                Global_ACL_Dic['global'] = l[n].split()[1]

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Accessgroup_Dic_by_if')
    retries = utils_v2.Shelve_Write_Try(tf_name,Accessgroup_Dic_by_if)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('Cannot write file %s/VAR_%s___%s! @ VAR_Show_Run_ACGR\n' %(log_folder,hostname___,'Accessgroup_Dic_by_if'))

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    retries = utils_v2.Shelve_Write_Try(tf_name,Accessgroup_Dic_by_ACL)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('Cannot write file %s/VAR_%s___%s! @ VAR_Show_Run_ACGR\n' %(log_folder,hostname___,'Accessgroup_Dic_by_ACL'))

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Global_ACL_Dic')
    retries = utils_v2.Shelve_Write_Try(tf_name,Global_ACL_Dic)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('Cannot write file %s/VAR_%s___%s! @ VAR_Show_Run_ACGR\n' %(log_folder,hostname___,'Global_ACL_Dic'))


#=============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _       ____  __  __  _  _    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )     (  _ \(  )(  )( \( )  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (  ___  )   / )(__)(  )  (    ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)(___)(_)\_)(______)(_)\_)  (___)(___)(_/
#
#=============================================================================================================================

def VAR_Show_Run(t_device, Config_Change, log_folder):
    from utils_v2 import File_Save_Try
    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    log_folder = log_folder + '/' + hostname___
    global WTF_Error_FName
    Not_ascii_L = []

    text = ('VAR_Show_Run @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    try:
        with open("%s/%s___Show_Running-Config.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            t_file = f.readlines()
    except:
        print('file %s/%s___Show_Running-Config.log not found! @ CREATE VARIABLES' %(log_folder,hostname___))
        exit(0)

    Declared_Object_List = []
    Declared_OBJ_NET = []
    Declared_OBJ_GRP_NET = []
    Used_Object_List = []
    Obejct_by_value_Dict = {}
    Undeclared_NetObj_List =[]
    Declared_Object_service = []
    ACL_SplitTunnel_List = []
    logging_monitor_line = ''
    Crypto_MAP_ACL_List = []

    ServicePolicy_Lst = []
    PolicyMap_Dct = {}
    ClassMap_Dct = {}

    Obj_Net_Dic = {}
    OBJ_SVC_Dic = {}
    OBJ_GRP_NET_Dic = {}
    OBJ_GRP_SVC_Dic = {}
    OBJ_GRP_PRT_Dic = {}
    Name_dic = {}

    for n in range(1,len(t_file)):
        l = t_file[n].strip('\n') # this_line

        if re_empty.match(l):
            continue

        elif t_file[n].startswith('logging monitor '):
            logging_monitor_line = l

        elif t_file[n].startswith('service-policy '):
            ServicePolicy_Lst.append(l.split()[1])

        elif t_file[n].startswith('name '):
            Name_dic[l.split()[2]]=l.split()[1]

        elif t_file[n].startswith(' split-tunnel-network-list value '):
            ACL_SplitTunnel_List.append(l.split()[-1])

        elif t_file[n].startswith(' vpn-filter value '):
            ACL_SplitTunnel_List.append(l.split()[-1])

        elif t_file[n].startswith('policy-map '):
            temp = []
            if l.split()[1] == 'type':
                print ('\nWARNING from "VAR_Show_Run" for %s' %hostname___)
                print ('        ... line "%s" not processed' % l)
            else:
                this_pm = l.split()[1]
                nn = n+1
                while (t_file[nn].startswith(' ')):
                    if t_file[nn].startswith(' class '):
                        temp.append(t_file[nn].split()[1])
                    nn = nn+1
                PolicyMap_Dct[this_pm] = temp

        elif t_file[n].startswith('class-map '):
            if 'description' in t_file[n+1]:
                if 'match access-list' in t_file[n+2]:
                    ClassMap_Dct[l.split()[1]] = (t_file[n+2].split()[2]).strip()
                else:
                    ClassMap_Dct[l.split()[1]] = ''
            else:
                if 'match access-list' in t_file[n+1]:
                    ClassMap_Dct[l.split()[1]] = (t_file[n+1].split()[2]).strip()
                else:
                    ClassMap_Dct[l.split()[1]] = ''

        # collect services to remove them from ACLs
        elif t_file[n].startswith('object service '):
            this_OBJ_SVC = l.split(' service ')[1]
            if this_OBJ_SVC not in Declared_Object_service:
                Declared_Object_service.append(this_OBJ_SVC)
            if this_OBJ_SVC not in OBJ_SVC_Dic.keys():
                OBJ_SVC_Dic[this_OBJ_SVC] = t_file[n+1].strip()
            else:
                print('WARNING!!!!')
                print('%s already in OBJ_SVC_Dic.keys()' %this_OBJ_SVC)

        elif t_file[n].startswith('object-group service '):
            temp = []
            t_key = ' '.join(l.split('object-group service ')[1:])
            nn = n+1
            while not (t_file[nn].startswith('object-group ') or t_file[nn].startswith('access-list ')):
                if t_file[nn].startswith(' group-object ') or t_file[nn].startswith(' port-object ') or t_file[nn].startswith(' service-object '):
                    temp.append(t_file[nn].strip())
                nn = nn+1
            OBJ_GRP_SVC_Dic[t_key] = temp

        elif t_file[n].startswith('object-group protocol '):
            temp = []
            t_key = ' '.join(l.split('object-group protocol ')[1:])
            nn = n+1
            while not (t_file[nn].startswith('object-group ') or t_file[nn].startswith('access-list ')):
                if t_file[nn].startswith(' group-object ') or t_file[nn].startswith(' protocol-object '):
                    temp.append(t_file[nn].strip())
                nn = nn+1
            OBJ_GRP_PRT_Dic[t_key] = temp

        # collect Declared_Object_List
        elif t_file[n].startswith('object network '):
            if l.split(' network ')[1] not in Declared_Object_List:
                Declared_Object_List.append(l.split(' network ')[1])
                Declared_OBJ_NET.append((l.split(' network ')[1]).strip())
                Obj_Net_Dic[(l.split(' network ')[1]).strip()] = t_file[n+1].strip()
            elif t_file[n+1].startswith(' nat ('):
                pass
            else:
                print('Object "%s" already declared! check it out' %l.split(' network ')[1])

        # collect "object-group network"
        elif t_file[n].startswith('object-group network '):
            temp = []
            t_key = (l.split(' network ')[1])
            nn = n+1
            while not (t_file[nn].startswith('object-group ') or t_file[nn].startswith('access-list ')):
                if t_file[nn].startswith(' group-object ') or t_file[nn].startswith(' network-object ') :
                    temp.append(t_file[nn].strip())
                nn = nn+1
            OBJ_GRP_NET_Dic[t_key] = temp

            if l.split(' network ')[1] not in Declared_Object_List:
                Declared_Object_List.append((l.split(' network ')[1]))
                Declared_OBJ_GRP_NET.append((l.split(' network ')[1]))
            else:
                print('Object "%s" already declared! check it out' %l.split(' network ')[1])

        # collect Used_Object_List
        elif t_file[n].startswith(' network-object object '):
            t_val = (t_file[n].split(' object ')[1].split()[0]).strip()
            if t_val not in Used_Object_List:
                Used_Object_List.append(t_val)
        elif t_file[n].startswith(' service-object object '):
            t_val = (t_file[n].split(' object ')[1].split()[0]).strip()
            if t_val not in Used_Object_List:
                Used_Object_List.append(t_val)
        elif t_file[n].startswith(' group-object '):
            t_val = (t_file[n].split(' group-object ')[1].split()[0]).strip()
            if t_val not in Used_Object_List:
                Used_Object_List.append(t_val)
        elif t_file[n].startswith('snmp-server host-group '):
            t_val = (t_file[n].split(' host-group ')[1].split()[1]).strip()
            if t_val not in Used_Object_List:
                Used_Object_List.append(t_val)
        elif t_file[n].startswith('access-list '):
            temp = l.replace(' object-group ',' object ')
            temp_split = temp.split(' object ')
            if len(temp_split) > 0:
                for nn in range(1,len(temp_split)):
                    if len(temp_split[nn].split()) > 1:
                        temp_split[nn] = temp_split[nn].split()[0]
                    if temp_split[nn].strip() not in Used_Object_List:
                        Used_Object_List.append(temp_split[nn].split()[0])

        # collect objects in nat
        elif t_file[n].startswith('nat ('):
            this_line = re_nat.sub('', t_file[n])
            t_object = this_line.split()
            for m in t_object:
                if m.strip() not in Used_Object_List:
                     Used_Object_List.append(m.strip())

        elif t_file[n].startswith(' nat ('):
            this_line = re_nat.sub('', t_file[n])
            t_object = this_line.split()
            for m in t_object:
                if m.strip() not in Used_Object_List:
                     Used_Object_List.append(m.strip())

        # collect undeclared network-object used in "object-group network"
        elif t_file[n].startswith(' network-object host '):
            if t_file[n].strip().split(' host ')[1] not in Undeclared_NetObj_List:
                Undeclared_NetObj_List.append((t_file[n].strip().split(' host ')[1]))
        elif t_file[n].startswith(' network-object '):
            t_val = (t_file[n].split(' network-object ')[1]).strip()
            if t_val not in Undeclared_NetObj_List:
                Undeclared_NetObj_List.append(t_val)

        # collect Obejct_by_value_Dict
        elif t_file[n].startswith(' host '):
            t_key = (t_file[n].split(' host ')[1]).strip()
            if t_key not in Obejct_by_value_Dict.keys():
                Obejct_by_value_Dict[t_key] = [(t_file[n-1].split(' network ')[1]).strip()]
            else:
                Obejct_by_value_Dict[t_key].append(t_file[n-1].split(' network ')[1].strip())
        elif t_file[n].startswith(' range '):
            t_key = (t_file[n].split(' range ')[1]).strip()
            t_val = (t_file[n-1].split(' network ')[1]).strip()
            if t_key not in Obejct_by_value_Dict.keys():
                Obejct_by_value_Dict[t_key] = [t_val]
            else:
                Obejct_by_value_Dict[t_key].append(t_val)
        elif t_file[n].startswith(' fqdn '):
            if ' network ' in t_file[n-1]:
                t_key = (t_file[n].split(' fqdn ')[1]).strip()
                t_val = (t_file[n-1].split(' network ')[1]).strip()
                if t_key not in Obejct_by_value_Dict.keys():
                    Obejct_by_value_Dict[t_key] = [t_val]
                else:
                    Obejct_by_value_Dict[t_key].append(t_val)
        elif t_file[n].startswith(' subnet '):
            t_key = (t_file[n].split(' subnet ')[1]).strip()
            if t_key not in Obejct_by_value_Dict.keys():
                t_key = (t_file[n].split(' subnet ')[1]).strip()
                Obejct_by_value_Dict[t_key] = [(t_file[n-1].split(' network ')[1]).strip()]
            else:
                Obejct_by_value_Dict[t_key].append((t_file[n-1].split(' network ')[1]).strip())

        elif re.match(r'^crypto map .* match address', t_file[n]):
            Crypto_MAP_ACL_List.append(t_file[n].strip().split()[-1])

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Declared_Object_List')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_Object_List)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Crypto_MAP_ACL_List')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Crypto_MAP_ACL_List)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Declared_OBJ_NET')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_OBJ_NET)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Declared_OBJ_GRP_NET')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_OBJ_GRP_NET)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Used_Object_List')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Used_Object_List)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Obejct_by_value_Dict')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Obejct_by_value_Dict)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Undeclared_NetObj_List')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Undeclared_NetObj_List)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Declared_Object_service')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_Object_service)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Obj_Net_Dic')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Obj_Net_Dic)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_SplitTunnel_List')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_SplitTunnel_List)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'logging_monitor_line')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,logging_monitor_line)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ServicePolicy_Lst')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ServicePolicy_Lst)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'PolicyMap_Dct')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,PolicyMap_Dct)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ClassMap_Dct')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ClassMap_Dct)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'OBJ_GRP_NET_Dic')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_GRP_NET_Dic)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'OBJ_GRP_SVC_Dic')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_GRP_SVC_Dic)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'OBJ_GRP_PRT_Dic')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_GRP_PRT_Dic)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Name_dic')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Name_dic)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'OBJ_SVC_Dic')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_SVC_Dic)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)
        print(err_line)

    DB_Available = True
    import sqlalchemy as db
    return Config_Change


#=======================================================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _      __    ___  ___  ____  ___  ___      __    ____  ___  ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )    /__\  / __)/ __)( ___)/ __)/ __) ___(  )  (_  _)/ __)(_  _)  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (    /(__)\( (__( (__  )__) \__ \\__ \(___))(__  _)(_ \__ \  )(     ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)  (__)(__)\___)\___)(____)(___/(___/    (____)(____)(___/ (__)   (___)(___)(_/
#=======================================================================================================================================================


def VAR_Show_Access_List(t_device, Config_Change, log_folder):
    re_space = re.compile(r'  +') # two or more spaces
    import pandas as pd
    import os
    hostname___ = t_device.replace('/','___')
    log_folder = log_folder + '/' + hostname___
    html_folder = log_folder
    text = ('VAR_Show_Access_List @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']


    try:
        with open("%s/%s___Show_Access-List.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            t_file = f.readlines()
    except:
        print('file %s/%s___Show_Access-List.log not found! @ CREATE VARIABLES' %(log_folder,hostname___))
        exit(0)

    Source_ACL_Obj_List = {}    # locale
    Show_run_ACL_NoLog_Lst = [] #locale
    Show_ACL_Lines = []
    ACL_List_Dict = {}
    ACL_List = []
    ACL_remark_Lines = []

    for n in range(1,len(t_file)):
        this_host = ''
        l = t_file[n].rstrip()
        if not l.isascii():
            continue

        ##re4 = re.compile('^  access-list .* line', re.IGNORECASE)
        if re4.match(l):
            this_ACL = l.split('  access-list ')[1].split()[0]
            if this_ACL not in Source_ACL_Obj_List.keys():
                Source_ACL_Obj_List[this_ACL] = []

            ##re1 = re.compile('(permit|deny) (tcp|icmp|udp|gre|ip|esp|ipsec|ospf)', re.IGNORECASE)
            this_line = re1.sub('', l)

            if this_line.split(' extended ')[1].split()[0] == 'host':
                this_host = '%s 255.255.255.255' %this_line.split(' host ')[1].split()[0]
                if this_host not in Source_ACL_Obj_List[this_ACL]:
                    Source_ACL_Obj_List[this_ACL].append(this_host)
            elif this_line.split(' extended ')[1].split()[0] == 'any':
                this_host = '0.0.0.0 0.0.0.0'
                if this_host not in Source_ACL_Obj_List[this_ACL]:
                    Source_ACL_Obj_List[this_ACL].append(this_host)
            elif (this_line.split(' extended ')[1].split()[0]).count('.') == 3:
                this_host = ('%s %s') %(this_line.split(' extended ')[1].split()[0],this_line.split(' extended ')[1].split()[1])
                if this_host not in Source_ACL_Obj_List[this_ACL]:
                    Source_ACL_Obj_List[this_ACL].append(this_host)
            elif this_line.split(' extended ')[1].split()[0] == 'range':
                first_host = ipaddress.IPv4Address(this_line.split(' extended ')[1].split()[1])
                last_host  = ipaddress.IPv4Address(this_line.split(' extended ')[1].split()[2])
                temp = first_host
                while temp <= last_host:
                    if (str(temp)+' 255.255.255.255') not in Source_ACL_Obj_List[this_ACL]:
                        Source_ACL_Obj_List[this_ACL].append(str(temp)+' 255.255.255.255')
                    temp = temp + 1
            elif this_line.split(' extended ')[1].split()[0] == 'any4':
                this_host = '0.0.0.0 0.0.0.0'
                if this_host not in Source_ACL_Obj_List[this_ACL]:
                    Source_ACL_Obj_List[this_ACL].append(this_host)
            else:
                print ('2. Unhandled exception @ %s' %this_line)
                Config_Change.append(f'Unhandled Exception: {this_line}')

        ##re11 = re.compile('^access-list .* line \d* extended', re.IGNORECASE)   # seleziona acl extended only
        elif re11.match(l):
            if l.split()[1] not in ACL_List:
                ACL_List.append(l.split()[1])
                Source_ACL_Obj_List[l.split()[1]] = []
            ##re9 = re.compile('\(hitcnt=.*')
            if l.split()[1] in Accessgroup_Dic_by_ACL.keys():
                if 'remark' not in l:
                    Show_ACL_Lines.append(l)
                    if ' inactive' not in l:
                        if (' log ' not in l):
                            Show_run_ACL_NoLog_Lst.append(re9.sub('log',l))
                        elif (' log disable' in l):
                            Show_run_ACL_NoLog_Lst.append('!The following line was having log disabled')
                            temp = (re9.sub('',l)).replace(' log disable ', ' log')
                            Show_run_ACL_NoLog_Lst.append(temp)

        ##re3 = re.compile('^access-list .* line', re.IGNORECASE) # a questo punto dovrebbero rimanere solo le std acl
        elif re3.match(l):
            if l.split()[1] not in ACL_List:
                ACL_List.append(l.split()[1])
                Source_ACL_Obj_List[l.split()[1]] = []
            if 'remark' in l:
                ACL_remark_Lines.append(l)

        ##re5 = re.compile(r'^\s*$') # empty line
        elif re5.match(l):
            continue

        ##re2 = re.compile('access-list .* element', re.IGNORECASE)
        elif re2.match(l):
            continue

        if l.split()[1] in Accessgroup_Dic_by_ACL.keys():
            ##re12 = re.compile('.*access-list .* line \d* extended')
            # remove remark
            if re12.match(l):
                if l.startswith('access-list '):
                    if l not in ACL_List_Dict.keys():
                        if 'object' not in l:
                            ACL_List_Dict[l] = [l]
                        else:
                            ACL_List_Dict[l] = []
                        t_Key = l
                        t_ACL_Line = l.split()[3]
                elif l.startswith('  access-list'):
                    if l.split()[3] == t_ACL_Line:
                        ACL_List_Dict[t_Key].append(l)

    Show_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(Show_ACL_Lines)

    # considering ative lines only...
    t_N_ACL_Lines_Expanded = 0
    t_N_ACL_Oversize_Expanded = 0
    Expanded_ACL_List = [] # Expanded_ACL_List = [['X_Lines', 'ACL']]
    Expanded_ACL_List_bis = [] # Expanded_ACL_List = [['X_Lines', 'Name', 'Line#', 'ACL']]
    ACL_Expanded_DF =  pd.DataFrame()
    for t_key in ACL_List_Dict.keys():
        if '(inactive)' not in t_key:
            t_N_ACL_Lines_Expanded += len(ACL_List_Dict[t_key])

            # Expanded_ACL_List --- start
            if len(ACL_List_Dict[t_key]) >= Max_ACL_Expand_Ratio:
                Expanded_ACL_List.append([len(ACL_List_Dict[t_key]), t_key])
                temp = utils_v2.ASA_ACL_to_DF([t_key])
                t_line_N = int(temp.Line[0].split()[1])
                Expanded_ACL_List_bis.append([len(ACL_List_Dict[t_key]), temp.Name[0], t_line_N, t_key])
                t_N_ACL_Oversize_Expanded = t_N_ACL_Oversize_Expanded + len(ACL_List_Dict[t_key])
            # Expanded_ACL_List --- end

        t_ACL_Expanded_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_key])
        t_ACL_Expanded_DF['Print'] = ''
        t_ACL_Expanded_DF['Root_Key'] = ''
        # convert ip and ports of "t_ACL_Expanded_DF"
        for row1 in t_ACL_Expanded_DF.itertuples():

            t1 = [row1.ACL, row1.Name, row1.Line, row1.Type, row1.Action, row1.Service, row1.Source, row1.S_Port, row1.Dest, row1.D_Port, row1.Rest, row1.Inactive, row1.Hitcnt, row1.Hash]

            t_ACL_Expanded_DF.at[row1.Index, 'Print'] = re_space.sub(' ',' '.join(t1))
            t_ACL_Expanded_DF.at[row1.Index, 'Root_Key'] = t_key

            t_ACL_Expanded_DF.at[row1.Index, 'Source'] = utils_v2.ASA_ACL_Obj_to_DecIP(row1.Source)
            t_ACL_Expanded_DF.at[row1.Index, 'Dest'] = utils_v2.ASA_ACL_Obj_to_DecIP(row1.Dest)
            if 'range ' in row1.S_Port:
                if (row1.S_Port.split()[1]).isdigit() == True:
                    Port_Range_Start = row1.S_Port.split()[1]
                else:
                    Port_Range_Start = Port_Converter[row1.S_Port.split()[1]]
                if (row1.S_Port.split()[2]).isdigit() == True:
                    Port_Range_End = row1.S_Port.split()[2]
                else:
                    Port_Range_End = Port_Converter[row1.S_Port.split()[2]]
                t_ACL_Expanded_DF.at[row1.Index, 'S_Port'] = [int(Port_Range_Start), int(Port_Range_End)]
            elif 'eq ' in row1.S_Port:
                if (row1.S_Port.split()[1]).isdigit() == True:
                    t_ACL_Expanded_DF.at[row1.Index, 'S_Port'] = [int(row1.S_Port.split()[1])]
                else:
                    t_ACL_Expanded_DF.at[row1.Index, 'S_Port'] = [int(Port_Converter[row1.S_Port.split()[1]])]
            else:
                t_ACL_Expanded_DF.at[row1.Index, 'S_Port'] = [row1.S_Port]

            if 'range ' in row1.D_Port:
                if (row1.D_Port.split()[1]).isdigit() == True:
                    Port_Range_Start = row1.D_Port.split()[1]
                else:
                    Port_Range_Start = Port_Converter[row1.D_Port.split()[1]]
                if (row1.D_Port.split()[2]).isdigit() == True:
                    Port_Range_End = row1.D_Port.split()[2]
                else:
                    Port_Range_End = Port_Converter[row1.D_Port.split()[2]]
                t_ACL_Expanded_DF.at[row1.Index, 'D_Port'] = [int(Port_Range_Start), int(Port_Range_End)]
            elif 'eq ' in row1.D_Port:
                if (row1.D_Port.split()[1]).isdigit() == True:
                    t_ACL_Expanded_DF.at[row1.Index, 'D_Port'] = [int(row1.D_Port.split()[1])]
                else:
                    t_ACL_Expanded_DF.at[row1.Index, 'D_Port'] = [int(Port_Converter[row1.D_Port.split()[1]])]
            else:
                t_ACL_Expanded_DF.at[row1.Index, 'D_Port'] = [row1.D_Port]

        ACL_Expanded_DF = pd.concat([ACL_Expanded_DF, t_ACL_Expanded_DF], ignore_index=True)

    t_N_ACL_Oversize =  len(Expanded_ACL_List)
    # Expanded_ACL_List --- start
    Expanded_ACL_df = pd.DataFrame(Expanded_ACL_List, columns = ['X_Lines' , 'ACL'])
    Expanded_ACL_df = Expanded_ACL_df.sort_values('X_Lines', ascending = (False))

    # try to split expanded lines......
    # MUST be sorted by descending line number
    Expanded_ACL_List_bis_df = pd.DataFrame(Expanded_ACL_List_bis, columns = ['X_Lines', 'Name', 'Line#', 'ACL'])
    Expanded_ACL_List_bis_df = Expanded_ACL_List_bis_df.sort_values(['Name', 'Line#'], ascending = (True,False))
    Splitted_ACL = []
    Splitted_ACL_Wrap = []
    for row in Expanded_ACL_List_bis_df.itertuples():
        # if ACL action is "deny" skip the line
        t_row_DF = utils_v2.ASA_ACL_to_DF([row.ACL])
        if t_row_DF.Action[0] == 'deny':
            continue
        Splitted_ACL = Split_Large_ACL(ACL_List_Dict, row.ACL, Max_ACL_Expand_Ratio, log_folder, t_device)

        for n in Splitted_ACL:
            Splitted_ACL_Wrap.append(n)
        Splitted_ACL_Wrap.append('___NEW_LINE_STARTS_HERE__')
    # Expanded_ACL_List --- end

    # Save values in DB @ MY_Devices
    import sqlalchemy as db
    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            ACL_Most_Expanded = db.Table('ACL_Most_Expanded', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    if DB_Available:
        Updated_Vals = dict(
                            N_ACL_Oversize = t_N_ACL_Oversize,
                            N_ACL_Oversize_Expanded = t_N_ACL_Oversize_Expanded,
                            N_ACL_Lines_Expanded = t_N_ACL_Lines_Expanded
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)

        delete_stmt = db.delete(ACL_Most_Expanded).where(ACL_Most_Expanded.c.HostName == hostname___)
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)

        for t_row in Expanded_ACL_df.itertuples():
            Insert_Vals = dict(
                            HostName = hostname___,
                            ACL_Line = t_row.ACL,
                            ACL_ELength = t_row.X_Lines
                            )
            insert_stmt = ACL_Most_Expanded.insert().values(**Insert_Vals)
            with engine.begin() as connection:
                results = connection.execute(insert_stmt)

        engine.dispose()

    # OUTPUT HTML FILE
    Watch_FName = hostname___ + '-X_Expanded_ACL-Watch.html'
    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
             raise OSError("Can't create destination directory (%s)!" % (html_folder))
    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            html_file.write('<div class="card-body">\n')
            html_file.write('''
               <div style="max-width: 100%; overflow-x: auto;">
               <table class="table-bordered table-condensed table-striped w-auto" id="dataTable" cellspacing="0" data-page-length="50" data-order='[[ 0, "desc" ]]' style="table-layout: auto;">
               ''')
            my_index = 0
            N_Cols = Expanded_ACL_df.shape[1]
            html_file.write('       <thead><tr>\n')
            for t_col_index in range(0,N_Cols):
                html_file.write('           <th class="px-2 text-nowrap">%s</th>\n' %Expanded_ACL_df.columns[t_col_index])
            html_file.write('       </tr></thead>\n')
            html_file.write('       <tbody>\n')
            for row in Expanded_ACL_df.itertuples():
                html_file.write('       <tr>\n')
                for t_col_index in range(0,N_Cols):
                    if t_col_index == N_Cols-1:
                        t_line = Expanded_ACL_df.iloc[row.Index][t_col_index]
                        t_line = utils_v2.Color_Line(t_line)
                        html_file.write('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
                    else:
                        html_file.write('           <td class="px-2 text-nowrap">%s</td>\n' %Expanded_ACL_df.iloc[row.Index][t_col_index])
                html_file.write('       </tr>\n')
            html_file.write('       </tbody>\n')
            html_file.write('   </table>\n')
            html_file.write('</div>\n')
            html_file.write('</div>\n')
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

    t_html_file = []
    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('<table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    my_index = 0
    t_html_file.append('''
    <style>
    p.small {
      line-height: 1.0;
      font-family:"Courier New";
      font-size: 1rem;
    }
    </style>''')
    t_html_file.append('       <tbody>\n')
    t_html_file.append('       <tr>\n')
    t_html_file.append('           <td><br>\n')
    for row in Splitted_ACL_Wrap:
        if row == '\n\n':
            continue
        if row.startswith('<_NO_CODE_>'):
            new_line = row.replace('<_NO_CODE_>','')
            new_line = new_line.replace(' ','&nbsp;')
            t_html_file.append('              <code class="text-secondary" style="line-height:1.0; font-size: 1rem">%s</code><br>\n' %new_line)
        elif row.startswith('<_BTN_>'):
            new_line = row.replace('<_BTN_>','')
            t_html_file.append('              %s\n' %new_line)
        elif '___NEW_LINE_STARTS_HERE__' in row:
            t_html_file.append('           <br></td>\n')
            t_html_file.append('       </tr>\n')
            t_html_file.append('       <tr>\n')
            t_html_file.append('           <td><br>\n')
        else:
            t_line = row
            t_line = utils_v2.Color_Line(t_line)
            t_html_file.append('              %s<br>\n' %t_line)
    t_html_file.append('           <br></td>\n')
    t_html_file.append('       </tr>\n')
    t_html_file.append('       </tbody>\n')
    t_html_file.append('   </table>\n')
    t_html_file.append('</div>\n')

    Fix_FName = hostname___ + '-X_Expanded_ACL-Fix.html'
    try:
        with open("%s/%s"%(html_folder,Fix_FName), mode="w", encoding="utf-8") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Fix_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Fix_FName))


    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_ACL_Lines')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Show_ACL_Lines)
    if retries == 3:
        print(err_line)
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_ACL_Lines_DF')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Show_ACL_Lines_DF)
    if retries == 3:
        print(err_line)
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_List_Dict')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_List_Dict)
    if retries == 3:
        print(err_line)
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_List')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_List)
    if retries == 3:
        print(err_line)
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_remark_Lines')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_remark_Lines)
    if retries == 3:
        print(err_line)
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_Expanded_DF')
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_Expanded_DF)
    if retries == 3:
        print(err_line)
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(err_line)

    return Config_Change


#===============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _    ____  _____  __  __  ____  ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )  (  _ \(  _  )(  )(  )(_  _)( ___)  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (    )   / )(_)(  )(__)(   )(   )__)    ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)  (_)\_)(_____)(______) (__) (____)  (___)(___)(_/
#===============================================================================================================================

def VAR_Show_Route(t_device, Config_Change, log_folder):
    from tabulate import tabulate
    import pandas as pd
    hostname___ = t_device.replace('/','___')
    log_folder = log_folder + '/' + hostname___

    re_space = re.compile(r'  +') # two or more spaces
    #print('----- VAR Show Route -----')

    try:
        with open("%s/%s___Show_Route.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            t_file = f.readlines()
    except:
        print('file %s/%s___Show_Route.log not found! @ CREATE VARIABLES' %(log_folder,hostname___))
        exit(0)

    ROUTE = []      # this will be the routing table (local)
    t_ROUTE = []    # local
    Prefix1 = ['S   ','R   ','M   ','B   ','D   ','EX   ','O   ','IA   ','N1   ','N2   ','E1   ','E2   ','V   ','i   ','su   ','L1   ','L2   ','ia   ','U   ','o   ','P   ']
    Prefix2 = ['S*  ','R*  ','M*  ','B*  ','D*  ','EX*  ','O*  ','IA*  ','N1*  ','N2*  ','E1*  ','E2*  ','V*  ','i*  ','su*  ','L1*  ','L2*  ','ia*  ','U*  ','o*  ','P*  ']
    for n in range(1,len(t_file)):
        if ((t_file[n][0:4] in Prefix1) or (t_file[n][0:4] in Prefix2)):
            temp_line = t_file[n]
            if ' connected by VPN ' in t_file[n]:
                temp_line = re_space.sub(' ', temp_line)
                temp_line = temp_line.strip().replace(' connected by VPN (advertised), ', ' ') + ' -'
                t_ROUTE.append(temp_line)
                continue
            elif ' is directly connected, ' in t_file[n]:
                temp_line = re_space.sub(' ', temp_line)
                temp_line = temp_line.replace(' is directly connected, ', ' ') + ' -'
                t_ROUTE.append(temp_line)
                #print(temp_line)
                continue
            elif ' via ' in t_file[n]:
                pass
            elif ' connected by VPN ' in t_file[n+1]:
                temp_line = re_space.sub(' ', temp_line)
                temp_line = temp_line.strip() + ' ' +t_file[n+1].strip().split()[-1] + ' -'
                t_ROUTE.append(temp_line)
                continue
            elif ' via ' in t_file[n+1]:
                temp_line = t_file[n].strip() + ' ' + t_file[n+1].strip()
            else:
                print ('   =====> Line split to be handled @ line %s' %n)
                exit(2)
            temp_line = re_space.sub(' ', temp_line)
            temp_line = temp_line.replace(' [1/0] ', ' ')
            temp_line = temp_line.replace(',', '')
            t1 = temp_line
            t1 = t1.split('via')[0]
            t2 = temp_line
            t2 = t2.split('via')[1].split()[1]
            t3 = temp_line
            t3 = t3.split('via')[1].split()[0]
            temp_line = t1 + t2 + ' ' + t3
            #print(temp_line)
            t_ROUTE.append(temp_line)
        elif t_file[n].startswith('C       '):
            temp_line = t_file[n]
            if ' is directly connected, ' in t_file[n]:
                temp_line = temp_line.strip() + ' -'
            elif ' is directly connected, ' in t_file[n+1]:
                temp_line = t_file[n].strip() + ' ' + t_file[n+1].strip() + ' -'
            else:
                print ('   =====> Line split to be handled @ line %s' %n)
                exit(20)
            #temp_line = temp_line.replace('        ', ' ')
            temp_line = re_space.sub(' ', temp_line)
            temp_line = temp_line.replace(' is directly connected, ', ' ')
            t_ROUTE.append(temp_line)


    for n in range(0,len(t_ROUTE)):
        t_line = t_ROUTE[n].split()
        t_SM = Sub_Mask_2[t_line[2]]
        t_line[2] = t_line[1]+t_SM
        t_line[1] = t_line[0]
        t_line[0] = t_device
        t_ROUTE[n] = t_line

    for n in range(0,len(t_ROUTE)):
        ROUTE.append(t_ROUTE[n])

    ROUTE_DF = pd.DataFrame(ROUTE, columns = ['HostName' , 'Type', 'Network', 'Interface','NextHop'])


    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ROUTE_DF')
    retries = utils_v2.Shelve_Write_Try(tf_name,ROUTE_DF)
    if retries == 3:
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('Cannot write file %s/VAR_%s___%s! @ VAR_Show_Route\n' %(log_folder,hostname___,'ROUTE_DF'))
            print  ('Cannot write file %s/VAR_%s___%s! @ VAR_Show_Route\n' %(log_folder,hostname___,'ROUTE_DF'))


#===============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _    _  _    __   ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )  ( \( )  /__\ (_  _)  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (    )  (  /(__)\  )(     ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)  (_)\_)(__)(__)(__)   (___)(___)(_/
#===============================================================================================================================

def VAR_Show_Nat(t_device, Config_Change, log_folder):
    import pandas as pd
    from tabulate import tabulate
    hostname___ = t_device.replace('/','___')
    log_folder = log_folder + '/' + hostname___

    try:
        with open("%s/%s___Show_Nat_Detail.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            t_file = f.readlines()
    except:
        print('file %s/%s___Show_Nat_Detail.log not found! @ CREATE VARIABLES' %(log_folder,hostname___))
        exit(0)

    Show_NAT = []
    col_names = ['Section','Line_N','IF_IN','IF_OUT','StaDin','SRC_IP','SNAT_IP','DST_IP','DNAT_IP','service','SRVC','DSRVC','inactive','Direction','DESC','Tr_Hit','Un_Hit','Nat_Line','SRC_Origin','SRC_Natted','DST_Origin','DST_Natted']

    nat_line0 = re.compile(r'^\d* \((.*?)\) to \((.*?)\) source (static|dynamic) ')
    nat_line1 = re.compile(r'^ *translate_hits = \d+, untranslate_hits = \d+')

    SRC_Origin_re = re.compile('Source - Origin: (.*?) Translated')
    SRC_Natted_re = re.compile('Translated: (.*?) Destination - Origin')
    DST_Origin_re = re.compile('Destination - Origin: (.*?) Translated')
    DST_Natted_re = re.compile('Translated: (.*?) Destination - Origin')

    t_Section  = ''
    for n in range(1,len(t_file)):
        t_Line_N   = ''
        t_IF_IN    = ''
        t_IF_OUT   = ''
        t_StaDin   = ''
        t_SRC_IP   = ''
        t_SNAT_IP  = ''
        t_DST_IP   = ''
        t_DNAT_IP  = ''
        t_service  = ''
        t_SRVC     = ''
        t_DSRVC    = ''
        t_Inactive = ''
        t_Direction= ''
        t_DESC     = ''
        t_Tr_Hit   = ''
        t_Un_Hit   = ''
        Nat_Line   = ''
        SRC_Origin = []
        SRC_Natted = []
        DST_Origin = []
        DST_Natted = []
        line0 = t_file[n].strip() # this_line
        line0 = re.sub(' +', ' ',line0) # remove more than one space

        if not line0.isascii():
            continue
        if re_empty.match(line0):
            continue
        elif '(Section 0)' in line0:
            t_Section = 0
        elif '(Section 1)' in line0:
            t_Section = 1
        elif '(Section 2)' in line0:
            t_Section = 2
        elif '(Section 3)' in line0:
            t_Section = 3
        elif nat_line0.match(line0):
            line1 = t_file[n+1].strip() # next_line
            line1 = re.sub(' +', ' ',line1) # remove more than one space
            t_line0 = line0.split()
            Nat_Line = ' '.join(t_line0[1:])
            t_Line_N  = t_line0[0]
            t_IF_IN   = t_line0[1].replace('(','').replace(')','')
            if t_IF_IN == 'nlp_int_tap':
                continue
            t_IF_OUT  = t_line0[3].replace('(','').replace(')','')

            if t_line0[5] == 'dynamic':
                t_StaDin  = 'dynamic'
            elif t_line0[5] == 'static':
                t_StaDin  = 'static'
            if 'source static' in line0:
                t_SRC_IP = line0.split('source static')[1].split()[0]
                t_SNAT_IP = line0.split('source static')[1].split()[1]
            elif 'source dynamic' in line0:
                t_SRC_IP = line0.split('source dynamic')[1].split()[0]
                if ' pat-pool ' in line0:
                    t_SNAT_IP = line0.split('source dynamic')[1].split()[2]
                else:
                    t_SNAT_IP = line0.split('source dynamic')[1].split()[1]
            if 'destination static' in line0:
                t_DST_IP = line0.split('destination static')[1].split()[0]
                t_DNAT_IP = line0.split('destination static')[1].split()[1]
            if ' service ' in line0:
                temp = line0.split(' service ')[1].split()[0]
                if temp in Proto_Map.keys():
                    t_service = temp
                    t_SRVC = line0.split(' service ')[1].split()[1]
                    t_DSRVC = line0.split(' service ')[1].split()[2]
                else:
                    t_SRVC = line0.split(' service ')[1].split()[0]
                    t_DSRVC = line0.split(' service ')[1].split()[1]

            if ' inactive' in line0:
                t_Inactive = 'inactive'
            if ' unidirectional' in line0:
                t_Direction = 'unidirectional'
            if ' description ' in line0:
                t_DESC = line0.split(' description ')[1].strip()
            if nat_line1.match(line1):
                t_Tr_Hit = line1.replace(',','').split()[2]
                t_Un_Hit = line1.replace(',','').split()[5]
            else:
                print('nat line counters expected: %s' %line1)
                exit(222)

            nn=n+2
            t_line = ''
            line_nn = t_file[nn].strip() # this_line
            line_nn = re.sub(' +', ' ',line_nn) # remove more than one space

            while not(nat_line0.match(line_nn)):
                if nn == (len(t_file)-1):
                    break
                elif('Section' in line_nn):
                    break
                t_line = t_line.strip() + ', ' + line_nn
                nn+=1
                line_nn = t_file[nn].strip() # this_line
                line_nn = re.sub(' +', ' ',line_nn) # remove more than one space
            t_line = re.sub(' \\(PAT\\)', '',t_line)

            if ('Destination - Origin:' in t_line):
                try:
                    Part1 = t_line.split('Source - Origin:')[1].split('Destination - Origin:')[0]
                    Part1 = Part1.replace(',',' ').strip()
                    Part1 = re.sub(' +', ' ',Part1)
                    SRC_Origin = (Part1.split('Translated:')[0].strip()).split()
                    SRC_Natted = (Part1.split('Translated:')[1].strip()).split()
                    if '-' in SRC_Natted[0]:
                        First_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[0])
                        Last_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[1])
                        SRC_Natted = []
                        while First_IP <= Last_IP:
                            SRC_Natted.append(str(First_IP) + '/32')
                            First_IP = First_IP + 1
                except:
                    pass
                if ('Service - Origin:' in t_line):
                    try:
                        Part2 = t_line.split('Destination - Origin:')[1].split('Service - Origin:')[0]
                        Part2 = Part2.replace(',',' ').strip()
                        Part2 = re.sub(' +', ' ',Part2)
                        DST_Origin = Part2.split('Translated:')[0].strip().split()
                        DST_Natted = Part2.split('Translated:')[1].strip().split()
                    except:
                        pass
                elif ('Service - Protocol:' in t_line):
                    try:
                        Part2 = t_line.split('Destination - Origin:')[1].split('Service - Protocol:')[0]
                        Part2 = Part2.replace(',',' ').strip()
                        Part2 = re.sub(' +', ' ',Part2)
                        DST_Origin = Part2.split('Translated:')[0].strip().split()
                        DST_Natted = Part2.split('Translated:')[1].strip().split()
                    except:
                        pass

            elif ('Service - Protocol:' in t_line):
                try:
                    Part1 = t_line.split('Service - Protocol:')[0]
                    Part1 = Part1.replace(',',' ').strip()
                    Part1 = re.sub(' +', ' ',Part1)
                    SRC_Origin = (Part1.split('Translated:')[0].split('Source - Origin:')[1].strip()).split()
                    SRC_Natted = (Part1.split('Translated:')[1].strip()).split()
                    if '-' in SRC_Natted[0]:
                        First_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[0])
                        Last_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[1])
                        SRC_Natted = []
                        while First_IP <= Last_IP:
                            SRC_Natted.append(str(First_IP) + '/32')
                            First_IP = First_IP + 1
                except:
                    pass
            elif ('Service - Origin:' in t_line):
                try:
                    Part1 = t_line.split('Service - Origin:')[0]
                    Part1 = Part1.replace(',',' ').strip()
                    Part1 = re.sub(' +', ' ',Part1)
                    SRC_Origin = (Part1.split('Translated:')[0].split('Source - Origin:')[1].strip()).split()
                    SRC_Natted = (Part1.split('Translated:')[1].strip()).split()
                    if '-' in SRC_Natted[0]:
                        First_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[0])
                        Last_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[1])
                        SRC_Natted = []
                        while First_IP <= Last_IP:
                            SRC_Natted.append(str(First_IP) + '/32')
                            First_IP = First_IP + 1
                except:
                    pass
            else:
                try:
                    Part1 = t_line
                    Part1 = Part1.replace(',',' ').strip()
                    Part1 = re.sub(' +', ' ',Part1)
                    SRC_Origin = (Part1.split('Translated:')[0].split('Source - Origin:')[1].strip()).split()
                    SRC_Natted = (Part1.split('Translated:')[1].strip()).split()
                    if '-' in SRC_Natted[0]:
                        First_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[0])
                        Last_IP = ipaddress.IPv4Address(SRC_Natted[0].split('-')[1])
                        SRC_Natted = []
                        while First_IP <= Last_IP:
                            SRC_Natted.append(str(First_IP) + '/32')
                            First_IP = First_IP + 1
                except:
                    pass

            Show_NAT.append([t_Section,t_Line_N,t_IF_IN,t_IF_OUT,t_StaDin,t_SRC_IP,t_SNAT_IP,t_DST_IP,t_DNAT_IP,t_service,t_SRVC,t_DSRVC,t_Inactive,t_Direction,t_DESC,t_Tr_Hit,t_Un_Hit,Nat_Line,SRC_Origin,SRC_Natted,DST_Origin,DST_Natted])
        else:
            continue

    Show_NAT_DF = pd.DataFrame(Show_NAT, columns = col_names)
    # delete all nat in Section0
    Show_NAT_DF = Show_NAT_DF.query("Section != 0")
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_NAT_DF')
    with shelve.open(tf_name, "c") as shelve_obj: shelve_obj['0'] = Show_NAT_DF

    DB_Available = True
    import sqlalchemy as db
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    if DB_Available:
        query = db.update(My_Devices).values(Declared_NAT=len(Show_NAT_DF))
        query = query.where(My_Devices.columns.HostName==hostname___)
        with engine.begin() as connection:
            results = connection.execute(query)
        engine.dispose()

    return Config_Change


#=====================================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _       ___  ____  _  _  ____  ____  _____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )     / __)(  _ \( \/ )(  _ \(_  _)(  _  )  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (  ___( (__  )   / \  /  )___/  )(   )(_)(    ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)(___)\___)(_)\_) (__) (__)   (__) (_____)  (___)(___)(_/
#=====================================================================================================================================
def VAR_Show_Crypto(t_device, Config_Change, log_folder):
    import pandas as pd
    from tabulate import tabulate

    hostname___ = t_device.replace('/','___')
    log_folder = log_folder + '/' + hostname___

    try:
        with open("%s/%s___Show_Crypto_Ipsec_Sa_Entry.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            t_file = f.readlines()
    except:
        print('file %s/%s___Show_Crypto_Ipsec_Sa_Entry.log not found! @ CREATE VARIABLES' %(log_folder,hostname___))
        exit(0)

    Show_Crypto = []
    col_names = ['Peer_IP', 'Local_IP', 'Crypto_Map', 'ACL', 'Pkts_Encaps','Pkts_Decaps']

    for n in range(1,len(t_file)):
        l = t_file[n].strip() # this_line
        if not l.isascii():
            continue
        if re_empty.match(l):
            continue
        elif l.startswith('peer address:'):
            t_Peer_IP = l.split()[2]
            if t_Peer_IP== '217.58.213.33':
                print('break')
            nn = n+1
            while not (t_file[nn].startswith('peer address:') or nn==len(t_file)-1):
                if t_file[nn].startswith('    Crypto map tag:'):
                    t_Crypto_Map = re.split('Crypto map tag: |, seq num:|, local addr: ', t_file[nn].strip())[1]
                    t_Local_IP   = re.split('Crypto map tag: |, seq num:|, local addr: ', t_file[nn].strip())[3]
                elif t_file[nn].startswith('      access-list '):
                    t_ACL = t_file[nn].strip()
                elif t_file[nn].startswith('      #pkts encaps:'):
                    t_Pkts_Encaps = re.split('#pkts encaps: |, #pkts encrypt: | #pkts digest: ', t_file[nn].strip())[1]
                elif t_file[nn].startswith('      #pkts decaps:'):
                    t_Pkts_Decaps = re.split('#pkts decaps: |, #pkts decrypt: | #pkts verify: ', t_file[nn].strip())[1]
                    Show_Crypto.append([t_Peer_IP,t_Local_IP,t_Crypto_Map,t_ACL,t_Pkts_Encaps,t_Pkts_Decaps])

                nn += 1

    Show_Crypto_DF = pd.DataFrame(Show_Crypto, columns = col_names)
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_Crypto_DF')
    with shelve.open(tf_name, "c") as shelve_obj: shelve_obj['0'] = Show_Crypto_DF

    Show_Crypto_RemoteNet_List = []
    for row in Show_Crypto_DF.itertuples():
        t_ACL = row.ACL.split()
        if 'host' in t_ACL[-2]:
            t_Remote_Network = t_ACL[-1]+'/32'
        else:
            t_Remote_Network = t_ACL[-2]+Sub_Mask_2[t_ACL[-1]]
        if t_Remote_Network not in Show_Crypto_RemoteNet_List:
            Show_Crypto_RemoteNet_List.append(t_Remote_Network)

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_Crypto_RemoteNet_List')
    with shelve.open(tf_name, "c") as shelve_obj: shelve_obj['0'] = Show_Crypto_RemoteNet_List


#=====================================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _     _  _  ____  ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )   ( \/ )( ___)(  _ \  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (  ___\  /  )__)  )   /   ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)(___)\/  (____)(_)\_)  (___)(___)(_/
#=====================================================================================================================================

# get the device uptime
def VAR_Show_Ver(t_device, Config_Change, log_folder):
    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    log_folder = log_folder + '/' + hostname___
    global WTF_Error_FName

    try:
        with open("%s/%s___Show_Ver.log"%(log_folder,hostname___),'r', encoding='utf-8', errors='ignore') as f:
            l = f.readlines()
    except:
        print('file %s/%s___Show_Ver.log not found! @ VAR_Show_Ver' %(log_folder,hostname___))
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('file %s/%s___Show_Ver.log not found! @ VAR_Show_Ver\n' %(log_folder,hostname___))
            Config_Change.append('file %s/%s___Show_Ver.log not found! @ VAR_Show_Ver\n' %(log_folder,hostname___))
        exit(0)

    Root_hostname = hostname___.split('__')[0]
    t_UpTime = 0
    for n in l:
        if n.startswith('%s up ' %Root_hostname):
            if 'years' in n:
                N_Years = int(n.split(' years ')[0].split()[-1])
                try:
                    N_Days = int(n.split(' days')[0].split()[-1])
                except Exception as e:
                    try:
                        N_Days = int(n.split(' day')[0].split()[-1])
                    except ValueError:
                        print(f'Error while reading uptime: "error is: {e}"')
                t_UpTime = N_Years*365 + N_Days
            elif 'year' in n:
                N_Years = int(n.split(' year ')[0].split()[-1])
                try:
                    N_Days = int(n.split(' days')[0].split()[-1])
                except Exception as e:
                    try:
                        N_Days = int(n.split(' day')[0].split()[-1])
                    except ValueError:
                        print(f'Error while reading uptime: "error is: {e}"')
                t_UpTime = N_Years*365 + N_Days
            elif 'days' in n:
                N_Days  = int(n.split(' days')[0].split()[-1])
                t_UpTime = N_Days
            else:
                t_UpTime = 0

    DB_Available = True
    import sqlalchemy as db
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    if DB_Available:
        query = db.update(My_Devices).values(UpTime=t_UpTime)
        query = query.where(My_Devices.columns.HostName==hostname___)
        with engine.begin() as connection:
            results = connection.execute(query)
        connection.close()
        engine.dispose()

    return Config_Change


##=============================================================================================================================
## ___  ____  __    ____  ____      __      __    ____   ___  ____         __    ___  __
##/ __)(  _ \(  )  (_  _)(_  _)    (  )    /__\  (  _ \ / __)( ___)       /__\  / __)(  )
##\__ \ )___/ )(__  _)(_   )(  ___  )(__  /(__)\  )   /( (_-. )__)  ___  /(__)\( (__  )(__
##(___/(__)  (____)(____) (__)(___)(____)(__)(__)(_)\_) \___/(____)(___)(__)(__)\___)(____)

def Split_Large_ACL(ACL_List_Dict, ACL_Line, Max_ACL_Expand_Ratio, log_folder, t_device):
    hostname___ = t_device.replace('/','___')
    #log_folder = log_folder + '/' + hostname___

    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Declared_Object_List')
    with shelve.open(tf_name) as shelve_obj: Declared_Object_List = shelve_obj['0']
    tf_name = f"{log_folder}/VAR_{hostname___}___Declared_Object_List"
    Declared_Object_List = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Obejct_by_value_Dict')
    with shelve.open(tf_name) as shelve_obj: Obejct_by_value_Dict = shelve_obj['0']

    Splitted_ACL = []
    t_ACL_expanded_df = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[ACL_Line])

    Zero_Rows_df = t_ACL_expanded_df.loc[t_ACL_expanded_df['Hitcnt'] == '0']
    NoZr_Rows_df = t_ACL_expanded_df.loc[t_ACL_expanded_df['Hitcnt'] != '0']
    Splitted_ACL.append('\n\n')
    Splitted_ACL.append('<_BTN_><a class="btn btn-primary btn-icon-split btn-sm"><span class="text">Exploded ACL Length</span><span class="icon text-white-50" style="width:70px;">{:<4}</span></a>'.format(t_ACL_expanded_df.shape[0]) )
    Splitted_ACL.append('<_BTN_><a class="btn btn-success btn-icon-split btn-sm"><span class="text">Triggered ACL      </span><span class="icon text-white-50" style="width:70px;">{:<4}</span></a>'.format(NoZr_Rows_df.shape[0]) )
    Splitted_ACL.append('<_BTN_><a class="btn btn-danger  btn-icon-split btn-sm"><span class="text">Zero Hit ACL       </span><span class="icon text-white-50" style="width:70px;">{:<4}</span></a><br>'.format(Zero_Rows_df.shape[0]) )

    Splitted_ACL.append(ACL_Line)
    t_ACL_Line_df = utils_v2.ASA_ACL_to_DF([ACL_Line])
    Src_Obj_Len = len(t_ACL_expanded_df.Source.unique())
    Expanded_Src = list(t_ACL_expanded_df.Source.unique())
    Expanded_Dst = list(t_ACL_expanded_df.Dest.unique())
    Dst_Obj_Len = len(Expanded_Dst)
    filtered_df = t_ACL_expanded_df.drop_duplicates(subset=['Service', 'D_Port'])
    Svc_and_Port_List = []
    for row in filtered_df.itertuples():
        Svc_and_Port_List.append([row.Service,row.D_Port])
    Triggered_filtered_df = NoZr_Rows_df.drop_duplicates(subset=['Service', 'D_Port'])
    Triggered_Svc_and_Port_List = []
    for row in Triggered_filtered_df.itertuples():
        Triggered_Svc_and_Port_List.append([row.Service,row.D_Port])

    if NoZr_Rows_df.shape[0] == 0:
        Splitted_ACL.append('... wait for it to age out')
    else:
        Triggered_Src = list(NoZr_Rows_df.Source.unique())
        for n in Triggered_Src:
            Expanded_Src.remove(n)
            # Expanded_Src becomes the BAD source
        Triggered_Dst = list(NoZr_Rows_df.Dest.unique())
        for n in Triggered_Dst:
            Expanded_Dst.remove(n)
            # Triggered_Dst becomes the BAD dest

        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Original SRC Length</span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a>'.format(Src_Obj_Len) )
        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Triggered SRC      </span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a>'.format(len(Triggered_Src)) )
        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Zero Hit SRC       </span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a><br>'.format(len(Expanded_Src)) )

        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Original DST Length</span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a>'.format(Dst_Obj_Len) )
        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Triggered DST      </span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a>'.format(len(Triggered_Dst)) )
        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Zero Hit DST       </span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a><br>'.format(len(Expanded_Dst)) )

        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Original SVC Length</span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a>'.format(len(Svc_and_Port_List)) )
        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Triggered SVC      </span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a>'.format(len(Triggered_Svc_and_Port_List)) )
        Splitted_ACL.append('<_BTN_><a class="btn btn-secondary btn-icon-split btn-sm"><span class="text">Zero Hit SVC       </span><span class="icon text-white-50" style="width:50px;">{:<4}</span></a><br>'.format(len(Svc_and_Port_List)-len(Triggered_Svc_and_Port_List)) )

        Splitted_ACL.append('<b>Triggered SRC</b> = %s' %Triggered_Src)
        Splitted_ACL.append('<b>Zero_Hit  SRC</b> = %s' %Expanded_Src)
        Splitted_ACL.append('<b>Triggered DST</b> = %s' %Triggered_Dst)
        Splitted_ACL.append('<b>Zero_Hit  DST</b> = %s' %Expanded_Dst)
        Splitted_ACL.append('<b>Triggered SVC</b> = %s' %Triggered_Svc_and_Port_List)

        OK_SRC_List = []
        if len(Triggered_Src) > 0:
            if len(Triggered_Src) == 1:
                if 'any' in Triggered_Src[0]:
                    OK_SRC_List.append('%s' %Triggered_Src[0])
                else:
                    n = Triggered_Src[0].split()[1]
                    if 'host ' in Triggered_Src[0]:
                        if n in Obejct_by_value_Dict.keys():
                            OK_SRC_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            OK_SRC_List.append('host %s' %n)
                    else:
                        if n in Obejct_by_value_Dict.keys():
                            OK_SRC_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            OK_SRC_List.append('%s' %Triggered_Src[0])
            else:
                T_index = 1
                T_Src_Name_1 = 'Split_Src_Obj_%s' %T_index
                while T_Src_Name_1 in Declared_Object_List:
                    T_index += 1
                    T_Src_Name_1 = 'Split_Src_Obj_%s' %T_index
                else:
                    Declared_Object_List.append(T_Src_Name_1)

                OK_SRC_List.append('object-group %s' %T_Src_Name_1)
                Splitted_ACL.append('\nobject-group network %s' %T_Src_Name_1)
                for n in Triggered_Src:
                    if 'any' in n:
                        Splitted_ACL.append('%s' %n)
                    else:
                        if 'host ' in n:
                            n = n.split()[1]
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object host %s' %n)
                        else:
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object %s' %n)

        KO_SRC_List = []
        if len(Expanded_Src) > 0:
            if len(Expanded_Src) == 1:
                if 'any' in Expanded_Src[0]:
                    KO_SRC_List.append('%s' %Expanded_Src[0])
                else:
                    n = Expanded_Src[0].split()[1]
                    if 'host ' in Expanded_Src[0]:
                        if n in Obejct_by_value_Dict.keys():
                            KO_SRC_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            KO_SRC_List.append('host %s' %n)
                    else:
                        if n in Obejct_by_value_Dict.keys():
                            KO_SRC_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            KO_SRC_List.append('%s' %Expanded_Src[0])
            else:
                T_index = 1
                T_Src_Name_2 = 'Split_Src_Obj_%s' %T_index
                while T_Src_Name_2 in Declared_Object_List:
                    T_index += 1
                    T_Src_Name_2 = 'Split_Src_Obj_%s' %T_index
                else:
                    Declared_Object_List.append(T_Src_Name_2)
                #print('2nd Available src name is %s' %T_Src_Name_2)
                KO_SRC_List.append('object-group %s' %T_Src_Name_2)
                Splitted_ACL.append('\nobject-group network %s' %T_Src_Name_2)
                for n in Expanded_Src:
                    if 'any' in n:
                        Splitted_ACL.append('%s' %n)
                    else:
                        if 'host ' in n:
                            n = n.split()[1]
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object host %s' %n)
                        else:
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object %s' %n)

        OK_DST_List = []
        if len(Triggered_Dst) > 0:
            if len(Triggered_Dst) == 1:
                if 'any' in Triggered_Dst[0]:
                    OK_DST_List.append('%s' %Triggered_Dst[0])
                else:
                    n = Triggered_Dst[0].split()[1]
                    if 'host ' in Triggered_Dst[0]:
                        if n in Obejct_by_value_Dict.keys():
                            OK_DST_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            OK_DST_List.append('host %s' %n)
                    else:
                        if n in Obejct_by_value_Dict.keys():
                            OK_DST_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            OK_DST_List.append('%s' %Triggered_Dst[0])
            else:
                T_index = 1
                T_Dst_Name_1 = 'Split_Dst_Obj_%s' %T_index
                while T_Dst_Name_1 in Declared_Object_List:
                    T_index += 1
                    T_Dst_Name_1 = 'Split_Dst_Obj_%s' %T_index
                else:
                    Declared_Object_List.append(T_Dst_Name_1)
                #print('1st Available dst name is %s' %T_Dst_Name_1)
                OK_DST_List.append('object-group %s' %T_Dst_Name_1)
                Splitted_ACL.append('\nobject-group network %s' %T_Dst_Name_1)
                for n in Triggered_Dst:
                    if 'any' in n:
                        Splitted_ACL.append('%s' %n)
                    else:
                        if 'host ' in n:
                            n = n.split()[1]
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object host %s' %n)
                        else:
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object %s' %n)

        KO_DST_List = []
        if len(Expanded_Dst) > 0:
            if len(Expanded_Dst) == 1:
                if 'any' in Expanded_Dst[0]:
                    KO_DST_List.append('%s' %Expanded_Dst[0])
                else:
                    n = Expanded_Dst[0].split()[1]
                    if 'host ' in Expanded_Dst[0]:
                        if n in Obejct_by_value_Dict.keys():
                            KO_DST_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            KO_DST_List.append('host %s' %n)
                    else:
                        if n in Obejct_by_value_Dict.keys():
                            KO_DST_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            KO_DST_List.append('%s' %Expanded_Dst[0])
            else:
                T_index = 1
                T_Dst_Name_2 = 'Split_Dst_Obj_%s' %T_index
                while T_Dst_Name_2 in Declared_Object_List:
                    T_index += 1
                    T_Dst_Name_2 = 'Split_Dst_Obj_%s' %T_index
                else:
                    Declared_Object_List.append(T_Dst_Name_2)
                #print('2nd Available dst name is %s' %T_Dst_Name_2)
                KO_DST_List.append('object-group %s' %T_Dst_Name_2)
                Splitted_ACL.append('\nobject-group network %s' %T_Dst_Name_2)
                for n in Expanded_Dst:
                    if 'any' in n:
                        Splitted_ACL.append('%s' %n)
                    else:
                        if 'host ' in n:
                            n = n.split()[1]
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object host %s' %n)
                        else:
                            if n in Obejct_by_value_Dict.keys():
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object %s' %n)

        #---------------------------------------

        Splitted_ACL.append('!')
        for t_OK_SRC_List in OK_SRC_List:
            for t_OK_DST_List in OK_DST_List:
                #good lines here (expand ports)
                for t_Svc_and_Por in Svc_and_Port_List:
                    Splitted_ACL.append('access-list %s %s extended permit %s %s %s %s log' %(t_ACL_Line_df.Name[0], t_ACL_Line_df.Line[0], t_Svc_and_Por[0], t_OK_SRC_List, t_OK_DST_List, t_Svc_and_Por[1]))
            Splitted_ACL.append('!')
            for t_KO_DST_List in KO_DST_List:
                #first bad block
                if (t_ACL_Line_df.Service[0] == 'tcp') or (t_ACL_Line_df.Service[0] == 'udp') or (t_ACL_Line_df.Service[0] == 'ip') or (t_ACL_Line_df.Service[0] == 'icmp'):
                    Splitted_ACL.append('access-list %s %s extended permit %s %s %s %s log' %(t_ACL_Line_df.Name[0], t_ACL_Line_df.Line[0], t_ACL_Line_df.Service[0], t_OK_SRC_List, t_KO_DST_List, t_ACL_Line_df.D_Port[0]))
                else:
                    for t_Svc_and_Por in Svc_and_Port_List:
                        Splitted_ACL.append('access-list %s %s extended permit %s %s %s %s log' %(t_ACL_Line_df.Name[0], t_ACL_Line_df.Line[0], t_Svc_and_Por[0], t_OK_SRC_List, t_KO_DST_List, t_Svc_and_Por[1]))
        for t_KO_SRC_List in KO_SRC_List:
            for t_OK_DST_List in OK_DST_List:
                #second bad block
                if (t_ACL_Line_df.Service[0] == 'tcp') or (t_ACL_Line_df.Service[0] == 'udp') or (t_ACL_Line_df.Service[0] == 'ip') or (t_ACL_Line_df.Service[0] == 'icmp'):
                    Splitted_ACL.append('access-list %s %s extended permit %s %s %s %s log' %(t_ACL_Line_df.Name[0], t_ACL_Line_df.Line[0], t_ACL_Line_df.Service[0], t_KO_SRC_List, t_OK_DST_List, t_ACL_Line_df.D_Port[0]))
                else:
                    for t_Svc_and_Por in Svc_and_Port_List:
                        Splitted_ACL.append('access-list %s %s extended permit %s %s %s %s log' %(t_ACL_Line_df.Name[0], t_ACL_Line_df.Line[0], t_Svc_and_Por[0], t_KO_SRC_List, t_OK_DST_List, t_Svc_and_Por[1]))

            for t_KO_DST_List in KO_DST_List:
                #third bad block
                if (t_ACL_Line_df.Service[0] == 'tcp') or (t_ACL_Line_df.Service[0] == 'udp') or (t_ACL_Line_df.Service[0] == 'ip') or (t_ACL_Line_df.Service[0] == 'icmp'):
                    Splitted_ACL.append('access-list %s %s extended permit %s %s %s %s log' %(t_ACL_Line_df.Name[0], t_ACL_Line_df.Line[0], t_ACL_Line_df.Service[0], t_KO_SRC_List, t_KO_DST_List, t_ACL_Line_df.D_Port[0]))
                else:
                    for t_Svc_and_Por in Svc_and_Port_List:
                        Splitted_ACL.append('access-list %s %s extended permit %s %s %s %s log' %(t_ACL_Line_df.Name[0], t_ACL_Line_df.Line[0], t_Svc_and_Por[0], t_KO_SRC_List, t_KO_DST_List, t_Svc_and_Por[1]))



        # WARNING if source port in ACL....


        tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Declared_Object_List')
        retries = utils_v2.Shelve_Write_Try(tf_name,Declared_Object_List)
        if retries == 3:
            with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
                f.write('Cannot write file %s/VAR_%s___%s! @ Split_Large_ACL\n' %(log_folder,hostname___,'Declared_Object_List'))

        temp_line = []
        temp_line.append(t_ACL_Line_df.ACL[0])
        temp_line.append(t_ACL_Line_df.Name[0])
        temp_line.append(t_ACL_Line_df.Type[0])
        temp_line.append(t_ACL_Line_df.Action[0])
        temp_line.append(t_ACL_Line_df.Service[0])
        temp_line.append(t_ACL_Line_df.Source[0])
        temp_line.append(t_ACL_Line_df.S_Port[0])
        temp_line.append(t_ACL_Line_df.Dest[0])
        temp_line.append(t_ACL_Line_df.D_Port[0])
        temp_line.append(t_ACL_Line_df.Rest[0])
        temp_line.append('inactive')
        Splitted_ACL.append('!')
        Splitted_ACL.append(re_space.sub(' ',' '.join(temp_line)))

    return Splitted_ACL

##=============================================================================================================================
