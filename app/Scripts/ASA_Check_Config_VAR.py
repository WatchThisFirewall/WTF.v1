# pylint: disable=C0103

import os
import sys
import shelve
import re
import ipaddress
import datetime
import utils_v2
import sqlalchemy as db
import pandas as pd
import pyarrow
import json

#from tabulate import tabulate
from Network_Calc import *
from ASA_Check_Config_PARAM import *

#from utils_v2 import File_Save_Try

re_space = re.compile(r'  +')
re_empty = re.compile(r'^\s*$') # empty line
##re1 = re.compile(r'(permit|deny) (tcp|icmp|udp|gre|ip|esp|ah|ipsec|ospf)', re.IGNORECASE)
##re4 = re.compile(r'^  access-list .* line', re.IGNORECASE)
re11 = re.compile(r'^access-list .* line \d* extended', re.IGNORECASE)
##re9 = re.compile(r'\(hitcnt=.*')
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

    file_path = os.path.join(log_folder, f"{hostname___}___Show_Nameif.log")
    err_file = os.path.join(Err_folder, WTF_Error_FName)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            l = f.readlines()
    except FileNotFoundError:
        msg = f'File not found: {file_path} @ VAR_Show_Nameif'
        print(msg)
        with open(err_file, 'a+', encoding='utf-8') as f:
            f.write(msg + '\n')
        sys.exit(msg)
    except OSError as e:
        msg = f'Error reading {file_path} @ VAR_Show_Nameif: {e}'
        print(msg)
        with open(err_file, 'a+', encoding='utf-8') as f:
            f.write(msg + '\n')
        sys.exit(msg)

    Nameif_List = []
    for n in range(1,len(l)):
        temp_l = l[n].split()
        if len(temp_l) > 2:
            if (temp_l[0] != 'Interface') and (temp_l[1] != 'Name') and (temp_l[2] != 'Security'):
                Nameif_List.append(temp_l[1])

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Nameif_List")
    retries = utils_v2.Shelve_Write_Try(tf_name,Nameif_List)
    if retries == 3:
        with open(os.path.join(Err_folder, WTF_Error_FName), "a+", encoding="utf-8") as f:
            f.write(f"Cannot write file {os.path.join(log_folder, f'VAR_{hostname___}___Nameif_List')}! @ VAR_Show_Nameif\n")

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

    file_path = os.path.join(log_folder, f"{hostname___}___Show_Run_Access-Group.log")
    err_path = os.path.join(Err_folder, WTF_Error_FName)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            l = f.readlines()
    except FileNotFoundError:
        msg = f"File not found: {file_path} @ VAR_Show_Run_ACGR"
        print(msg)
        with open(err_path, 'a+', encoding='utf-8') as err_file:
            err_file.write(msg + '\n')
        sys.exit(msg)
    except OSError as e:
        msg = f"Error reading {file_path} @ VAR_Show_Run_ACGR: {e}"
        print(msg)
        with open(err_path, 'a+', encoding='utf-8') as err_file:
            err_file.write(msg + '\n')
        sys.exit(msg)

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

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Accessgroup_Dic_by_if")
    retries = utils_v2.Shelve_Write_Try(tf_name, Accessgroup_Dic_by_if)
    if retries == 3:
        msg = f"Cannot write file {tf_name}! @ VAR_Show_Run_ACGR\n"
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(msg)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Accessgroup_Dic_by_ACL")
    retries = utils_v2.Shelve_Write_Try(tf_name,Accessgroup_Dic_by_ACL)
    if retries == 3:
        msg = f"Cannot write file {tf_name}! @ VAR_Show_Run_ACGR\n"
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(msg)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Global_ACL_Dic")
    retries = utils_v2.Shelve_Write_Try(tf_name,Global_ACL_Dic)
    if retries == 3:
        msg = f"Cannot write file {tf_name}! @ VAR_Show_Run_ACGR\n"
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(msg)


#=============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _       ____  __  __  _  _    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )     (  _ \(  )(  )( \( )  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (  ___  )   / )(__)(  )  (    ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)(___)(_)\_)(______)(_)\_)  (___)(___)(_/
#
#=============================================================================================================================

def VAR_Show_Run(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    log_folder = log_folder + '/' + hostname___
    global WTF_Error_FName

    text = f'VAR_Show_Run @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    file_path = os.path.join(log_folder, f"{hostname___}___Show_Running-Config.log")
    err_file = os.path.join(Err_folder, WTF_Error_FName)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            t_file = f.readlines()
    except FileNotFoundError:
        msg = f"File not found: {file_path} @ CREATE VARIABLES"
        print(msg)
        sys.exit(msg)
    except OSError as e:
        msg = f"Error reading {file_path} @ CREATE VARIABLES: {e}"
        print(msg)
        sys.exit(msg)

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
                print (f'\nWARNING from "VAR_Show_Run" for {hostname___}')
                print (f'        ... line "{l}" not processed')
            else:
                this_pm = l.split()[1]
                nn = n+1
                while t_file[nn].startswith(' '):
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
            if this_OBJ_SVC not in OBJ_SVC_Dic:
                OBJ_SVC_Dic[this_OBJ_SVC] = t_file[n+1].strip()
            else:
                print('WARNING!!!!')
                print(f'{this_OBJ_SVC} already in OBJ_SVC_Dic')

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
                print(f'Object "{l.split(" network ")[1]}" already declared! check it out')

        # collect "object-group network"
        elif t_file[n].startswith('object-group network '):
            temp = []
            t_key = l.split(' network ')[1]
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
                print(f'Object "{l.split(" network ")[1]}" already declared! check it out')

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
            if t_key not in Obejct_by_value_Dict:
                Obejct_by_value_Dict[t_key] = [(t_file[n-1].split(' network ')[1]).strip()]
            else:
                Obejct_by_value_Dict[t_key].append(t_file[n-1].split(' network ')[1].strip())
        elif t_file[n].startswith(' range '):
            t_key = (t_file[n].split(' range ')[1]).strip()
            t_val = (t_file[n-1].split(' network ')[1]).strip()
            if t_key not in Obejct_by_value_Dict:
                Obejct_by_value_Dict[t_key] = [t_val]
            else:
                Obejct_by_value_Dict[t_key].append(t_val)
        elif t_file[n].startswith(' fqdn '):
            if ' network ' in t_file[n-1]:
                t_key = (t_file[n].split(' fqdn ')[1]).strip()
                t_val = (t_file[n-1].split(' network ')[1]).strip()
                if t_key not in Obejct_by_value_Dict:
                    Obejct_by_value_Dict[t_key] = [t_val]
                else:
                    Obejct_by_value_Dict[t_key].append(t_val)
        elif t_file[n].startswith(' subnet '):
            t_key = (t_file[n].split(' subnet ')[1]).strip()
            if t_key not in Obejct_by_value_Dict:
                t_key = (t_file[n].split(' subnet ')[1]).strip()
                Obejct_by_value_Dict[t_key] = [(t_file[n-1].split(' network ')[1]).strip()]
            else:
                Obejct_by_value_Dict[t_key].append((t_file[n-1].split(' network ')[1]).strip())

        elif re.match(r'^crypto map .* match address', t_file[n]):
            Crypto_MAP_ACL_List.append(t_file[n].strip().split()[-1])

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Declared_Object_List")
    err_line = f"Can Not Write File {tf_name} @ VAR_Show_Run\n"
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_Object_List)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Crypto_MAP_ACL_List")
    err_line = f"Can Not Write File {tf_name} @ VAR_Show_Run\n"
    retries = utils_v2.Shelve_Write_Try(tf_name,Crypto_MAP_ACL_List)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Declared_OBJ_NET")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_OBJ_NET)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Declared_OBJ_GRP_NET")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_OBJ_GRP_NET)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Used_Object_List")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Used_Object_List)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Obejct_by_value_Dict")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Obejct_by_value_Dict)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Undeclared_NetObj_List")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Undeclared_NetObj_List)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Declared_Object_service")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Declared_Object_service)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Obj_Net_Dic")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Obj_Net_Dic)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___ACL_SplitTunnel_List")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_SplitTunnel_List)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___logging_monitor_line")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,logging_monitor_line)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___ServicePolicy_Lst")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ServicePolicy_Lst)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___PolicyMap_Dct")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,PolicyMap_Dct)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___ClassMap_Dct")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ClassMap_Dct)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___OBJ_GRP_NET_Dic")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_GRP_NET_Dic)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___OBJ_GRP_SVC_Dic")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_GRP_SVC_Dic)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___OBJ_GRP_PRT_Dic")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_GRP_PRT_Dic)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Name_dic")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Name_dic)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___OBJ_SVC_Dic")
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Run\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,OBJ_SVC_Dic)
    if retries == 3:
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(err_line)
        print(err_line)

    return Config_Change


###=======================================================================================================================================================
###  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _      __    ___  ___  ____  ___  ___      __    ____  ___  ____    ___  ___  _
### / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )    /__\  / __)/ __)( ___)/ __)/ __) ___(  )  (_  _)/ __)(_  _)  (___)(___)( \
###( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (    /(__)\( (__( (__  )__) \__ \\__ \(___))(__  _)(_ \__ \  )(     ___  ___  ) )
### \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)  (__)(__)\___)\___)(____)(___/(___/    (____)(____)(___/ (__)   (___)(___)(_/
###=======================================================================================================================================================
##
##
def VAR_Show_Access_List(t_device, Config_Change, log_folder):
    hostname___ = t_device.replace('/','___')
    log_folder = f"{log_folder}/{hostname___}"
    html_folder = log_folder

    text = f'VAR_Show_Access_List @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    start = datetime.datetime.now()
    print(f'start time is {start}')

    tf_name = f"{log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_ACL"
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']

    Show_ACL_Lines = []
    ACL_List_Dict = {}
    ACL_List = []
    ACL_remark_Lines = []

    try:
        with open(f"{log_folder}/{hostname___}___Show_Access-List.log", 'r', encoding='utf-8', errors='ignore') as f:
            pass
    except FileNotFoundError:
        print(f'File not found: {log_folder}/{hostname___}___Show_Access-List.log @ CREATE VARIABLES')
        sys.exit(f'File not found: {log_folder}/{hostname___}___Show_Access-List.log @ CREATE VARIABLES')
    except Exception as e:
        print(f'Unexpected error reading ACL file: {e}')
        sys.exit(f'Unexpected error reading ACL file: {e}')

    with open(f"{log_folder}/{hostname___}___Show_Access-List.log", 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            l = line.rstrip()
            l_parts = l.split()
            if not l.isascii():
                continue

            #re11 = re.compile('^access-list .* line \d* extended', re.IGNORECASE)   # seleziona acl extended only
            if re11.match(l):
                if l_parts[1] not in ACL_List:
                    ACL_List.append(l_parts[1])
                if l_parts[1] in Accessgroup_Dic_by_ACL:
                    if 'remark' not in l:
                        Show_ACL_Lines.append(l)
            #re3 = re.compile('^access-list .* line', re.IGNORECASE) # a questo punto dovrebbero rimanere solo le std acl e remark
            elif re3.match(l):
                if l_parts[1] not in ACL_List:
                    ACL_List.append(l_parts[1])
                if 'remark' in l:
                    ACL_remark_Lines.append(l)

            #re5 = re.compile(r'^\s*$') # empty line
            elif re5.match(l):
                continue

            #re2 = re.compile('access-list .* element', re.IGNORECASE)
            elif re2.match(l):
                continue

            if l_parts[1] in Accessgroup_Dic_by_ACL:
                # re12 = re.compile('.*access-list .* line \d* extended')
                # remove remark
                if re12.match(l):
                    if '(inactive)' not in l:
                        if l.startswith('access-list '):
                            if l not in ACL_List_Dict:
                                if 'object' not in l:
                                    ACL_List_Dict[l] = [l]
                                else:
                                    ACL_List_Dict[l] = []
                                t_Key = l
                                t_ACL_Line = l_parts[3]
                        elif l.startswith('  access-list'):
                            if l_parts[3] == t_ACL_Line:
                                ACL_List_Dict[t_Key].append(l)

    Show_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(Show_ACL_Lines)

    # considering ative lines only...
    t_N_ACL_Lines_Expanded = 0
    t_N_ACL_Oversize_Expanded = 0
    Expanded_ACL_List = [] # Expanded_ACL_List = [['X_Lines', 'ACL']]
    Expanded_ACL_List_bis = [] # Expanded_ACL_List = [['X_Lines', 'Name', 'Line#', 'ACL']]
    ACL_Expanded_DF =  pd.DataFrame()
    cols = ['ACL','Name','Line','Type','Action','Service','Source','S_Port','Dest','D_Port','Rest','Inactive','Hitcnt','Hash']
    df_list = []
    #for t_key in ACL_List_Dict:

    def parse_port(val):
        if isinstance(val, str):
            parts = val.split()
            if val.startswith('range '):
                start = parts[1] if parts[1].isdigit() else Port_Converter.get(parts[1], parts[1])
                end   = parts[2] if parts[2].isdigit() else Port_Converter.get(parts[2], parts[2])
                return [int(start), int(end)]
            if val.startswith('eq '):
                num = parts[1] if parts[1].isdigit() else Port_Converter.get(parts[1], parts[1])
                return [int(num)]
##            else:
##                #print('ERROR in VAR line 665 -------------------------- ')
##        else:
##            #print('ERROR in VAR line 667 --------------------------')
        return [val]

    for t_key, acl_lines in ACL_List_Dict.items():
        if '(inactive)' not in t_key:
            t_N_ACL_Lines_Expanded += len(acl_lines)

            # Expanded_ACL_List --- start
            if len(acl_lines) >= Max_ACL_Expand_Ratio:
                Expanded_ACL_List.append([len(acl_lines), t_key])
                temp = utils_v2.ASA_ACL_to_DF([t_key])
                t_line_N = int(temp.Line[0].split()[1])
                Expanded_ACL_List_bis.append([len(acl_lines), temp.Name[0], t_line_N, t_key])
                t_N_ACL_Oversize_Expanded += len(acl_lines)
            # Expanded_ACL_List --- end

        t_ACL_Expanded_DF = utils_v2.ASA_ACL_to_DF(acl_lines)
        t_ACL_Expanded_DF['Root_Key'] = t_key
        if t_ACL_Expanded_DF.empty:
            print("WARNING!!! Some Object in ACL is empty")
            print(f'----- {t_key}')
            continue

        t_ACL_Expanded_DF['Print'] = (t_ACL_Expanded_DF[cols].astype(str).agg(' '.join, axis=1).str.replace(r'  +', ' ', regex=True))
        t_ACL_Expanded_DF['Source'] = t_ACL_Expanded_DF['Source'].apply(utils_v2.ASA_ACL_Obj_to_DecIP)
        t_ACL_Expanded_DF['Dest']   = t_ACL_Expanded_DF['Dest'].apply(utils_v2.ASA_ACL_Obj_to_DecIP)
        t_ACL_Expanded_DF['S_Port'] = t_ACL_Expanded_DF['S_Port'].apply(parse_port)
        t_ACL_Expanded_DF['D_Port'] = t_ACL_Expanded_DF['D_Port'].apply(parse_port)
        df_list.append(t_ACL_Expanded_DF)
        #ACL_Expanded_DF = pd.concat(df_list, ignore_index=True)
    ACL_Expanded_DF = pd.concat(df_list, ignore_index=True)

    t_N_ACL_Oversize =  len(Expanded_ACL_List)
    # Expanded_ACL_List --- start
    Expanded_ACL_df = pd.DataFrame(Expanded_ACL_List, columns = ['X_Lines' , 'ACL'])
    Expanded_ACL_df = Expanded_ACL_df.sort_values('X_Lines', ascending = False)

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
    DB_Available = True
    try:
        engine = db.create_engine(f"postgresql://{PostgreSQL_User}:{PostgreSQL_PW}@{PostgreSQL_Host}:{PostgreSQL_Port}/{db_Name}")
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
        Updated_Vals = {
                        "N_ACL_Oversize"            : t_N_ACL_Oversize,
                        "N_ACL_Oversize_Expanded"   : t_N_ACL_Oversize_Expanded,
                        "N_ACL_Lines_Expanded"      : t_N_ACL_Lines_Expanded
                        }
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            connection.execute(query)

        delete_stmt = db.delete(ACL_Most_Expanded).where(ACL_Most_Expanded.c.HostName == hostname___)
        with engine.begin() as connection:
            connection.execute(delete_stmt)

        for t_row in Expanded_ACL_df.itertuples():
            Insert_Vals = {
                            "HostName"      : hostname___,
                            "ACL_Line"      : t_row.ACL,
                            "ACL_ELength"   : t_row.X_Lines
                            }
            insert_stmt = ACL_Most_Expanded.insert().values(**Insert_Vals)
            with engine.begin() as connection:
                connection.execute(insert_stmt)

        engine.dispose()

    # OUTPUT HTML FILE

    html_list = []
    html_list.append('<div class="card-body">\n')
    html_list.append('''
       <div style="max-width: 100%; overflow-x: auto;">
       <table class="table-bordered table-condensed table-striped w-auto" id="dataTable" cellspacing="0" data-page-length="50" data-order='[[ 0, "desc" ]]' style="table-layout: auto;">
       ''')
    N_Cols = Expanded_ACL_df.shape[1]
    html_list.append('       <thead><tr>\n')
    for t_col_index in range(0,N_Cols):
        html_list.append(f'           <th class="px-2 text-nowrap">{Expanded_ACL_df.columns[t_col_index]}</th>\n')
    html_list.append('       </tr></thead>\n')
    html_list.append('       <tbody>\n')
    for row in Expanded_ACL_df.itertuples():
        html_list.append('       <tr>\n')
        for t_col_index in range(0,N_Cols):
            if t_col_index == N_Cols-1:
                t_line = Expanded_ACL_df.iloc[row.Index][t_col_index]
                t_line = utils_v2.Color_Line(t_line)
                html_list.append(f'           <td class="px-2 text-nowrap">{t_line}</td>\n')
            else:
                html_list.append(f'           <td class="px-2 text-nowrap">{Expanded_ACL_df.iloc[row.Index][t_col_index]}</td>\n')
        html_list.append('       </tr>\n')
    html_list.append('       </tbody>\n')
    html_list.append('   </table>\n')
    html_list.append('</div>\n')
    html_list.append('</div>\n')

    Watch_FName = hostname___ + '-X_Expanded_ACL-Watch.html'
    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except OSError as e:
            raise OSError(f"Can't create destination directory ({html_folder})! {e}") from e
    try:
        with open(f"{html_folder}/{Watch_FName}",mode="w", encoding="utf-8") as html_file:
            html_file.write(''.join(html_list))
        print(f'... saved file "{html_folder}/{Watch_FName}" ')
    except OSError as e:
        raise OSError(f"Can't write to destination file ({html_folder}/{Watch_FName})! {e}") from e

    t_html_file = []
    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('<table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
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
            t_html_file.append(f'              <code class="text-secondary" style="line-height:1.0; font-size: 1rem">{new_line}</code><br>\n')
        elif row.startswith('<_BTN_>'):
            new_line = row.replace('<_BTN_>','')
            t_html_file.append(f'              {new_line}\n')
        elif '___NEW_LINE_STARTS_HERE__' in row:
            t_html_file.append('           <br></td>\n')
            t_html_file.append('       </tr>\n')
            t_html_file.append('       <tr>\n')
            t_html_file.append('           <td><br>\n')
        else:
            t_line = row
            t_line = utils_v2.Color_Line(t_line)
            t_html_file.append(f'              {t_line}<br>\n')
    t_html_file.append('           <br></td>\n')
    t_html_file.append('       </tr>\n')
    t_html_file.append('       </tbody>\n')
    t_html_file.append('   </table>\n')
    t_html_file.append('</div>\n')

    Fix_FName = hostname___ + '-X_Expanded_ACL-Fix.html'
    try:
        with open(f"{html_folder}/{Fix_FName}", mode="w", encoding="utf-8") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print(f'... saved file "{html_folder}/{Fix_FName}" ')
    except:
        raise OSError(f"Can't write to destination file ({html_folder}/{Fix_FName})!")

    tf_name = f'{log_folder}/VAR_{hostname___}___Show_ACL_Lines'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Show_ACL_Lines)
    if retries == 3:
        print(err_line)
        with open(f'{Err_folder}/{WTF_Error_FName}',"a+") as f:
            f.write(err_line)

    tf_name = f'{log_folder}/VAR_{hostname___}___Show_ACL_Lines_DF'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Show_ACL_Lines_DF)
    if retries == 3:
        print(err_line)
        with open(f'{Err_folder}/{WTF_Error_FName}',"a+") as f:
            f.write(err_line)

    tf_name = f'{log_folder}/VAR_{hostname___}___ACL_List_Dict'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_List_Dict)
    if retries == 3:
        print(err_line)
        with open(f'{Err_folder}/{WTF_Error_FName}',"a+") as f:
            f.write(err_line)

    tf_name = f'{log_folder}/VAR_{hostname___}___ACL_List'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_List)
    if retries == 3:
        print(err_line)
        with open(f'{Err_folder}/{WTF_Error_FName}',"a+") as f:
            f.write(err_line)

    tf_name = f'{log_folder}/VAR_{hostname___}___ACL_remark_Lines'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_remark_Lines)
    if retries == 3:
        print(err_line)
        with open(f'{Err_folder}/{WTF_Error_FName}',"a+") as f:
            f.write(err_line)

    tf_name = f'{log_folder}/VAR_{hostname___}___ACL_Expanded_DF'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    for c in ["S_Port", "D_Port", "Source", "Dest"]:
        if c in ACL_Expanded_DF.columns:
            ACL_Expanded_DF[c] = ACL_Expanded_DF[c].apply(lambda x: json.dumps(x) if isinstance(x, (list, tuple)) else x)
    ACL_Expanded_DF.to_feather(f"{tf_name}.feather", compression="zstd")

    end = datetime.datetime.now()
    print(f'VAR Show_Access_List elapsed time is: {str(end-start)}')
    return Config_Change

#===============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _    ____  _____  __  __  ____  ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )  (  _ \(  _  )(  )(  )(_  _)( ___)  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (    )   / )(_)(  )(__)(   )(   )__)    ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)  (_)\_)(_____)(______) (__) (____)  (___)(___)(_/
#===============================================================================================================================

def VAR_Show_Route(t_device, Config_Change, log_folder):

    def safe_ipv4network(net):
        try:
            return ipaddress.IPv4Network(net)
        except:
            try:
                t_ip_name, t_sm = net.split('/')
                t_ip = Name_dic.get(t_ip_name)
                if t_ip:
                    return ipaddress.IPv4Network(f"{t_ip}/{t_sm}", strict=False)
            except:
                return None

    hostname___ = t_device.replace('/', '___')
    log_folder = f"{log_folder}/{hostname___}"
    file_path = f"{log_folder}/{hostname___}___Show_Route.log"

    tf_name = f"{log_folder}/VAR_{hostname___}___Name_dic"
    Name_dic = utils_v2.Shelve_Read_Try(tf_name,'')

    text = f'VAR_Show_Route @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            t_file = f.readlines()
    except FileNotFoundError:
        msg = f"File not found: {file_path} @ CREATE VARIABLES"
        print(msg)
        sys.exit(msg)
    except OSError as e:
        msg = f"Error opening file {file_path} @ CREATE VARIABLES: {e}"
        print(msg)
        sys.exit(msg)

    ROUTE = []      # this will be the routing table (local)
    t_ROUTE = []    # local
    #Prefix1 = ['S   ','R   ','M   ','B   ','D   ','EX   ','O   ','IA   ','N1   ','N2   ','E1   ','E2   ','V   ','i   ','su   ','L1   ','L2   ','ia   ','U   ','o   ','P   ']
    #Prefix2 = ['S*  ','R*  ','M*  ','B*  ','D*  ','EX*  ','O*  ','IA*  ','N1*  ','N2*  ','E1*  ','E2*  ','V*  ','i*  ','su*  ','L1*  ','L2*  ','ia*  ','U*  ','o*  ','P*  ']
    Prefix1 = {'S   ','R   ','M   ','B   ','D   ','EX   ','O   ','IA   ','N1   ','N2   ','E1   ','E2   ','V   ','i   ','su   ','L1   ','L2   ','ia   ','U   ','o   ','P   '}
    Prefix2 = {p.replace('   ', '*  ') for p in Prefix1}  # auto-build * set

    for n in range(1, len(t_file)):
        temp_line = t_file[n].strip()
        #temp_line = re_space.sub(' ', temp_line)
        prefix = temp_line[0:4]
        if prefix in Prefix1 or prefix in Prefix2:
            if ' connected by VPN ' in t_file[n]:
                temp_line = temp_line.replace(' connected by VPN (advertised), ', ' ') + ' -'
                t_ROUTE.append(temp_line)
                continue
            elif ' is directly connected, ' in t_file[n]:
                temp_line = temp_line.replace(' is directly connected, ', ' ') + ' -'
                t_ROUTE.append(temp_line)
                #print(temp_line)
                continue
            elif ' via ' in t_file[n]:
                pass
            elif ' connected by VPN ' in t_file[n+1]:
                temp_line = temp_line + ' ' + t_file[n+1].strip().split()[-1] + ' -'
                t_ROUTE.append(temp_line)
                continue
            elif ' via ' in t_file[n+1]:
                temp_line = temp_line + ' ' + t_file[n+1].strip()
            else:
                print(f'   =====> Line split to be handled @ line {n}')
                sys.exit(f'   =====> Line split to be handled @ line {n}')
            temp_line = re_space.sub(' ', temp_line)
            temp_line = re.sub(r"\s*\[\d+/0\]\s*", " ", temp_line)
            #temp_line = temp_line.replace(' [1/0] ', ' ')
            temp_line = temp_line.replace(',', '')
            #t1 = temp_line
            t1 = temp_line.split('via')[0]
            #t2 = temp_line
            t2 = temp_line.split('via')[1].split()[1]
            #t3 = temp_line
            t3 = temp_line.split('via')[1].split()[0]
            temp_line = t1 + t2 + ' ' + t3
            #print(temp_line)
            t_ROUTE.append(temp_line)
        elif t_file[n].startswith('C       '):
            if ' is directly connected, ' in t_file[n]:
                temp_line = temp_line + ' -'
            elif ' is directly connected, ' in t_file[n+1]:
                temp_line = temp_line + ' ' + t_file[n+1].strip() + ' -'
            else:
                print(f'   =====> Line split to be handled @ line {n}')
                sys.exit(f'   =====> Line split to be handled @ line {n}')
            #temp_line = temp_line.replace('        ', ' ')
            temp_line = re_space.sub(' ', temp_line)
            temp_line = temp_line.replace(' is directly connected, ', ' ')
            t_ROUTE.append(temp_line)

    ROUTE = [
        [t_device, t0, t1 + Sub_Mask_2[t2], t3, t4]
        for t0, t1, t2, t3, t4 in (line.split() for line in t_ROUTE)
    ]
    ROUTE_DF = pd.DataFrame(ROUTE, columns=['HostName', 'Type', 'Network', 'Interface', 'NextHop'])
    # Vectorized conversion
    ROUTE_DF["Network"] = ROUTE_DF["Network"].apply(safe_ipv4network)

    # Handle failed conversions in bulk

    # Save values in DB @ MY_Devices
    DB_Available = True
    try:
        engine = db.create_engine(f"postgresql://{PostgreSQL_User}:{PostgreSQL_PW}@{PostgreSQL_Host}:{PostgreSQL_Port}/{db_Name}")
        with engine.connect() as connection:
            WTF_Log    = db.Table('WTF_Log',    db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    bad_rows = ROUTE_DF[ROUTE_DF["Network"].isna()]
    if not bad_rows.empty:
        for _, row in bad_rows.iterrows():
            msg = f'ERROR 2193 while converting {row.Network} to ipaddress in {t_device}\n'
            Config_Change.append(msg)
            print(msg)

            log_entry = {
                'TimeStamp': datetime.datetime.now().astimezone(),
                'Level': 'WARNING',
                'Message': msg
            }
            with engine.begin() as connection:
                connection.execute(WTF_Log.insert().values(**log_entry))

        ROUTE_DF = ROUTE_DF.drop(bad_rows.index)

    # Vectorized prefix length extraction
    ROUTE_DF["PrefixLength"] = ROUTE_DF["Network"].map(lambda net: net.prefixlen)
    ROUTE_DF = ROUTE_DF.sort_values(by=['PrefixLength'], ascending=[False]).reset_index(drop=True)


    tf_name = f"{log_folder}/VAR_{hostname___}___ROUTE_DF"
    retries = utils_v2.Shelve_Write_Try(tf_name,ROUTE_DF)
    if retries == 3:
        with open(f"{Err_folder}/{WTF_Error_FName}", "a+") as f:
            msg = f'Cannot write file {tf_name}! @ VAR_Show_Route\n'
            f.write(msg)
            print(msg)

#===============================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _    _  _    __   ____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )  ( \( )  /__\ (_  _)  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (    )  (  /(__)\  )(     ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)  (_)\_)(__)(__)(__)   (___)(___)(_/
#===============================================================================================================================

def VAR_Show_Nat(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    log_folder = os.path.join(log_folder, hostname___)

    file_path = os.path.join(log_folder, f"{hostname___}___Show_Nat_Detail.log")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            t_file = f.readlines()
    except FileNotFoundError:
        msg = f"File not found: {file_path} @ CREATE VARIABLES"
        print(msg)
        sys.exit(msg)

    Show_NAT = []
    col_names = ['Section','Line_N','IF_IN','IF_OUT','StaDin','SRC_IP','SNAT_IP','DST_IP','DNAT_IP','service','SRVC','DSRVC','inactive','Direction','DESC','Tr_Hit','Un_Hit','Nat_Line','SRC_Origin','SRC_Natted','DST_Origin','DST_Natted']

    nat_line0 = re.compile(r'^\d* \((.*?)\) to \((.*?)\) source (static|dynamic) ')
    nat_line1 = re.compile(r'^ *translate_hits = \d+, untranslate_hits = \d+')

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
                if temp in Proto_Map:
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
                print(f'nat line counters expected: {line1}')
                sys.exit(f'nat line counters expected: {line1}')

            nn=n+2
            t_line = ''
            line_nn = t_file[nn].strip() # this_line
            line_nn = re.sub(' +', ' ',line_nn) # remove more than one space

            while not nat_line0.match(line_nn):
                if nn == (len(t_file)-1):
                    break
                elif 'Section' in line_nn:
                    break
                t_line = t_line.strip() + ', ' + line_nn
                nn+=1
                line_nn = t_file[nn].strip() # this_line
                line_nn = re.sub(' +', ' ',line_nn) # remove more than one space
            t_line = re.sub(' \\(PAT\\)', '',t_line)

            if 'Destination - Origin:' in t_line:
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
                if 'Service - Origin:' in t_line:
                    try:
                        Part2 = t_line.split('Destination - Origin:')[1].split('Service - Origin:')[0]
                        Part2 = Part2.replace(',',' ').strip()
                        Part2 = re.sub(' +', ' ',Part2)
                        DST_Origin = Part2.split('Translated:')[0].strip().split()
                        DST_Natted = Part2.split('Translated:')[1].strip().split()
                    except:
                        pass
                elif 'Service - Protocol:' in t_line:
                    try:
                        Part2 = t_line.split('Destination - Origin:')[1].split('Service - Protocol:')[0]
                        Part2 = Part2.replace(',',' ').strip()
                        Part2 = re.sub(' +', ' ',Part2)
                        DST_Origin = Part2.split('Translated:')[0].strip().split()
                        DST_Natted = Part2.split('Translated:')[1].strip().split()
                    except:
                        pass

            elif 'Service - Protocol:' in t_line:
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
            elif 'Service - Origin:' in t_line:
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
    tf_name = f"{log_folder}/VAR_{hostname___}___Show_NAT_DF"
    with shelve.open(tf_name, "c") as shelve_obj: shelve_obj['0'] = Show_NAT_DF

    DB_Available = True
    try:
        engine = db.create_engine(f"postgresql://{PostgreSQL_User}:{PostgreSQL_PW}@{PostgreSQL_Host}:{PostgreSQL_Port}/{db_Name}")
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
            connection.execute(query)
        engine.dispose()

    return Config_Change


#=====================================================================================================================================
#  _  ___  ___    _  _  __    ____                 ___  _   _  _____  _    _       ___  ____  _  _  ____  ____  _____    ___  ___  _
# / )(___)(___)  ( \/ )/__\  (  _ \               / __)( )_( )(  _  )( \/\/ )     / __)(  _ \( \/ )(  _ \(_  _)(  _  )  (___)(___)( \
#( (  ___  ___    \  //(__)\  )   / ___  ___  ___ \__ \ ) _ (  )(_)(  )    (  ___( (__  )   / \  /  )___/  )(   )(_)(    ___  ___  ) )
# \_)(___)(___)    \/(__)(__)(_)\_)(___)(___)(___)(___/(_) (_)(_____)(__/\__)(___)\___)(_)\_) (__) (__)   (__) (_____)  (___)(___)(_/
#=====================================================================================================================================
def VAR_Show_Crypto(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    log_folder = os.path.join(log_folder, hostname___)

    file_path = os.path.join(log_folder, f"{hostname___}___Show_Crypto_Ipsec_Sa_Entry.log")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            t_file = f.readlines()
    except FileNotFoundError:
        msg = f"File not found: {file_path} @ CREATE VARIABLES"
        print(msg)
        sys.exit(msg)

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
    hardware_model = ''
    asa_version = ''
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

        elif n.startswith('Hardware:'):
            hardware_model = n.split()[1]

        elif 'Software Version' in n:
            asa_version = n.split('Software Version')[1].strip()

    DB_Available = True
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

    Updated_Vals = dict(
                        UpTime = t_UpTime,
                        SW_Version = asa_version,
                        Hardware = hardware_model
                        )
    if DB_Available:
        query = db.update(My_Devices).where(My_Devices.c.HostName == hostname___).values(**Updated_Vals)
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
                        if n in Obejct_by_value_Dict:
                            OK_SRC_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            OK_SRC_List.append('host %s' %n)
                    else:
                        if n in Obejct_by_value_Dict:
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
                            if n in Obejct_by_value_Dict:
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object host %s' %n)
                        else:
                            if n in Obejct_by_value_Dict:
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
                        if n in Obejct_by_value_Dict:
                            KO_SRC_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            KO_SRC_List.append('host %s' %n)
                    else:
                        if n in Obejct_by_value_Dict:
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
                            if n in Obejct_by_value_Dict:
                                Splitted_ACL.append('  network-object object %s' %Obejct_by_value_Dict[n][0])
                            else:
                                Splitted_ACL.append('  network-object host %s' %n)
                        else:
                            if n in Obejct_by_value_Dict:
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
                        if n in Obejct_by_value_Dict:
                            OK_DST_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            OK_DST_List.append('host %s' %n)
                    else:
                        if n in Obejct_by_value_Dict:
                            OK_DST_List.append('object %s' %Obejct_by_value_Dict[n][0])
                        else:
                            OK_DST_List.append('%s' %Triggered_Dst[0])
            else:
                T_index = 1
                T_Dst_Name_1 = f'Split_Dst_Obj_{T_index}'
                while T_Dst_Name_1 in Declared_Object_List:
                    T_index += 1
                    T_Dst_Name_1 = f'Split_Dst_Obj_{T_index}'
                else:
                    Declared_Object_List.append(T_Dst_Name_1)
                #print('1st Available dst name is %s' %T_Dst_Name_1)
                OK_DST_List.append('object-group %s' %T_Dst_Name_1)
                Splitted_ACL.append('\nobject-group network %s' %T_Dst_Name_1)
                for n in Triggered_Dst:
                    if 'any' in n:
                        Splitted_ACL.append(n)
                    else:
                        if 'host ' in n:
                            addr = n.split()[1]
                            if addr in Obejct_by_value_Dict:
                                Splitted_ACL.append(f' network-object object {Obejct_by_value_Dict[addr][0]}')
                            else:
                                Splitted_ACL.append(f' network-object host {addr}')
                        else:
                            if n in Obejct_by_value_Dict:
                                Splitted_ACL.append(f' network-object object {Obejct_by_value_Dict[n][0]}')
                            else:
                                Splitted_ACL.append(f' network-object {n}')

        KO_DST_List = []
        if len(Expanded_Dst) > 0:
            dst = Expanded_Dst[0]
            if len(Expanded_Dst) == 1:
                if 'any' in dst:
                    KO_DST_List.append(dst)
                else:
                    n = dst.split()[1]
                    if n in Obejct_by_value_Dict:
                        KO_DST_List.append(f'object {Obejct_by_value_Dict[n][0]}')
                    elif 'host ' in dst:
                        KO_DST_List.append(f'host {n}')
                    else:
                        KO_DST_List.append(dst)

            else:
                T_index = 1
                T_Dst_Name_2 = f'Split_Dst_Obj_{T_index}'
                while T_Dst_Name_2 in Declared_Object_List:
                    T_index += 1
                    T_Dst_Name_2 = f'Split_Dst_Obj_{T_index}'
                else:
                    Declared_Object_List.append(T_Dst_Name_2)
                #print('2nd Available dst name is %s' %T_Dst_Name_2)
                KO_DST_List.append(f"object-group {T_Dst_Name_2}")
                Splitted_ACL.append(f"\nobject-group network {T_Dst_Name_2}")
                for n in Expanded_Dst:
                    if 'any' in n:
                        Splitted_ACL.append(n)
                    elif 'host ' in n:
                        addr = n.split()[1]
                        if addr in Obejct_by_value_Dict:
                            Splitted_ACL.append(f' network-object object {Obejct_by_value_Dict[addr][0]}')
                        else:
                            Splitted_ACL.append(f' network-object host {addr}')
                    elif n in Obejct_by_value_Dict:
                        Splitted_ACL.append(f' network-object object {Obejct_by_value_Dict[n][0]}')
                    else:
                        Splitted_ACL.append(f' network-object {n}')

        #---------------------------------------
        valid_services = {'tcp', 'udp', 'ip', 'icmp'}
        name = t_ACL_Line_df.Name[0]
        line = t_ACL_Line_df.Line[0]
        service = t_ACL_Line_df.Service[0]
        d_port = t_ACL_Line_df.D_Port[0]
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
        tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Declared_Object_List")
        retries = utils_v2.Shelve_Write_Try(tf_name, Declared_Object_List)
        if retries == 3:
            err_file = os.path.join(Err_folder, WTF_Error_FName)
            err_msg = f"Cannot write file {tf_name}! @ Split_Large_ACL\n"
            with open(err_file, "a+", encoding="utf-8") as f:
                f.write(err_msg)

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
