#!/usr/bin/env python3
# ASA_Check_Config.v.1.py


##asgiref==3.8.1
##bcrypt==4.2.0
##cffi==1.17.0
##cryptography==43.0.0
##Django==4.2.15
##django-background-tasks==1.2.8
##et-xmlfile==1.1.0
##future==1.0.0
##greenlet==3.0.3
##netmiko==4.4.0
##ntc_templates==6.0.0
##numpy==1.23.5
##openpyxl==3.1.5
##pandas==1.5.3
##paramiko==3.4.1
##psycopg2==2.9.9
##pycparser==2.22
##PyNaCl==1.5.0
##pyserial==3.5
##python-dateutil==2.9.0.post0
##pytz==2024.1
##PyYAML==6.0.2
##scp==0.15.0
##six==1.16.0
##SQLAlchemy==2.0.32
##sqlparse==0.5.1
##tabulate==0.9.0
##textfsm==1.1.3
##typing_extensions==4.12.2
##tzdata==2024.1

import os
from pathlib import Path
import sys
import time
import datetime
##import threading
import utils_v2
import re
import shutil
import ipaddress
##import io
import pandas as pd
##import numpy as np
import sqlalchemy as db
import concurrent.futures
#from netmiko import ConnectHandler
from Network_Calc import *
from ASA_Check_Config_FNC import *
from ASA_Check_Config_VAR import *
from ASA_Check_Config_PARAM import *
from tabulate import tabulate

#----------------------------------------------------------------------------------------
# ALL                           = 0
# Unused_Object                 = 1
# Unused_ACL                    = 1
# Duplicated_Objects            = 2
# ObjGrpNet_With1Entry          = 3
# ACL_VS_Interface              = 4
# NO_Log_For_ACL                = 5
# Use_Declared_Objects          = 6 (depends from 2)
# DB_For_ACL                    = 7 (time consuming)
# F_Active_Capture              = 8
# Explicit_Deny_IP_Any_Any      = 9
# ACL_Source_Vs_Routing_Table   = 12 (depends from 7)
# Check_NAT                     = 16
# ACL_Dest_Vs_Routing_Table     = 17
# Check_Range                   = 18

# prod params -------
DEBUG_LEVEL           = 1      #[0 = verbose]
ARGS_SEE_ELAPSED      = True   #[                                                (-e default = True)]
ARGS_FETCH_CONFIG     = True   #[True=Connect_To_Device, False=Read_Local_Files  (-f default = True)]
ARGS_REBUILD_VARS     = True   #[True=Rebuild Variables, False=Skip this session (-r default = True)]
ARGS_PARRALEL_PROCESS = False  #[                                                (-p default = False)]
DELETE_VAR_FILES      = True

#TEST_THIS_ONLY   = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18]
TEST_THIS_ONLY   = [1,2,3,4,5,6,7,8,9,      12,         16,17,18]

### debug params -------
##DEBUG_LEVEL           = 1      #[0 = verbose]
##ARGS_SEE_ELAPSED      = True   #[                                                (-e default = True)]
##ARGS_FETCH_CONFIG     = False  #[True=Connect_To_Device, False=Read_Local_Files  (-f default = True)]
##ARGS_REBUILD_VARS     = True  #[True=Rebuild Variables, False=Skip this session (-r default = True)]
##ARGS_PARRALEL_PROCESS = False  #[                                                (-p default = False)]
##DELETE_VAR_FILES      = False
##TEST_THIS_ONLY   = [12]
#----------------------------------------------------------------------------------------
start_time = time.time()
pd.set_option('display.max_rows', 500)
pd.set_option('display.max_columns', 1000)
pd.set_option('display.width', 1000)


##print(f'PostgreSQL_Host = {PostgreSQL_Host}')
##print(f'PostgreSQL_Port = {PostgreSQL_Port}')
##print(f'db_Name = {db_Name}')
##print(f'PostgreSQL_User = {PostgreSQL_User}')
##print(f'PostgreSQL_PW = {PostgreSQL_PW}')


args = utils_v2.Get_Args()
#print('args = %s' %args)
if args.e == False:
    ARGS_SEE_ELAPSED = False
if args.f == False:
    ARGS_FETCH_CONFIG = False
if args.r == False:
    ARGS_REBUILD_VARS = False
if args.p == True:
    ARGS_PARRALEL_PROCESS = True
if args.d != '':
    ARGS_DEVICE = args.d
else:
    ARGS_DEVICE = False
#----------------------------------------------------------------------------------------

if ARGS_FETCH_CONFIG == True:
    ARGS_REBUILD_VARS = True

if ARGS_PARRALEL_PROCESS == False:
    print('\n\n SERIAL PROCESSING GOING ON !!!!!!\n\n' )
else:
    print('\n\n PARALLEL PROCESSING GOING ON !!!!!!\n\n')

if Path.cwd().parts[-1] == 'Scripts':
    print(f'working dir = {Path.cwd()}')
else:
    script_path = './app/Scripts'
    if os.path.exists(script_path):
        os.chdir(script_path)
        #print("Directory changed successfully.")
        print(f'working dir = {Path.cwd()}')
    else:
        print(f"Directory '{script_path}' does not exist.")
        exit(123)

##max_threads = int(args.threads)
##max_threads = 50

if len(TEST_THIS_ONLY)>=1:
    Running_T0 = datetime.datetime.now()

DB_Available = True
try:
    engine = db.create_engine(f"postgresql://{PostgreSQL_User}:{PostgreSQL_PW}@{PostgreSQL_Host}:{PostgreSQL_Port}/{db_Name}")
    with engine.connect() as connection:
        My_Devices      = db.Table('My_Devices',      db.MetaData(), autoload_with=engine)
        Global_Settings = db.Table('Global_Settings', db.MetaData(), autoload_with=engine)
        Devices_Model   = db.Table('Devices_Model',   db.MetaData(), autoload_with=engine)
        Default_Credentials = db.Table('Default_Credentials', db.MetaData(), autoload_with=engine)

        ACL_GROSS       = db.Table('ACL_GROSS',       db.MetaData(), autoload_with=engine)
        Show_NAT_DB     = db.Table('Show_NAT_DB',     db.MetaData(), autoload_with=engine)
        ACL_Summary     = db.Table('ACL_Summary',     db.MetaData(), autoload_with=engine)
        Active_Capture  = db.Table('Active_Capture',  db.MetaData(), autoload_with=engine)
        WTF_Log         = db.Table('WTF_Log',         db.MetaData(), autoload_with=engine)

except Exception as e:
    print(f"An error occurred: {e}")
    print('DB not connected, some feature is unavailable\n')
    with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
        f.write('=================[ Warning ]==================')
        f.write('DB not connected, some feature is unavailable\n')
        f.write(f"An error occurred: {e}\n")
    DB_Available = False

if DB_Available:
    query = db.select(Global_Settings).where(Global_Settings.c.Name=='Global_Settings')
    with engine.connect() as connection:
        Global_Settings_df = pd.DataFrame(connection.execute(query).fetchall())

    query = db.select(Default_Credentials).where(Default_Credentials.c.Name=='Default_Credentials')
    with engine.connect() as connection:
        Default_Credentials_df = pd.DataFrame(connection.execute(query).fetchall())

    query = db.select(Devices_Model)
    with engine.connect() as connection:
        Devices_Model_df = pd.DataFrame(connection.execute(query).fetchall())
else:
    print('@ MAIN: DB_Available=False')

WTFLog_Duration_Days = int(Global_Settings_df.WTFLog_Duration_Days[0])
#today = datetime.datetime.now().strftime('%Y-%m-%d')

#<===================================================================================================================================================
#  ___  __    ____    __    _  _    _____  __    ____     ____  ____  _  _  ____  ___  ____  ___    ____  ____  _____  __  __    ____  ____
# / __)(  )  ( ___)  /__\  ( \( )  (  _  )(  )  (  _ \   (  _ \( ___)( \/ )(_  _)/ __)( ___)/ __)  ( ___)(  _ \(  _  )(  \/  )  (  _ \(  _ \
#( (__  )(__  )__)  /(__)\  )  (    )(_)(  )(__  )(_) )   )(_) ))__)  \  /  _)(_( (__  )__) \__ \   )__)  )   / )(_)(  )    (    )(_) )) _ <
# \___)(____)(____)(__)(__)(_)\_)  (_____)(____)(____/   (____/(____)  \/  (____)\___)(____)(___/  (__)  (_)\_)(_____)(_/\/\_)  (____/(____/

if DB_Available:
    query = db.select(My_Devices)
    with engine.connect() as connection:
        My_Devices_df = pd.DataFrame(connection.execute(query).fetchall())

    Good_Hostname = list(My_Devices_df.HostName)

    query = db.select(ACL_GROSS).where(~ACL_GROSS.c.HostName.in_(Good_Hostname))
    with engine.connect() as connection:
        t_ACL_GROSS_df = pd.DataFrame(connection.execute(query).fetchall())
    if len(t_ACL_GROSS_df) > 0:
        bad_hostname_list = list(t_ACL_GROSS_df.HostName.unique())
        for t_bad_hostname in bad_hostname_list:
            Log_Message = (f'@ ACL_GROSS: Device {t_bad_hostname} has been deleted!'); print(Log_Message)
            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        delete_stmt = db.delete(ACL_GROSS).where(~ACL_GROSS.c.HostName.in_(Good_Hostname))
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)
        Log_Message = (f"{result.rowcount} row(s) deleted."); print(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    query = db.select(ACL_Summary).where(~ACL_Summary.c.HostName.in_(Good_Hostname))
    with engine.connect() as connection:
        t_ACL_Summary_df = pd.DataFrame(connection.execute(query).fetchall())
    if len(t_ACL_Summary_df) > 0:
        bad_hostname_list = list(t_ACL_Summary_df.HostName.unique())
        for t_bad_hostname in bad_hostname_list:
            Log_Message = (f'@ ACL_Summary: Device {t_bad_hostname} has been deleted!'); print(Log_Message)
            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        delete_stmt = db.delete(ACL_Summary).where(~ACL_Summary.c.HostName.in_(Good_Hostname))
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)
        Log_Message = (f"{result.rowcount} row(s) deleted."); print(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    query = db.select(My_Devices).where(~My_Devices.c.HostName.in_(Good_Hostname))
    with engine.connect() as connection:
        t_My_Devices_df = pd.DataFrame(connection.execute(query).fetchall())
    if len(t_My_Devices_df) > 0:
        bad_hostname_list = list(t_My_Devices_df.HostName.unique())
        for t_bad_hostname in bad_hostname_list:
            Log_Message = (f'@ My_Devices: Device {t_bad_hostname} has been deleted!'); print(Log_Message)
            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        delete_stmt = db.delete(My_Devices).where(~My_Devices.c.HostName.in_(Good_Hostname))
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)
        Log_Message = (f"{result.rowcount} row(s) deleted."); print(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    query = db.select(Active_Capture).where(~Active_Capture.c.HostName.in_(Good_Hostname))
    with engine.connect() as connection:
        t_Active_Capture_df = pd.DataFrame(connection.execute(query).fetchall())
    if len(t_Active_Capture_df) > 0:
        bad_hostname_list = list(t_Active_Capture_df.HostName.unique())
        for t_bad_hostname in bad_hostname_list:
            Log_Message = (f'@ Active_Capture: Device {t_bad_hostname} has been deleted!'); print(Log_Message)
            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        delete_stmt = db.delete(Active_Capture).where(~Active_Capture.c.HostName.in_(Good_Hostname))
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)
        Log_Message = (f"{result.rowcount} row(s) deleted."); print(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    query = db.select(Show_NAT_DB).where(~Show_NAT_DB.c.HostName.in_(Good_Hostname))
    with engine.connect() as connection:
        t_Show_NAT_DB_df = pd.DataFrame(connection.execute(query).fetchall())
    if len(t_Show_NAT_DB_df) > 0:
        bad_hostname_list = list(t_Show_NAT_DB_df.HostName.unique())
        for t_bad_hostname in bad_hostname_list:
            Log_Message = (f'@ Show_NAT_DB: Device {t_bad_hostname} has been deleted!'); print(Log_Message)
            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        delete_stmt = db.delete(Show_NAT_DB).where(~Show_NAT_DB.c.HostName.in_(Good_Hostname))
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)
        Log_Message = (f"{result.rowcount} row(s) deleted."); print(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))


    # Delete log Folder History
    path = Path(log_folder)
    if path.exists():
        directories = [d.name for d in path.iterdir() if d.is_dir()]
        for t_directory in directories:
            if t_directory not in Good_Hostname:
                folder_path = os.path.join(log_folder, t_directory)
                if os.path.exists(folder_path):
                    Log_Message = (f"Folder {folder_path} to be deleted"); print(Log_Message)
                    row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
                    with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

                    try:
                        shutil.rmtree(folder_path)  # Deletes folder and all contents
                        Log_Message = (f"Folder {folder_path} and its contents deleted successfully."); print(Log_Message)
                        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
                        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
                    except OSError as e:
                        Log_Message = (f"Error deleting folder {folder_path}: {e}"); print(Log_Message)
                        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
                else:
                    Log_Message = (f"Folder {folder_path} does not exist."); print(Log_Message)
                    row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
                    with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    # Delete log Messsages in "WTF_Log" older than Global_Settings.WTFLog_Duration_Days
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=WTFLog_Duration_Days)
    delete_stmt = db.delete(WTF_Log).where(WTF_Log.c.TimeStamp < cutoff_date)
    with engine.begin() as connection:
        result = connection.execute(delete_stmt)
    if result:
        Log_Message = (f"{result.rowcount} row(s) deleted in WTF_Log"); print(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'INFO', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

#===================================================================================================================================================>
# ____  ____  ____  ___  _   _    ____  ____  _  _  ____  ___  ____    __    ____  ___  ____
#( ___)( ___)(_  _)/ __)( )_( )  (  _ \( ___)( \/ )(_  _)/ __)( ___)  (  )  (_  _)/ __)(_  _)
# )__)  )__)   )( ( (__  ) _ (    )(_) ))__)  \  /  _)(_( (__  )__)    )(__  _)(_ \__ \  )(
#(__)  (____) (__) \___)(_) (_)  (____/(____)  \/  (____)\___)(____)  (____)(____)(___/ (__)

Devices2 = []
Device_List_dic = {}

if not os.path.exists(log_folder):
    try:
        os.mkdir(log_folder)
    except:
        with open(f"{Err_folder}/{WTF_Error_FName}","a+") as f:
            f.write(f"Can't create destination directory ({log_folder})\n")
        raise OSError(f"Can't create destination directory ({log_folder})!")

if ARGS_DEVICE:
    if DB_Available:
        query = db.select(My_Devices).where(My_Devices.c.HostName=="%s" %ARGS_DEVICE)
        with engine.connect() as connection:
            Device_to_Check_df = pd.DataFrame(connection.execute(query).fetchall())

        if (Device_to_Check_df.empty):
            Log_Message = (f"No Device available with Hostname {ARGS_DEVICE}"); print(Log_Message)
            with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
                f.write(Log_Message)
            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            exit()

    OLD_TimeStamp_t0 = Device_to_Check_df.TimeStamp_t0[0]

    #check if device is enabled
    if Device_to_Check_df.Enabled[0] == True:
        t_Device_IP = Device_to_Check_df.IP_Address[0]
        t_Device_Hostname = Device_to_Check_df.HostName[0]
        t_Device_username = Device_to_Check_df.Username[0]
        if t_Device_username == None:
            t_Device_username = Default_Credentials_df.Username[0]
        t_Device_password = Device_to_Check_df.Password[0]
        if t_Device_password == None:
            t_Device_password = Default_Credentials_df.Password[0]
        t_Device_type = Device_to_Check_df.Type_id[0]
        t_Device_Vendor = Devices_Model_df.query(f'id == {t_Device_type}')['Device_Vendor'][0]
        t_Device_Model = Devices_Model_df.query(f'id == {t_Device_type}')['Device_Model'][0]
        if ( (t_Device_Vendor == 'Cisco') and (t_Device_Model == 'ASA') ):
            t_Device_type = 'cisco_asa'
        else:
            Log_Message = (f'ERROR! Device Type "{t_Device_type}" Unknown'); print(Log_Message)
            with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f: f.write(Log_Message)
            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            exit()
        Devices2.append([t_Device_IP, t_Device_username, t_Device_password, t_Device_type, t_Device_Hostname])
        Device_List_dic[t_Device_IP] = t_Device_Hostname
    else:
        Log_Message = (f'Device {ARGS_DEVICE} is Disabled...'); print(Log_Message)
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f: f.write(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        exit()
else:
    try:
        counter = 0
        for line in open("Device_List.txt").readlines():
            if line:
                if line.startswith('#') or line.startswith('!'):
                    continue
                elif re.match(r'^\s*$', line):
                    continue
                elif ('#' in line) or ('!' in line):
                    line.replace('!','#')
                    line = line.split('#')[0]
                try:
                    t_Device_Hostname = line.split()[4].strip()
                    Devices2.append(line.strip().split())
                    Device_List_dic[line.split()[0].strip()] = t_Device_Hostname
                except:
                    Log_Message = (f"READING DEVICES - Device List not correct, found a problem at line {counter}\n"); print(Log_Message)
                    try:
                        with open("%s/%s"%(log_folder,WTF_Error_FName),"a+") as f: f.write(Log_Message)
                    except:
                        Log_Message = ('ERROR!!! can not open {log_folder}/{WTF_Error_FName} for writing @ READING DEVICES'); print(Log_Message)
                    exit()

                if DB_Available:
                    query = db.select(My_Devices).where(My_Devices.c.HostName=="%s" %t_Device_Hostname.replace('/','___'))
                    with engine.connect() as connection:
                        Device_to_Check_df = pd.DataFrame(connection.execute(query).fetchall())

                    if (Device_to_Check_df.empty):
                        Log_Message = (f'No Device available with Hostname: "{t_Device_Hostname}"'); print(Log_Message)
                        with open("%s/%s"%(log_folder,WTF_Error_FName),"a+") as f: f.write(Log_Message)
                        exit()

                OLD_TimeStamp_t0 = Device_to_Check_df.TimeStamp_t0[0]
                counter +=1
    except Exception as e:
        Log_Message = "Device_List.txt file not found"; print(Log_Message)
        with open(f"{Err_folder}/{WTF_Error_FName}","a+") as f: f.write(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        Log_Message = (f"An error occurred: {e}"); print(Log_Message)
        with open(f"{Err_folder}/{WTF_Error_FName}","a+") as f: f.write(Log_Message)
        row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        exit()

Config_Change_Dic = {}
for t_device in Device_List_dic.values():
    Config_Change_Dic[t_device] = []

#<===================================================================================================================================================
#   _  ___  ___     ___  _____  __    __    ____  ___  ____    _____  __  __  ____  ____  __  __  ____    ___  ___  _
#  / )(___)(___)   / __)(  _  )(  )  (  )  ( ___)/ __)(_  _)  (  _  )(  )(  )(_  _)(  _ \(  )(  )(_  _)  (___)(___)( \
# ( (  ___  ___   ( (__  )(_)(  )(__  )(__  )__)( (__   )(     )(_)(  )(__)(   )(   )___/ )(__)(   )(     ___  ___  ) )
#  \_)(___)(___)   \___)(_____)(____)(____)(____)\___) (__)   (_____)(______) (__) (__)  (______) (__)   (___)(___)(_/

start = datetime.datetime.now()
today = datetime.datetime.now().strftime('%Y-%m-%d')
Status_Flag = True
if ARGS_FETCH_CONFIG == True:
    text = ('Collect Output')
    utils_v2.Text_in_Frame (text, Config_Change_Dic[t_device], Print_also=1)
    # connnect to device and give commands

    if len(Devices2) != 0:
        print(f"Running commands on {len(Devices2)} devices")
        if ARGS_PARRALEL_PROCESS == True:
        #if True:
            with concurrent.futures.ThreadPoolExecutor(max_workers=VAR_max_workers) as executor:
                futures = []
                for t_Device in Devices2:
                    if DB_Available:
                        Updated_Vals = {'Fetching_Config_Spinner' : True}
                        query = db.update(My_Devices).where(My_Devices.c.HostName==t_Device[-1].replace('/','___')).values(**Updated_Vals)
                        with engine.begin() as connection:
                            results = connection.execute(query)

                        row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                               'Level'     : 'INFO',
                               'Message'   : (f"{t_Device[4]} - Retriving Config from {t_Device[0]} - START")}
                        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

                    futures.append(executor.submit(Get_ASA_Commands, t_Device, Config_Change_Dic[t_device], log_folder, Status_Flag))

            if ARGS_SEE_ELAPSED:
                end = datetime.datetime.now()
                print('GET Commands elapsed time is: %s' %str(end-start))
            for t_Device in Devices2:
                if DB_Available:
                    Updated_Vals = {'Fetching_Config_Spinner' : False}
                    query = db.update(My_Devices).where(My_Devices.c.HostName==t_Device[-1].replace('/','___')).values(**Updated_Vals)
                    with engine.begin() as connection:
                        results = connection.execute(query)

                    row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                           'Level'     : 'INFO',
                           'Message'   : (f"{t_Device[4]} - Retriving Config from {t_Device[0]} - END")}
                    with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        else:
            for t_Device in Devices2:
                if DB_Available:
                    Updated_Vals = {'Fetching_Config_Spinner' : True}
                    query = db.update(My_Devices).where(My_Devices.c.HostName==t_Device[-1].replace('/','___')).values(**Updated_Vals)
                    with engine.begin() as connection:
                        results = connection.execute(query)
                    row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                           'Level'     : 'INFO',
                           'Message'   : (f"{t_Device[4]} - Retriving Config from {t_Device[0]} - START")}
                    with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

                Status_Flag = Get_ASA_Commands(t_Device, Config_Change_Dic[t_device], log_folder, Status_Flag)

                if ARGS_SEE_ELAPSED:
                    end = datetime.datetime.now()
                    print('GET Commands elapsed time is: %s' %str(end-start))
                if DB_Available:
                    Updated_Vals = {'Fetching_Config_Spinner' : False}
                    query = db.update(My_Devices).where(My_Devices.c.HostName==t_Device[-1].replace('/','___')).values(**Updated_Vals)
                    with engine.begin() as connection:
                        results = connection.execute(query)

                    row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                           'Level'     : 'INFO',
                           'Message'   : (f"{t_Device[4]} - Retriving Config from {t_Device[0]} - END")}
                    with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

                if Status_Flag == False:
                    row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                           'Level'     : 'ERROR',
                           'Message'   : (f"{t_Device[4]} - Could not Connect to Device {t_Device[0]}")}
                    with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
                    sys.exit('Quitting...')

##            for future in concurrent.futures.as_completed(futures):
##                print(future.result())

    print('...saved all files')
else:
    print('working on saved files....')

# =======================================================================================================================
# =================== SERIAL PROCESSING
# =======================================================================================================================

def wtf(t_device, Config_Change, log_folder, ARGS_FETCH_CONFIG, ARGS_REBUILD_VARS, ARGS_SEE_ELAPSED, TEST_THIS_ONLY, DB_Available):
    Start_Time = datetime.datetime.now()
    start = datetime.datetime.now()
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    hostname___ = t_device.replace('/','___')

    if len(TEST_THIS_ONLY)>=1:
        if DB_Available:
            Updated_Vals = {'Processing_Conf_Spinner' : True}
            query = db.update(My_Devices).where(My_Devices.c.HostName == hostname___).values(**Updated_Vals)
            try:
                with engine.begin() as connection:
                    connection.execute(query)
                    print('My_Devices DB Updated "Processing_Conf_Spinner=True" status for %s.\n' %hostname___)
            except Exception as e:
                print(f"An error occurred: {e}")
            row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                   'Level'     : 'INFO',
                   'Message'   : (f"{t_device} - Processing Config - START")}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        else:
            print('My_Devices DB NOT AVAILABLE... Can not update "Processing_Conf_Spinner=True" status for %s.\n' %hostname___)

    #if (ARGS_FETCH_CONFIG == True or ARGS_REBUILD_VARS == True):
    if (ARGS_FETCH_CONFIG == True):
        start = datetime.datetime.now()
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show running-config', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show ver', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show run access-group', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show nameif', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show capture', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show route', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show access-list', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show nat detail', log_folder)
        Split_Show_run(t_device, Config_Change_Dic[t_device], 'show crypto ipsec sa entry', log_folder)

    if ARGS_REBUILD_VARS == True:
        start = datetime.datetime.now()
        text = ('Create Variables @ %s' %t_device)
        utils_v2.Text_in_Frame (text, Config_Change_Dic[t_device], Print_also=1)

        #Config_Diff         (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Ver        (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Nameif     (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Run_ACGR   (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Route      (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Crypto     (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Run        (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Nat        (t_device, Config_Change_Dic[t_device], log_folder)
        VAR_Show_Access_List(t_device, Config_Change_Dic[t_device], log_folder)

    Config_Diff         (t_device, Config_Change_Dic[t_device], log_folder)

    if (1 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = Unused_Object(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (1 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY) or (10 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = Unused_ACL(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (2 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = Duplicated_Objects(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (3 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        ObjGrpNet_With1Entry(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (4 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = ACL_VS_Interface(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (5 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = NO_Log_For_ACL(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (6 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = Use_Declared_Objects(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (7 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = DB_For_ACL(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (8 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = F_Active_Capture(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (9 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = Explicit_Deny_IP_Any_Any(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (12 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = ACL_Source_Vs_Routing_Table(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (16 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = Check_NAT(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (17 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = ACL_Dest_Vs_Routing_Table(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    if (18 in TEST_THIS_ONLY) or (0 in TEST_THIS_ONLY):
        start = datetime.datetime.now()
        Config_Change_Dic[t_device] = Check_Range(t_device, Config_Change_Dic[t_device], log_folder)
        if ARGS_SEE_ELAPSED:
            print('wtf elapsed time is: %s' %str(datetime.datetime.now()-start))

    End_Time_Dic = datetime.datetime.now()
    End_Time = datetime.datetime.now()
    Execution_Time = End_Time - Start_Time

    t_TimeStamp_t1 = OLD_TimeStamp_t0
    t_TimeStamp_t0 = datetime.datetime.now()
    t_TimeStamp_t1 = t_TimeStamp_t1.replace(tzinfo=t_TimeStamp_t0.tzinfo)
    print(f'----- TimeStamp_T0 = {t_TimeStamp_t0} -----')
    t_time_delta = t_TimeStamp_t0 - t_TimeStamp_t1
    days = t_time_delta.days
    seconds = t_time_delta.seconds
    hours = seconds // 3600           # 3600 seconds in an hour
    minutes = (seconds % 3600) // 60  # Remaining seconds after hours, divided by 60 to get minutes
    print(f"Difference: {days} days, {hours} hours, {minutes} minutes")

    if len(TEST_THIS_ONLY)>=1:
        if DB_Available:
            Updated_Vals = dict(
                                Processing_Conf_Spinner = False,
                                Last_Check = today,
                                Check_Duration = Execution_Time,
                                TimeStamp_t1 = t_TimeStamp_t1,
                                TimeStamp_t0 = t_TimeStamp_t0,
                                Delta_TimeStamps = (f"{days} days, {hours} hours, {minutes} minutes"),
                                )
            query = db.update(My_Devices).where(My_Devices.c.HostName == hostname___).values(**Updated_Vals)
            with engine.begin() as connection:
                try:
                    results = connection.execute(query)
                    if results.rowcount > 0:
                        print(f"Update successful. Rows affected: {results.rowcount}")
                    else:
                        print("No rows were updated.")
                except Exception as e:
                    print(f"Update failed with error: {e}")

            row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                   'Level'     : 'INFO',
                   'Message'   : (f"{t_device} - Processing Config - END")}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            print('My_Devices DB Updated "Processing_Conf_Spinner=False" status for %s.\n' %hostname___)
        else:
            print('My_Devices DB NOT AVAILABLE... Can not update "Processing_Conf_Spinner=False" status for %s.\n' %hostname___)


    Log_Message = (f"!#####################################################################################################"); print(Log_Message)
    Config_Change_Dic[t_device].append(Log_Message)
    Log_Message = (f"!            WTF! for {hostname___} completed in {Execution_Time}"); print(Log_Message)
    Config_Change_Dic[t_device].append(Log_Message)
    Log_Message = (f"!#####################################################################################################"); print(Log_Message)
    Config_Change_Dic[t_device].append(Log_Message)

    log_folder_new = log_folder + '/' + hostname___
    with open("%s/_CONFIG_%s.txt"%(log_folder_new,hostname___),"w") as f:
        f.write('\n'.join(Config_Change_Dic[t_device]))
    print('...saved file: "%s/_CONFIG_%s.txt"'%(log_folder_new,hostname___))

    if DELETE_VAR_FILES:
        #delete all local variable files
        DEL_Dir_Path = Path(log_folder_new)
        extensions_to_delete = {'.bak', '.dat', '.dir', '.log', '.feather'}
        #excluded_file = "Diff_Only_DF"
        excluded_file = "None"

        # Iterate through all files in the directory and subdirectories
        Deleted_Flag = False
        for t_file in DEL_Dir_Path.rglob('*'):
            if ((t_file.suffix in extensions_to_delete) and (excluded_file not in t_file.name)):
                try:
                    t_file.unlink()  # Deletes the file
                    Deleted_Flag = True
                    #print(f"Deleted: {t_file}")
                except Exception as e:
                    print(f"Error deleting {t_file}: {e}")
        if Deleted_Flag: print('Deleted all VAR files...')

# =======================================================================================================================
# =======================================================================================================================

Start_Time_Dic = {}
End_Time_Dic = {}
for t_device in Device_List_dic.values():
    End_Time_Dic[t_device] = datetime.datetime.now()

# =======================================================================================================================
# =================== TEST FUNCTION PARALLEL START
# =======================================================================================================================
start = datetime.datetime.now()
if ARGS_PARRALEL_PROCESS == True:
    with concurrent.futures.ThreadPoolExecutor(max_workers=VAR_max_workers) as executor:
        futures = []
        for t_device in Device_List_dic.values():
            Start_Time = datetime.datetime.now()
            future = executor.submit(wtf, t_device, Config_Change_Dic[t_device], log_folder, ARGS_FETCH_CONFIG, ARGS_REBUILD_VARS, ARGS_SEE_ELAPSED, TEST_THIS_ONLY, DB_Available)
            futures.append((future, Start_Time))

        for future, Start_Time in futures:
            result = future.result()
            print(f"Task completed with result: {result}")

else:
    for t_device in Device_List_dic.values():
        Start_Time_Dic[t_device] = datetime.datetime.now()
        wtf(t_device, Config_Change_Dic[t_device], log_folder, ARGS_FETCH_CONFIG, ARGS_REBUILD_VARS, ARGS_SEE_ELAPSED, TEST_THIS_ONLY, DB_Available)


end_time = time.time()
elapsed_time = (end_time - start_time)
elapsed_time_t = datetime.timedelta(seconds=elapsed_time)
print('...TOTAL elapsed time = %s' %elapsed_time_t)

if DB_Available:
    engine.dispose()


# =======================================================================================================================
# =======================================================================================================================

    # le ACL utilizzate sono anche dentro " split-tunnel-network-list XXX" nelle "group-policy YYY attributes"

    # gestire inactive line in "no log for acl"
    # gestire le ACL global

    # controllare nomi doppi e proporre sanatoria @ Duped_Objects_Dict (da mettere prima delle altre cose da sanare)

    # collezionare i nomi degli host in un db e popolare IPAM ( e poi usarlo per fcross chech dei nomi)

    # usare il database dei nomi noti
    # in generale rimuovere tutti i "object-group" con dentro una sola entry, sia service che network


    #http://patorjk.com/software/taag/#p=display&f=Bulbhead&t=FW-ALPHA-01

    #mettere questo "OBJ_NAME_REPO_DF = pd.read_excel(my_file, sheet_name='OBJ_Names')" in un DB e fare il check li sopra

# analizzare anchce gli show nat (older than...)
# fare funzione per ACL self shadowing

#link graph python charts echarts grafici plot
#https://echarts.apache.org/examples/en/index.html#chart-type-graphGL

# i numeri di ACL in NoLogForAcl e in DB for acl non sono gli stessi... come mai?
## perche' db4acl tiene in pancia anche la acl not applied to any interface...

# nella tabella "Check Acl Destination Vs Routing Table" aggiungere una colonna con l'hit count cumulativo della riga

# Move to the end the top most wide ACL



