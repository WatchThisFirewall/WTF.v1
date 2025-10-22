#----------------------------------------------------------------------------------------------------
# def Get_ASA_Commands
# def Split_Show_run
# def Config_Diff
# def ACL_VS_Interface
# def NO_Log_For_ACL
# def Unused_ACL
# def Unused_Object
# def ObjGrpNet_With1Entry
# def Duplicated_Objects
# def ACL_Source_Vs_Routing_Table
# def ACL_Dest_Vs_Routing_Table
# def F_Active_Capture
# def Use_Declared_Objects
# def Explicit_Deny_IP_Any_Any
# def DB_For_ACL
# def Check_Dec_Shadowing
# def Check_NAT
# def Check_Range
# def Where_Used
#----------------------------------------------------------------------------------------------------
import os, sys
import datetime
import re
import utils_v2
import shelve
import ipaddress
import pandas as pd
import sqlalchemy as db
import time
import pyarrow
import json

from difflib import Differ
from ASA_Check_Config_PARAM import *
from utils_v2 import Write_Think_File, File_Save_Try, File_Save_Try2, timedelta_in_months

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException, BadHostKeyException
from pathlib import Path

from Network_Calc import Sub_Mask_2, Sub_Mask_1, IPv4_to_DecList, Is_Dec_Overlapping, Port_Converter
from Network_Calc import PRTOTOCOLS, Proto_Map
from tabulate import tabulate

re_space = re.compile(r'[ ]{2,}')
re_iprange = re.compile(r'\b\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+\b')

##=============================================================================================================================
##  ___  ____  ____        __    ___    __         ___  _____  __  __  __  __    __    _  _  ____   ___
## / __)( ___)(_  _)      /__\  / __)  /__\       / __)(  _  )(  \/  )(  \/  )  /__\  ( \( )(  _ \ / __)
##( (_-. )__)   )(  ___  /(__)\ \__ \ /(__)\  ___( (__  )(_)(  )    (  )    (  /(__)\  )  (  )(_) )\__ \
## \___/(____) (__)(___)(__)(__)(___/(__)(__)(___)\___)(_____)(_/\/\_)(_/\/\_)(__)(__)(_)\_)(____/ (___/

def Get_ASA_Commands(Device, Config_Change, log_folder, Status_Flag):
    # return False to order the caller to kill the program

    Config_Change.append('\n')
    t_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    Config_Change.append(f'Timestamp = {t_time}\n')
    print (f'Timestamp = {t_time}\n')

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

    Commands = []
    Commands.append('term page 0')
    Commands.append('show ver')
    Commands.append('show run access-group')
    Commands.append('show nameif')
    Commands.append('show capture')
    Commands.append('show running-config')
    Commands.append('show route')
    Commands.append('show access-list')
    Commands.append('show nat detail')
    Commands.append('show crypto ipsec sa entry')

    Status_Flag = True
    Device_Info = {
        "host"       : Device[0],
        "username"   : Device[1],
        "password"   : Device[2],
        "device_type": Device[3],
        "timeout"    : 60
    }
    retries = 0
    device_connection = None
    _now_ = datetime.datetime.now().astimezone()
    while retries <= 3:
        try:
            print('trying to connect to %s...' %(Device_Info["host"]))
            Config_Change.append(f'trying to connect to {Device_Info["host"]}...')
            device_connection = ConnectHandler(**Device_Info)
            if not device_connection.is_alive():
                err_line = 'device_connection.is_alive() == False:'
                print(err_line)
                Config_Change.append(err_line)
                return False
            else:
                err_line = 'device_connection.is_alive() == True:'
                print(err_line)
                Config_Change.append(err_line)
                break
        except NetmikoTimeoutException:
            err_line = 'Connection timed out!'
            print(err_line)
            Config_Change.append(err_line)
            row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':(f'@{Device_Info["host"]} - Connection timed out!')}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            retries +=1
        except NetmikoAuthenticationException:
            err_line = 'Authentication failed!'
            print(err_line)
            Config_Change.append(err_line)
            row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':(f'@{Device_Info["host"]} - Authentication failed!')}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            retries +=1
        except BadHostKeyException:
            err_line = 'The host key is not recognized. Possible man-in-the-middle attack!'
            print(err_line)
            Config_Change.append(err_line)
            row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':(f'@{Device_Info["host"]} - The host key is not recognized. Possible man-in-the-middle attack!')}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            retries +=1
        except SSHException:
            err_line = 'SSH connection failed!'
            print(err_line)
            Config_Change.append(err_line)
            row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':(f'@{Device_Info["host"]} - SSH connection failed!')}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            retries +=1
        except Exception as e:
            err_line = f'An unexpected error occurred: {e}'
            print(err_line)
            Config_Change.append(err_line)
            row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':(f'@{Device_Info["host"]} - An unexpected error occurred: {e}')}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            retries +=1

    if retries >= 3:
        err_line = '_________________________________________________________'
        print(err_line)
        Config_Change.append(err_line)
        err_line = f'FAILED TO CONNECT TO {Device[4]}@{Device[0]}'
        print(err_line)
        Config_Change.append(err_line)
        row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':f'FAILED TO CONNECT TO {Device[4]}@{Device[0]}'}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        return False

    if Device_Info['device_type'] == 'cisco_ftd':
        device_connection.send_command('system support diagnostic-cli',max_loops=50000,delay_factor=1)
        device_connection.send_command('enable\n',max_loops=50000,delay_factor=1)

    hostname = device_connection.find_prompt()[:-1]
    if 'act' in hostname:
        hostname=hostname.replace('/act','')
    if 'pri' in hostname:
        hostname=hostname.replace('/pri','')
    if 'sec' in hostname:
        hostname=hostname.replace('/sec','')
    t_Device_Slash = Device[4].replace('___','/')
    if hostname != t_Device_Slash:
        print(f'!')
        print(f'!  (=================================================)')
        print(f'!  (==                  Warning!                   ==)')
        print(f'!  (==             Hostname Mismatch!              ==)')
        print(f'!  (==                                             ==)')
        print(f'!      This Device is {Device[4]}                     ')
        print(f'!      while connected device is {hostname}           ')
        print(f'!  (==                                             ==)')
        print(f'!  (=================================================)')
        print(f'!  Please correct the Device Hostname in the database ')
        print(f'!  (=================================================)')

        Config_Change.append(f'!')
        Config_Change.append(f'!  (=================================================)')
        Config_Change.append(f'!  (==                  Warning!                   ==)')
        Config_Change.append(f'!  (==             Hostname Mismatch!              ==)')
        Config_Change.append(f'!  (==                                             ==)')
        Config_Change.append(f'!      This Device is [Device[4]]                     ')
        Config_Change.append(f'!      while connected device is {hostname}           ')
        Config_Change.append(f'!  (==                                             ==)')
        Config_Change.append(f'!  (=================================================)')
        Config_Change.append(f'!  Please correct the Device Hostname in the database ')
        Config_Change.append(f'!  (=================================================)')

        _now_ = datetime.datetime.now().astimezone()
        row = { 'TimeStamp':_now_, 'Level':'ERROR', 'Message':f'Hostname Mismatch!'}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        row = { 'TimeStamp':_now_, 'Level':'ERROR', 'Message':f'Configured is {Device[4]} while connected is {hostname}'}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
        return Config_Change

    hostname___ = hostname.replace('/','___')
    print(f'... Connecting to {hostname}\n')
    Config_Change.append(f'... Connecting to {hostname}\n')

    retries = 1
    output = []
    for t_Command in Commands:
        if t_Command.startswith("#") or t_Command.startswith("!"):
            continue
        Log_Message = (f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M'):<20}| {hostname:<30}| {t_Command.strip():<30}"); print(Log_Message)
        Config_Change.append(Log_Message)
        while retries <5:
            try:
                #output.append("%s\n\n%s\n\n" %(t_Command, device_connection.send_command(t_Command,max_loops=50000,delay_factor=3,read_timeout=1000*retries)))
                output.append("%s\n\n%s\n\n" %(t_Command, device_connection.send_command(t_Command,read_timeout=3600)))
                break
            except Exception as e:
                print(f"Error while executing command: {e}")
                retries +=1
                time.sleep(retries*2)
        if retries == 4:
            Log_Message = (f"UNABLE TO RUN COMMAND {t_Command} on {hostname}"); print(Log_Message)
            Config_Change.append(Log_Message)
            print(Log_Message)
            row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':f'UNABLE TO RUN COMMAND {t_Command} on {hostname}'}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            return False

    device_connection.disconnect()

    FW_log_folder = log_folder + '/' + hostname___
    if not os.path.exists(FW_log_folder):
        try:
            os.mkdir(FW_log_folder)
        except:
            raise OSError("Can't create destination directory (%s)!" % (FW_log_folder))
            row = {'TimeStamp':_now_, 'Level':'ERROR', 'Message':f"Can't create destination directory {FW_log_folder}!"}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    try:
        with open("%s/%s.log"%(FW_log_folder,hostname___),"w+") as f:
            for n in output:
                f.write('\n\n!_________________________________________________________\n\n')
                f.write(n)
                f.write('\n\n')
        print('... saved file "%s/%s.log" '%(FW_log_folder,hostname___))
        Config_Change.append('... saved file "%s/%s.log" '%(FW_log_folder,hostname___))
        return True
    except:
        print("Can't write to destination file (%s/%s.log)!" % (FW_log_folder,hostname___))
        Config_Change.append("Can't write to destination file (%s/%s.log)!" % (FW_log_folder,hostname___))
        return False


##=============================================================================================================================
## ___  ____  __    ____  ____      ___  _   _  _____  _    _       ____  __  __  _  _
##/ __)(  _ \(  )  (_  _)(_  _)    / __)( )_( )(  _  )( \/\/ )     (  _ \(  )(  )( \( )
##\__ \ )___/ )(__  _)(_   )(  ___ \__ \ ) _ (  )(_)(  )    (  ___  )   / )(__)(  )  (
##(___/(__)  (____)(____) (__)(___)(___/(_) (_)(_____)(__/\__)(___)(_)\_)(______)(_)\_)

def Split_Show_run(Device, Config_Change, Show_Line, log_folder):

    hostname___ = Device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___

    try:
        with open(f"{FW_log_folder}/{hostname___}.log", 'r', encoding='utf-8', errors='replace') as f:
            l = f.readlines()
    except:
        print(f'file {FW_log_folder}/{hostname___}.log not found!')
        Config_Change.append(f'file {FW_log_folder}/{hostname___}.log not found!')

    for n in range(0,len(l)):
        line = l[n]
        if line.startswith('!'):
            continue
        elif line.startswith(Show_Line):
            temp = [line]
            nn = n+1
            while not( (nn == len(l)-1) or (l[nn].startswith('show ')) ):
                temp.append(l[nn]) if not l[nn].startswith('!') else ''
                nn += 1


    Not_ascii_Run = []  # To store lines with non-ASCII characters
    Not_ascii_Cap = []  # To store lines with non-ASCII characters

    if Show_Line == 'show running-config':

        l = []
        for line_number, line in enumerate(temp, start=1):
            if any(ord(char) > 127 for char in line):  # Detect non-ASCII characters
                Not_ascii_Run.append((line_number, line.strip().encode('utf-8')))
                l.append(line.encode('ascii', errors='ignore').decode('ascii'))
            else:
                l.append(line)
        temp = l

        # Output the lines with non-ASCII characters
        for line_num, content in Not_ascii_Run:
            print(f"line {line_num}: {content}")

        DB_Available = True
        try:
            engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
            with engine.connect() as connection:
                My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
                WTF_Log    = db.Table('WTF_Log',    db.MetaData(), autoload_with=engine)
        except Exception as e:
            print(f"error is: {e}")
            print('=================[ Warning ]==================')
            print('DB not connected, some feature is unavailable\n')
            Config_Change.append('=================[ Warning ]==================')
            Config_Change.append('DB not connected, some feature is unavailable\n')
            DB_Available = False

        if DB_Available:
            Updated_Vals = dict(
                                N_Not_Ascii = len(Not_ascii_Run),
                                )
            query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
            with engine.begin() as connection:
                results = connection.execute(query)
            engine.dispose()

        Watch_FList = []
        Watch_FList.append('<p class="text-secondary" >')
        if len(Not_ascii_Run)> 0:
            Watch_FList.append('<ul>')
            for line_num, content in Not_ascii_Run:
                Watch_FList.append(f'<li>line {line_num}: {content}</li>')
            Watch_FList.append('</ul>')
            Watch_FList.append('</p>')
        else:
            Watch_FList.append('All Ascii chars found!</p>')

        Watch_FName = FW_log_folder + '/' + hostname___ + '-Not_Ascii-Watch.html'
        log_msg = File_Save_Try2(Watch_FName, Watch_FList, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    elif Show_Line == 'show capture':

        l = []
        for line_number, line in enumerate(temp, start=1):
            if any(ord(char) > 127 for char in line):  # Detect non-ASCII characters
                Not_ascii_Cap.append((line_number, line.strip().encode('utf-8')))
                l.append(line.encode('ascii', errors='ignore').decode('ascii'))
            else:
                l.append(line)
        temp = l

        # Output the lines with non-ASCII characters
        for line_num, content in Not_ascii_Cap:
            print(f"Capture line {line_num}: {content}")

    else:
        with open(f"{FW_log_folder}/{hostname___}.log", 'r', encoding='ascii', errors='ignore') as f:
            t_file = f.readlines()
        l = []
        for line_number, line in enumerate(t_file, start=1):
            if any(ord(char) > 127 for char in line):
                l.append(line.encode('ascii', errors='ignore').decode('ascii'))
                print(f" --- Not ascii @ {Show_Line} line {line_number}: {line}")
            else:
                l.append(line)
        for n in range(0,len(l)):
            line = l[n]
            if line.startswith('!'):
                continue
            elif line.startswith(Show_Line):
                temp = [line]
                nn = n+1
                while not( (nn == len(l)-1) or (l[nn].startswith('show ')) ):
                    temp.append(l[nn]) if not l[nn].startswith('!') else ''
                    nn += 1

    t_DestFileFullName = ("%s/%s___%s.log"%(FW_log_folder,hostname___,Show_Line.title().strip().replace(' ','_')))
    log_msg = File_Save_Try2(t_DestFileFullName, temp, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))


##=============================================================================================================================
##  ___  _____  _  _  ____  ____  ___    ____  ____  ____  ____
## / __)(  _  )( \( )( ___)(_  _)/ __)  (  _ \(_  _)( ___)( ___)
##( (__  )(_)(  )  (  )__)  _)(_( (_-.   )(_) )_)(_  )__)  )__)
## \___)(_____)(_)\_)(__)  (____)\___/  (____/(____)(__)  (__)

def Config_Diff(Device, Config_Change, log_folder):

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            WTF_Log    = db.Table('WTF_Log',    db.MetaData(), autoload_with=engine)
            Bad_News   = db.Table('Bad_News',   db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    hostname___ = Device.replace('/','___')
    Err_folder = log_folder
    FW_log_folder = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    #log_folder = hostname___
    global WTF_Error_FName

    text = f'Config Diff @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    T_0_ShowRun_file   = FW_log_folder + '/' + hostname___ + '.CFG.t-0.txt'
    #T_1_ShowRun_file   = FW_log_folder + '/' + hostname___ + '.CFG.t-1.txt'
    Delta_ShowRun_file = FW_log_folder + '/' + hostname___ + '.CFG.Delta.txt'
    Delta_ShowRun_html = hostname___ + '.CFG.Delta.html'
    html_folder = FW_log_folder
    old_file = ''

    # ----- load current data -----
    try:
        with open("%s/%s___Show_Running-Config.log" %(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            new_file = f.readlines()
    except Exception as e:
        print(f"error is: {e}")
        print(f'file "{hostname___}___Show_Running-Config.log" for compare missing')

    # --- Load previous state or handle first run ---
    if os.path.isfile(T_0_ShowRun_file):
        with open(T_0_ShowRun_file, "r", encoding="utf-8", errors='replace') as f:
            old_file = f.readlines()
    else:
        # First run: save current file as baseline and exit
        try:
            with open(T_0_ShowRun_file, mode="w", encoding='utf-8', errors='replace') as f:
                f.writelines(line for line in new_file)
        except Exception as e:
            print(f"error is: {e}")
            print(f'Can not write to destination file "{T_0_ShowRun_file}"')
            Config_Change.append(f"error is: {e}")
            Config_Change.append(f'Can not write to destination file "{T_0_ShowRun_file}"')
            return Config_Change

    # --- Find differences ---
    Delta_File = []
    differ = Differ()
    Line_Number = 0
    Diff_Only = []
    Num_Added_Lines = 0
    Num_Remvd_Lines = 0
    Diff_Only_DF = pd.DataFrame()

    if old_file:
        for line in differ.compare(old_file, new_file):
            Delta_File.append([Line_Number, line.strip()])
            Line_Number += 1

        for item in Delta_File:
            if item[1].startswith('+'):
                if 'Cryptochecksum:' in item[1]:
                    continue
                else:
                    Diff_Only.append(item)
                    Num_Added_Lines +=1
            elif item[1].startswith('-'):
                if 'Cryptochecksum:' in item[1]:
                    continue
                else:
                    Diff_Only.append(item)
                    Num_Remvd_Lines +=1

    if DB_Available:
        Updated_Vals = dict(
                            Config_Diff_Added_Lines = Num_Added_Lines,
                            Config_Diff_Remvd_Lines = Num_Remvd_Lines,
                            Config_Total_Lines = len(new_file)
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)

    # --- Clean old logs (remove NEW + purge old entries) ---
    cutoff = datetime.datetime.now() - datetime.timedelta(days=Max_Diff_Log_Age)
    #if os.path.exists(Delta_ShowRun_file):
    if os.path.exists(Delta_ShowRun_file) and os.path.getsize(Delta_ShowRun_file) > 0:
        with open(Delta_ShowRun_file, "r", encoding="utf-8", errors='replace') as f:
            lines = f.readlines()
        # --- parse the tabulated to dataframe ---
        data_lines = []
        for line in lines:
            if line.startswith("+") or line.startswith("|-"):
                continue
            line = line.strip().strip('|')
            data_lines.append(line)
        rows = []
        for line in data_lines:
            # skip empty lines
            if not line:
                continue
            # split by '|' and strip spaces
            parts = [x.strip() for x in line.split("|")]
            #print(parts)
            if parts[0] != 'Date':
                ts = datetime.datetime.strptime(parts[0], "%Y.%m.%d-%H:%M:%S")
                if ts >= cutoff:
                    if ts.date() != datetime.datetime.today().date():
                        rows.append([parts[0], parts[1], '', parts[3]])
                    else:
                        rows.append(parts)
            else:
                rows.append(parts)
        if rows:  # only build dataframe if rows exist
            headers = rows[0]
            data = rows[1:]
            try:
                Delta_ShowRun_df = pd.DataFrame(data, columns=headers)
            except ValueError as e:
                print(f"[!] Data mismatch: {e}")
                print(f"Header count: {len(headers)}, Sample row length: {len(data[0]) if data else 'N/A'}")
                print(f"data = {data}, headers = {headers}")
        else:
            Delta_ShowRun_df = pd.DataFrame()  # empty dataframe
    else:
        # File missing or empty
        Delta_ShowRun_df = pd.DataFrame()

    # --- If no changes ---
    if (Num_Added_Lines + Num_Remvd_Lines) == 0:
        try:
            with open(Delta_ShowRun_file, mode="w", encoding='utf-8', errors='replace') as txt_file:
                txt_file.write(tabulate(Delta_ShowRun_df,Delta_ShowRun_df,tablefmt='psql',showindex=False))
        except Exception as e:
            print(f"error is: {e}")
            print('Erron when writing to file "%s" in tabulate' %Delta_ShowRun_file)
        Diff_Only_DF = Delta_ShowRun_df
    else:
        # Add new changes
        t_now = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
        col_names = ['Line_N','Line']
        NEW_Diff_Only_DF = pd.DataFrame(Diff_Only, columns = col_names)
        NEW_Diff_Only_DF.insert(0,'Date',t_now)
        NEW_Diff_Only_DF.insert(2,'New','NEW')
        if os.path.exists(Delta_ShowRun_file):
            Diff_Only_DF = pd.concat([NEW_Diff_Only_DF, Delta_ShowRun_df], ignore_index=True)
        else:
            Diff_Only_DF = NEW_Diff_Only_DF
        # Save updated log in tabular form
        try:
            with open(Delta_ShowRun_file, mode="w", encoding='utf-8', errors='replace') as txt_file:
                txt_file.write(tabulate(Diff_Only_DF,Diff_Only_DF,tablefmt='psql',showindex=False))
        except Exception as e:
            print(f"error is: {e}")
            print('Erron when writing to file "%s" in tabulate' %Delta_ShowRun_file)
        Config_Change.append(tabulate(Diff_Only_DF,Diff_Only_DF,tablefmt='psql',showindex=False))
    # --- Save new state ---
    try:
        with open(T_0_ShowRun_file, mode="w", encoding='utf-8', errors='replace') as f:
            f.writelines(line for line in new_file)
    except Exception as e:
        print(f"error is: {e}")
        print(f'Can not write to destination file "{T_0_ShowRun_file}"')
        Config_Change.append(f"error is: {e}")
        Config_Change.append(f'Can not write to destination file "{T_0_ShowRun_file}"')

    # --- Check for Bad Words ---
    for line in Diff_Only:
        Processed_Line = False
        for t_word in Bad_Words:
            if t_word in line[1]:
                if not Processed_Line:
                    if DB_Available:
                        row = dict(
                                  HostName = Device,
                                  Tmiestamp = datetime.datetime.now().astimezone(),
                                  Content = line[1],
                                  Flag = True
                                  )
                        insert_stmt = Bad_News.insert().values(**row)
                        with engine.begin() as connection:
                            connection.execute(insert_stmt)
                        Processed_Line = True
                        print(f'_____ Bad_News @ {line}"')
                        Config_Change.append(f'_____ Bad_News @ {line}"')



    # OUTPUT HTML FILE
    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
            raise OSError("Can't create destination directory (%s)!" % (html_folder))

    t_html_file = []
    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('''
       <table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-order='[[ 0, "desc" ]]' data-page-length="50" >\n
       ''')
    #my_index = 0
    if not Diff_Only_DF.empty:
        N_Cols = Diff_Only_DF.shape[1]
        t_html_file.append('       <thead><tr>\n')
        t_html_file.append('           <th> Date </th>\n')
        t_html_file.append('           <th class="text-center"> Line # </th>\n')
        t_html_file.append('           <th class="text-center"> New </th>\n')
        t_html_file.append('           <th> Line </th>\n')
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        for row in Diff_Only_DF.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                if t_col_index == N_Cols-1:
                    new_line = ''
                    new_line = utils_v2.Color_Line(Diff_Only_DF.iloc[row.Index][t_col_index])
                    new_line = new_line.encode('ascii', errors='replace').decode('ascii')
                    t_html_file.append('           <td class="text-nowrap mr-2">%s</td>\n' %new_line)
                elif t_col_index == 0:
                    t_html_file.append('           <td class="text-nowrap mr-2">%s</td>\n' %Diff_Only_DF.iloc[row.Index][t_col_index])
                else :
                    t_html_file.append('           <td class="text-center">%s</td>\n' %Diff_Only_DF.iloc[row.Index][t_col_index])
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')
    else:
        t_html_file.append('\n')

    t_DestFileName = f"{html_folder}/{Delta_ShowRun_html}"
    log_msg = File_Save_Try2(t_DestFileName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    # ============================================
    # ========= config length line chart =========
    # ============================================

    ConfLenHist_FList = []
    ConfLenHist_FName = f'{FW_log_folder}/{hostname___}-ConfLenHist.txt'
    t_year_Nbr  = int(datetime.datetime.now().strftime('%Y'))
    t_month_Nbr = int(datetime.datetime.now().strftime('%m'))
    #t_month_Str = datetime.datetime.now().strftime('%b')

    ConfLenHist_Exists = False
    if len(new_file) > 0:
        try:
            with open(ConfLenHist_FName,'r', encoding='utf-8', errors='replace') as f:
                ConfLenHist = f.readlines()
            ConfLenHist_Exists = True
            File_Last_Year  = int(ConfLenHist[-1].split()[0].split('-')[0])
            File_Last_Month = int(ConfLenHist[-1].split()[0].split('-')[1])

            start_date = datetime.datetime(File_Last_Year, File_Last_Month, 1)
            end_date   = datetime.datetime(t_year_Nbr, t_month_Nbr, 1)
            Delta_Months = timedelta_in_months(start_date, end_date)

        except:
            time_axis = []
            t_year = t_year_Nbr
            t_month = t_month_Nbr
            for n in range (0,Conf_Length_History):
                t_time_val = '%s-%s' %(t_year,t_month)
                if t_month == 1:
                    t_month = 13
                    t_year = t_year-1
                t_month = t_month -1
                time_axis.append(t_time_val)
            time_axis.reverse()

            for n in time_axis:
                ConfLenHist_FList.append([n,'NAN'])
            ConfLenHist_FList[-1] = [ConfLenHist_FList[-1][0], len(new_file)]
            ConfLenHist_FList[-2] = [ConfLenHist_FList[-2][0], len(new_file)]
            text = '\n'.join([' '.join([str(j) for j in i]) for i in ConfLenHist_FList]) + '\n'
            log_msg = File_Save_Try2(ConfLenHist_FName, text, t_ErrFileFullName, Config_Change)
            if log_msg:
                with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    if ConfLenHist_Exists:
        if Delta_Months == 0:
            ConfLenHist[-1] = ConfLenHist[-1].split()[0]+ ' ' + str(len(new_file)) + '\n'
            text = ''.join(i for i in ConfLenHist)
        elif Delta_Months == 1:
            # left_shift the array for delta values
            ConfLenHist = ConfLenHist[Delta_Months:] + ConfLenHist[:Delta_Months]
            ConfLenHist[-1] = '%s-%s %s\n' %(t_year_Nbr,t_month_Nbr,len(new_file))
            text = ''.join(i for i in ConfLenHist)
        elif Delta_Months <= 24:
            # left_shift the array for delta values
            ConfLenHist = ConfLenHist[Delta_Months:] + ConfLenHist[:Delta_Months]
            ConfLenHist[-1] = '%s-%s %s\n' %(t_year_Nbr,t_month_Nbr,len(new_file))
            t_year = t_year_Nbr
            t_month = t_month_Nbr
            for n in range(1,Delta_Months):
                t_month = t_month - 1
                if t_month == 0:
                    t_month = 12
                    t_year = t_year-1
                ConfLenHist.pop(-1-n)
                ConfLenHist.insert(-n, '%s-%s %s\n' %(t_year,t_month,''))
            text = ''.join(i for i in ConfLenHist)
        else:
            # rebuild from scratch
            time_axis = []
            t_year = t_year_Nbr
            t_month = t_month_Nbr
            for n in range (0,Conf_Length_History):
                t_time_val = '%s-%s' %(t_year,t_month)
                if t_month == 1:
                    t_month = 13
                    t_year = t_year-1
                t_month = t_month -1
                time_axis.append(t_time_val)
            time_axis.reverse()

            for n in time_axis:
                ConfLenHist_FList.append([n,'NAN'])
            ConfLenHist_FList[-1] = [ConfLenHist_FList[-1][0], len(new_file)]
            ConfLenHist_FList[-2] = [ConfLenHist_FList[-2][0], len(new_file)]
            text = '\n'.join([' '.join([str(j) for j in i]) for i in ConfLenHist_FList]) + '\n'

        log_msg = File_Save_Try2(ConfLenHist_FName, text, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    try:
        with open("chart-area1.js","r") as f:
            l = f.readlines()
    except:
        print('ERROR!!! file chart-area1.js not found!')

    for n in range(0,len(l)):
        if "_LABELS_GOES_HERE_" in l[n]:
            temp = 'labels: ['
            for m in range(0,len(text.strip().split('\n'))):
                m1 = text.strip().split('\n')[m]
                temp = temp + '"%s",' %(m1.split()[0])
            temp = temp + '],\n'
            l[n] = temp
        elif "_DATA_GOES_HERE_" in l[n]:
            temp = 'data: ['
            for m in range(0,len(text.strip().split('\n'))):
                m1 = text.strip().split('\n')[m]
                try:
                    temp = temp + '%s,' %(m1.split()[1].replace('NAN',''))
                except:
                    temp = temp + ' ,'
            temp = temp + '],\n'
            l[n] = temp

    t_fname = f"{html_folder}/chart-area1.js"
    File_Save_Try(t_fname,l)

    return Config_Change


##=============================================================================================================================
##   __    ___  __      _  _  ___    ____  _  _  ____  ____  ____  ____  ____  __    ___  ____
##  /__\  / __)(  )    ( \/ )/ __)  (_  _)( \( )( ___)(_  _)( ___)(  _ \( ___)/__\  / __)( ___)
## /(__)\( (__  )(__    \  / \__ \   _)(_  )  (  )__)   )(   )__)  )   / )__)/(__)\( (__  )__)
##(__)(__)\___)(____)    \/  (___/  (____)(_)\_)(____) (__) (____)(_)\_)(__)(__)(__)\___)(____)

def ACL_VS_Interface(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    Err_folder  = log_folder
    FW_log_folder  = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    global WTF_Error_FName
    Watch_FList = []
    Watch_FName = FW_log_folder + '/' + hostname___ + '-Unprotected_IF-Watch.html'
    Think_FList = []
    Think_FName = FW_log_folder + '/' + hostname___ + '-Unprotected_IF-Think.html'
    Fix_FList   = []
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Unprotected_IF-Fix.html'

    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
            raise OSError("Can't create destination directory (%s)!" % (html_folder))

    text = f'Acl Vs Ineterface @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    DB_Available = True

    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            ACL_Summary = db.Table('ACL_Summary', db.MetaData(), autoload_with=engine)
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            WTF_Log    = db.Table('WTF_Log',    db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    try:
        with open("%s/%s___Show_Nameif.log"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            l = f.readlines()
    except:
        print('ERROR!!! file %s/%s___Show_Nameif.log not found!' %(FW_log_folder,hostname___))

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_if"
    Accessgroup_Dic_by_if = utils_v2.Shelve_Read_Try(tf_name,'')

    Nameif_Dic = {}
    for n in range(1,len(l)):
        if re.match(r'^\s*$', l[n]):
            continue
        elif ('Interface' in l[n]) and ('Name' in l[n]):
            continue
        else:
            Nameif_Dic[l[n].split()[1]] = l[n].split()[0]

    t_N_Interfaces_NoACL = 0
    t_N_Interfaces = len(Nameif_Dic)
    Done_Flag = False
    for n in Nameif_Dic:
        if n not in Accessgroup_Dic_by_if:
            if not Done_Flag:
                #Watch_FList.append('The Following Interfaces have not ACLs applied:<br>')
                text_line = 'The following Interfaces have not ACLs applied:'
                Done_Flag = True
            Watch_FList.append('%s' %n)
            Think_FList.append('show interface %s' %n)
            Think_FList.append('show run access-group | i %s<br>' %n)
            Fix_FList.append('access-list ACL_%s extended permit ip any any log' %n.replace('-','_'))
            Fix_FList.append('access-group ACL_%s in interface %s<br>' %(n.replace('-','_'),n))
            t_N_Interfaces_NoACL += 1

    if DB_Available:
        delete_stmt = db.delete(ACL_Summary).where(ACL_Summary.columns.HostName=="%s" %hostname___)
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)
        print(f"{result.rowcount} row(s) deleted.")

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_List_Dict"
    ACL_List_Dict = utils_v2.Shelve_Read_Try(tf_name,'')
    Root_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict)

    for t_item in Accessgroup_Dic_by_if:
        Root_ACL_Lines_DF_Slice = Root_ACL_Lines_DF.loc[Root_ACL_Lines_DF['Name'] == Accessgroup_Dic_by_if[t_item]]
        Root_ACL_Lines_DF_Slice.reset_index(inplace=True, drop=True)

        N_inactive = 0
        N_Expanded = 0
        N_Logging = 0
        N_HitCnt_Zero = 0
        for index_1 in range(0,len(Root_ACL_Lines_DF_Slice)):
            row1 = Root_ACL_Lines_DF_Slice.loc[index_1].copy()
            if row1.Inactive == 'inactive': #non conteggio le linee 'inactive'
                N_inactive += 1
                continue
            if row1['Hitcnt'] == '0':
                N_HitCnt_Zero += 1
            if 'log' not in row1['Rest']:
                N_Logging += 1

            row1['Hitcnt'] = "(hitcnt=%s)" %row1['Hitcnt']
            t1_Root_key = ' '.join(row1)
            t1_Root_key = re_space.sub(' ', t1_Root_key)
            try:
                N_Expanded += len(ACL_List_Dict[t1_Root_key])
            except:
                print('why? can not find this key:\n%s' %t1_Root_key)

        if DB_Available:
            New_Vals = dict(
                            HostName = hostname___,
                            Nameif = t_item,
                            ACL_Name = Accessgroup_Dic_by_if[t_item],
                            ACL_Length = len(Root_ACL_Lines_DF_Slice),
                            ACL_ELength = N_Expanded,
                            N_ACL_Inactive = N_inactive,
                            N_ACL_NoLog = N_Logging,
                            N_ACL_HitCnt_Zero = N_HitCnt_Zero
                            )
            insert_stmt = ACL_Summary.insert().values(**New_Vals)
            with engine.begin() as connection:
                connection.execute(insert_stmt)

            Updated_Vals = dict(
                                N_Interfaces = t_N_Interfaces,
                                N_Interfaces_NoACL = t_N_Interfaces_NoACL
                                )
            query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
            with engine.begin() as connection:
                results = connection.execute(query)

    if len(Watch_FList) >= 1:
        t_html_file = []
        t_html_file.append('<p class="text-secondary" >\n')
        t_html_file.append('%s<br>\n' %text_line)
        t_html_file.append('<ul>\n')
        for item in Watch_FList:
            t_html_file.append('<li>%s</li>\n' %item)
        t_html_file.append('</ul>\n')
        t_html_file.append('</p>\n')

        log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
        Write_Think_File(Think_FName, Think_FList)
        Write_Think_File(Fix_FName, Fix_FList)
    else:   # means empty file
        Write_Think_File(Watch_FName, ['\n'])
        Write_Think_File(Think_FName, Think_FList)
        Write_Think_File(Fix_FName, ['\n'])

    if DB_Available:
        engine.dispose()

    return Config_Change


##=============================================================================================================================
## _  _  _____    __    _____  ___    ____  _____  ____      __    ___  __
##( \( )(  _  )  (  )  (  _  )/ __)  ( ___)(  _  )(  _ \    /__\  / __)(  )
## )  (  )(_)(    )(__  )(_)(( (_-.   )__)  )(_)(  )   /   /(__)\( (__  )(__
##(_)\_)(_____)  (____)(_____)\___/  (__)  (_____)(_)\_)  (__)(__)\___)(____)

def NO_Log_For_ACL(t_device, Config_Change, log_folder):

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

    logging_monitor_line = ''
    hostname___ = t_device.replace('/','___')

    N_Lines_ACL = 0
    N_Lines_ACL_active = 0
    N_Lines_ACL_inactive = 0
    N_Lines_ACL_NoLog = 0
    N_Lines_ACL_LogDis = 0
    N_Lines_ACL_Remarks = 0

    FW_log_folder = log_folder + '/' + hostname___
    nologacl_htm_FName = FW_log_folder + '/' + hostname___ + '.nologacl_Fix.html'
    logdisabledacl_htm_FName = FW_log_folder + '/' + hostname___ + '.logdisabledacl_Fix.html'

    text = f'No Log For Acl @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    #inactiveacl_htm_FName = FW_log_folder + '/' + hostname___ + '.inactiveacl_Fix.html'
    text = f'Inactive Acl @ {hostname___}'
    #re9 = re.compile(r'(hitcnt=.*)')

    try:
        with open("%s/%s___Show_Running-Config.log"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            l = f.readlines()
    except:
        print('ERROR!!! file %s/%s___Show_Running-Config.log not found!' %(FW_log_folder,hostname___))
        exit(0)

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_if"
    Accessgroup_Dic_by_if = utils_v2.Shelve_Read_Try(tf_name,'')

    Show_run_ACL_LogDis_Lst = []
    Show_run_ACL_NoLog_Lst = []
    for n in range(1,len(l)):
        if re.match(r'^\s*$', l[n]):
            continue
        elif l[n].startswith('logging monitor '):
            logging_monitor_line = l[n]
        elif l[n].startswith('access-list '):
            ACL_NAME = l[n].split()[1]
            if ACL_NAME in list(Accessgroup_Dic_by_if.values()): #sto facendo i controlli solo sulle ACL applicate ad interfacce
                if ' remark ' not in l[n]:
                    if ' standard ' not in l[n]:
                        N_Lines_ACL = N_Lines_ACL +1
                        if ' inactive' not in l[n]:
                            N_Lines_ACL_active += 1
                            if ' log disable' in l[n]:
                                temp = l[n].rstrip().replace(' log disable', ' log')
                                Show_run_ACL_LogDis_Lst.append(temp)
                                N_Lines_ACL_LogDis = N_Lines_ACL_LogDis +1
                            elif ' log ' not in l[n]:
                                Show_run_ACL_NoLog_Lst.append(l[n].strip() + ' log')
                                N_Lines_ACL_NoLog = N_Lines_ACL_NoLog +1
                        else:
                            N_Lines_ACL_inactive +=1
                else:
                    N_Lines_ACL_Remarks +=1


    if logging_monitor_line != '':
        Config_Change.append('! logging monitor level configured is: "%s"' %logging_monitor_line.strip())
    if logging_monitor_line != '':
        if logging_monitor_line.strip().split()[2] != 'notifications':
            Config_Change.append('Suggestion!!! Consider changing the monitor logging level to "notifications"')
    else:
        Config_Change.append('Suggestion!!! no explicit logging monitor level configured')

    #percent = round(N_Lines_ACL_NoLog/N_Lines_ACL_active*100,2) if N_Lines_ACL_active else 0
    #percent = round(N_Lines_ACL_LogDis/N_Lines_ACL_active*100,2) if N_Lines_ACL_active else 0

    Write_Think_File(nologacl_htm_FName, Show_run_ACL_NoLog_Lst)
    Write_Think_File(logdisabledacl_htm_FName, Show_run_ACL_LogDis_Lst)

    if DB_Available:
        Updated_Vals = dict(
                            N_ACL_Lines = N_Lines_ACL,
                            N_ACL_Inactive = N_Lines_ACL_inactive,
                            N_ACL_Active = N_Lines_ACL_active,
                            N_ACL_NoLog = N_Lines_ACL_NoLog,
                            N_ACL_LogDisabled = N_Lines_ACL_LogDis,
                            N_ACL_Remarks = N_Lines_ACL_Remarks
                            )

        query = db.update(My_Devices).where(My_Devices.c.HostName == hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)
        engine.dispose()

    return Config_Change


##=============================================================================================================================
## __  __  _  _  __  __  ___  ____  ____       __    ___  __
##(  )(  )( \( )(  )(  )/ __)( ___)(  _ \     /__\  / __)(  )
## )(__)(  )  (  )(__)( \__ \ )__)  )(_) )   /(__)\( (__  )(__
##(______)(_)\_)(______)(___/(____)(____/   (__)(__)\___)(____)

def Unused_ACL(t_device, Config_Change, log_folder):

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            WTF_Log    = db.Table('WTF_Log',    db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___
    Watch_FList = [' ']
    Watch_Heading_Text = 'The Following ACLs are not applied:'
    Watch_FName = FW_log_folder + '/' + hostname___ + '-Unused_ACL-Watch.html'
    Think_FList = [' ']
    Think_FName = FW_log_folder + '/' + hostname___ + '-Unused_ACL-Think.html'
    Fix_FList   = [' ']
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Unused_ACL-Fix.html'

    # find unused acl for service-policy
    Used_ACL_ServPol = []
    ServicePolicy_Lst = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ServicePolicy_Lst')
    ServicePolicy_Lst = utils_v2.Shelve_Read_Try(tf_name,'')

    PolicyMap_Dct = {}
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'PolicyMap_Dct')
    PolicyMap_Dct = utils_v2.Shelve_Read_Try(tf_name,'')

    ClassMap_Dct = {}
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ClassMap_Dct')
    ClassMap_Dct = utils_v2.Shelve_Read_Try(tf_name,'')

    for n in ServicePolicy_Lst:
        t_cm = PolicyMap_Dct[n]
        for m in t_cm:
            try:
                Used_ACL_ServPol.append(ClassMap_Dct[m])
            except:
                print('WARNING... class %s in policy-map %s not used' %(m,n))

    Unused_ACL_List = []

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_ACL"
    Accessgroup_Dic_by_ACL = utils_v2.Shelve_Read_Try(tf_name,'')

    with open("%s/%s___Show_Capture.log"%(FW_log_folder,hostname___),"r") as f:
        l = f.readlines()
    ACL_Capture_List = []
    for n in range(0,len(l)):
        if 'access-list' in l[n]:
            ACL_Capture_List.append(l[n].split('access-list')[1].split()[0])

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Global_ACL_Dic"
    Global_ACL_Dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_List"
    ACL_List = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_SplitTunnel_List"
    ACL_SplitTunnel_List = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Crypto_MAP_ACL_List"
    Crypto_MAP_ACL_List = utils_v2.Shelve_Read_Try(tf_name,'')

    for n in ACL_List:
        #if n not in Accessgroup_Dic_by_if.values():
        if n not in Accessgroup_Dic_by_ACL:
            if n not in ACL_Capture_List:
                if n not in Used_ACL_ServPol:
                    if n not in ACL_SplitTunnel_List:
                        if n not in Global_ACL_Dic.values():
                            if n not in Crypto_MAP_ACL_List:
                                #print('Notify...  access-list "%s" is not applied to any interface or capture' %n) if (DEBUG_LEVEL == 1) else ''
                                Watch_FList.append('%s' %n)
                                Unused_ACL_List.append(n)

    try:
        percent = round(len(Unused_ACL_List)/len(ACL_List)*100,2) if len(ACL_List) else 0
    except:
        print('ERROR! Divide by zero @ %s, %s' %(hostname___, ACL_List))
        exit(123456)

    if DB_Available:
        Updated_Vals = dict(
                            Unused_ACL=len(Unused_ACL_List),
                            Declared_ACL=len(ACL_List),
                            Percent_Unused_ACL=percent
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)
        engine.dispose()

    for n in Unused_ACL_List:
        Think_FList.append('show run | i %s ' %n)

    if len(Unused_ACL_List) > 0:
        for n in Unused_ACL_List:
            Fix_FList.append('clear configure access-list %s' %n)

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Unused_ACL_List"
    retries = utils_v2.Shelve_Write_Try(tf_name,Unused_ACL_List)

    FirstRun = True
    for n in ClassMap_Dct.values():
        if n not in Used_ACL_ServPol:
            for t_key, t_value in ClassMap_Dct.items():
                if t_value == n:
                    if FirstRun == True:
                        Watch_FList.append('!')
                    #print('Notify... class-map "%s" not used' %t_value) if (DEBUG_LEVEL == 0) else ''
                    Watch_FList.append('class-map "%s" not used' %t_key)
                    Think_FList.append('show run | i %s ' %t_key)
                    Fix_FList.append('no class-map %s' %t_key)
                    FirstRun = False

    FirstRun = True
    for n in PolicyMap_Dct:
        if n not in ServicePolicy_Lst:
            if FirstRun == True:
                Watch_FList.append('!')
            #print('Notify... policy-map "%s" not used' %n) if (DEBUG_LEVEL == 0) else ''
            Watch_FList.append('policy-map "%s" not used' %n)
            Think_FList.append('show run | i %s ' %n)
            Fix_FList.append('no policy-map %s' %n)
            FirstRun = False

# aggiungere timestamp
    t_file = []
    t_file.append('<p class="text-secondary" >\n')
    t_file.append('%s<br>\n' %Watch_Heading_Text)
    t_file.append('<ul>\n')
    for item in Watch_FList:
        t_file.append('<li>%s</li>\n' %item)
    t_file.append('</ul>\n')
    t_file.append('</p>\n')

    if len(Watch_FList) >= 1:
        log_msg = File_Save_Try2(Watch_FName, t_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
    else:
        Write_Think_File(Watch_FName, [''])
    Write_Think_File(Think_FName, Think_FList)
    Write_Think_File(Fix_FName, Fix_FList)

    return Config_Change

##=============================================================================================================================
## __  __  _  _  __  __  ___  ____  ____     _____  ____   ____  ____  ___  ____
##(  )(  )( \( )(  )(  )/ __)( ___)(  _ \   (  _  )(  _ \ (_  _)( ___)/ __)(_  _)
## )(__)(  )  (  )(__)( \__ \ )__)  )(_) )   )(_)(  ) _ <.-_)(   )__)( (__   )(
##(______)(_)\_)(______)(___/(____)(____/   (_____)(____/\____) (____)\___) (__)

def Unused_Object(t_device, Config_Change, log_folder):

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

    hostname___ = t_device.replace('/','___')
    Err_folder  = log_folder
    FW_log_folder  = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    global WTF_Error_FName

    text = f'Unused Object @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    Used_Object_List = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Used_Object_List')
    Used_Object_List = utils_v2.Shelve_Read_Try(tf_name,'')

    Declared_OBJ_NET = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Declared_OBJ_NET')
    Declared_OBJ_NET = utils_v2.Shelve_Read_Try(tf_name,'')

    Declared_OBJ_GRP_NET = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Declared_OBJ_GRP_NET')
    Declared_OBJ_GRP_NET = utils_v2.Shelve_Read_Try(tf_name,'')

    Declared_Object_service = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Declared_Object_service')
    Declared_Object_service = utils_v2.Shelve_Read_Try(tf_name,'')

    OBJ_GRP_SVC_Dic = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_SVC_Dic')
    OBJ_GRP_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    OBJ_GRP_PRT_Dic = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_PRT_Dic')
    OBJ_GRP_PRT_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic:
        if len(t_OBJ_GRP_SVC_Dic_key.split()) == 2:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = [t_OBJ_GRP_SVC_Dic_key.split()[1], OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)]
        else:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = ['', OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)]


    Unused_Obj_Net = []
    Count_Obj_Not_Applied = 0
    for n in Declared_OBJ_NET:
        if n not in Used_Object_List:
            Count_Obj_Not_Applied += 1
            Unused_Obj_Net.append(n)
    #percent = round(Count_Obj_Not_Applied/len(Declared_OBJ_NET)*100,2) if len(Declared_OBJ_NET) else 0

    Unused_ObjGrp_Net = []
    Count_ObjGrp_Not_Applied = 0
    for n in Declared_OBJ_GRP_NET:
        if n not in Used_Object_List:
            Count_ObjGrp_Not_Applied += 1
            Unused_ObjGrp_Net.append(n)
    #percent = round(Count_ObjGrp_Not_Applied/len(Declared_OBJ_GRP_NET)*100,2) if len(Declared_OBJ_GRP_NET) else 0

    Unused_Obj_Service = []
    Count_ObjSrv_Not_Applied = 0
    for n in Declared_Object_service:
        if n not in Used_Object_List:
            Count_ObjSrv_Not_Applied += 1
            Unused_Obj_Service.append(n)
    #percent = round(Count_ObjSrv_Not_Applied/len(Declared_Object_service)*100,2) if len(Declared_Object_service) else 0

    Unused_ObjGrp_Service = []
    Count_ObjGrpSrv_Not_Applied = 0
    # find in services
    for n in OBJ_GRP_SVC_Dic_2:
        if n not in Used_Object_List:
            Count_ObjGrpSrv_Not_Applied += 1
            Unused_ObjGrp_Service.append(n)
    # find in protocols
    for n in OBJ_GRP_PRT_Dic:
        if n not in Used_Object_List:
            Count_ObjGrpSrv_Not_Applied += 1
            Unused_ObjGrp_Service.append(n)
    LEN_OBJ_SVC = len(OBJ_GRP_SVC_Dic_2) + len(OBJ_GRP_PRT_Dic)
    #percent = round(Count_ObjGrpSrv_Not_Applied/LEN_OBJ_SVC*100,2) if LEN_OBJ_SVC else 0

    # ----- WTF for Unused_Obj_Net ---------------------------------------------------
    Watch_FList = []
    Watch_FName = FW_log_folder + '/' + hostname___ + '-ObjNet_Not_Applied-Watch.html'
    Think_FList = []
    Think_FName = FW_log_folder + '/' + hostname___ + '-ObjNet_Not_Applied-Think.html'
    Fix_FList   = []
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-ObjNet_Not_Applied-Fix.html'

    Watch_FList.append('<p class="text-secondary" >')
    if len(Unused_Obj_Net) > 0:
        Watch_FList.append('<ul>')
        for item in Unused_Obj_Net:
            Watch_FList.append('<li>%s</li>' %item)
            Think_FList.append('show run | i %s' %item)
            Fix_FList.append('no object network %s' %item)
        Watch_FList.append('</ul>')
        Watch_FList.append('</p>')
    else:
        Watch_FList.append('No spare Network Object found!')

    File_Save_Try(Watch_FName,Watch_FList)
    Write_Think_File(Think_FName, Think_FList)
    Write_Think_File(Fix_FName, Fix_FList)

    # ----- WTF for Unused_ObjGrp_Net ---------------------------------------------------
    Watch_FList = []
    Watch_FName = FW_log_folder + '/' + hostname___ + '-ObjGrpNet_Not_Applied-Watch.html'
    Think_FList = []
    Think_FName = FW_log_folder + '/' + hostname___ + '-ObjGrpNet_Not_Applied-Think.html'
    Fix_FList   = []
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-ObjGrpNet_Not_Applied-Fix.html'

    Watch_FList.append('<p class="text-secondary" >')
    if len(Unused_ObjGrp_Net) > 0:
        Watch_FList.append('<ul>')
        for item in Unused_ObjGrp_Net:
            Watch_FList.append('<li>%s</li>' %item)
            Think_FList.append('show run | i %s' %item)
            Fix_FList.append('no object-group network %s' %item)
        Watch_FList.append('</ul>')
        Watch_FList.append('</p>')
    else:
        Watch_FList.append('No spare Network Object-Group found!')

    File_Save_Try(Watch_FName,Watch_FList)
    Write_Think_File(Think_FName, Think_FList)
    Write_Think_File(Fix_FName, Fix_FList)

    # ----- WTF for Unused_Obj_Service ---------------------------------------------------
    Watch_FList = []
    Watch_FName = FW_log_folder + '/' + hostname___ + '-ObjSvc_Not_Applied-Watch.html'
    Think_FList = []
    Think_FName = FW_log_folder + '/' + hostname___ + '-ObjSvc_Not_Applied-Think.html'
    Fix_FList   = []
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-ObjSvc_Not_Applied-Fix.html'

    Watch_FList.append('<p class="text-secondary" >')
    if len(Unused_Obj_Service) > 0:
        Watch_FList.append('<ul>')
        for item in Unused_Obj_Service:
            Watch_FList.append('<li>%s</li>' %item)
            Think_FList.append('show run | i %s' %item)
            Fix_FList.append('no object service %s' %item)
        Watch_FList.append('</ul>')
        Watch_FList.append('</p>')
    else:
        Watch_FList.append('No spare Service Object found!')

    File_Save_Try(Watch_FName, Watch_FList)
    Write_Think_File(Think_FName, Think_FList)
    Write_Think_File(Fix_FName, Fix_FList)

    # ----- WTF for Unused_ObjGrp_Service ---------------------------------------------------
    Watch_FList = []
    Watch_FName = FW_log_folder + '/' + hostname___ + '-ObjGrpSvc_Not_Applied-Watch.html'
    Think_FList = []
    Think_FName = FW_log_folder + '/' + hostname___ + '-ObjGrpSvc_Not_Applied-Think.html'
    Fix_FList   = []
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-ObjGrpSvc_Not_Applied-Fix.html'

    Watch_FList.append('<p class="text-secondary" >')
    if len(Unused_ObjGrp_Service) > 0:
        Watch_FList.append('<ul>')
        for item in Unused_ObjGrp_Service:
            Watch_FList.append('<li>%s</li>' %item)
            Think_FList.append('show run | i %s' %item)
            if item in OBJ_GRP_SVC_Dic_2:
                Fix_FList.append('no object-group service %s' %item)
            elif item in OBJ_GRP_PRT_Dic:
                Fix_FList.append('no object-group protocol %s' %item)
            else:
                print('WTF!!!! @ unused object')

        Watch_FList.append('</ul>')
        Watch_FList.append('</p>')
    else:
        Watch_FList.append('No spare Service Object-Group found!')

    File_Save_Try(Watch_FName, Watch_FList)
    Write_Think_File(Think_FName, Think_FList)
    Write_Think_File(Fix_FName, Fix_FList)

    if DB_Available:
        Updated_Vals = dict(
                            N_OBJ_NET_Declared   = len(Declared_OBJ_NET),
                            N_OBJ_NET_Unapplied  = Count_Obj_Not_Applied,
                            N_OBJ_NET_Duplicated = 0,

                            N_OBJ_GRP_NET_Declared   = len(Declared_OBJ_GRP_NET),
                            N_OBJ_GRP_NET_Unapplied  = Count_ObjGrp_Not_Applied,
                            N_OBJ_GRP_NET_Duplicated = 0,

                            N_OBJ_SVC_Declared   = len(Declared_Object_service),
                            N_OBJ_SVC_Unapplied  = Count_ObjSrv_Not_Applied,
                            N_OBJ_SVC_Duplicated = 0,

                            N_OBJ_GRP_SVC_Declared   = LEN_OBJ_SVC,
                            N_OBJ_GRP_SVC_Unapplied  = Count_ObjGrpSrv_Not_Applied,
                            N_OBJ_GRP_SVC_Duplicated = 0,

                            SUM_OBJ_Declared = len(Declared_OBJ_NET) + len(Declared_OBJ_GRP_NET) + len(Declared_Object_service) + LEN_OBJ_SVC
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)
        engine.dispose()
    return Config_Change


##=============================================================================================================================
## _____  ____   ____  ____  ___  ____       ___  ____  _____  __  __  ____    _  _  ____  ____  _    _  _____  ____  _  _    _    _  ____  ____  _   _    _____  _  _  ____    ____  _  _  ____  ____  _  _
##(  _  )(  _ \ (_  _)( ___)/ __)(_  _)___  / __)(  _ \(  _  )(  )(  )(  _ \  ( \( )( ___)(_  _)( \/\/ )(  _  )(  _ \( )/ )  ( \/\/ )(_  _)(_  _)( )_( )  (  _  )( \( )( ___)  ( ___)( \( )(_  _)(  _ \( \/ )
## )(_)(  ) _ <.-_)(   )__)( (__   )( (___)( (_-. )   / )(_)(  )(__)(  )___/   )  (  )__)   )(   )    (  )(_)(  )   / )  (    )    (  _)(_   )(   ) _ (    )(_)(  )  (  )__)    )__)  )  (   )(   )   / \  /
##(_____)(____/\____) (____)\___) (__)      \___/(_)\_)(_____)(______)(__)    (_)\_)(____) (__) (__/\__)(_____)(_)\_)(_)\_)  (__/\__)(____) (__) (_) (_)  (_____)(_)\_)(____)  (____)(_)\_) (__) (_)\_) (__)

def ObjGrpNet_With1Entry(t_device, Config_Change, log_folder):
    re10 = re.compile(r'line \d+ ')

    hostname___ = t_device.replace('/','___')

    text = f'object-group network with one entry @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    FW_log_folder = log_folder + '/' + hostname___

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_GRP_NET_Dic"
    OBJ_GRP_NET_Dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obj_Net_Dic"
    Obj_Net_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    Declared_OBJ_GRP_NET_Dic = len(OBJ_GRP_NET_Dic)

    OBJ_GRP_NET_ONE = []
    Old_to_New = {}
    TEMP_Config_Change = []

    for t_key in OBJ_GRP_NET_Dic:
        if len(OBJ_GRP_NET_Dic[t_key]) == 1:
            TEMP_Config_Change.append('\n!object-group network %s' %(t_key))
            TEMP_Config_Change.append('!%s' %(OBJ_GRP_NET_Dic[t_key][0]))

            this_item = OBJ_GRP_NET_Dic[t_key][0]

            if ' host ' in this_item:
                OBJ_GRP_NET_ONE.append(t_key)
                Old_Name = t_key
                New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('H_')) else ('H_%s' %t_key.replace('-','_').upper())

                Old_to_New[Old_Name] = New_Name
                TEMP_Config_Change.append('object network %s' %New_Name)
                TEMP_Config_Change.append(' %s' %(OBJ_GRP_NET_Dic[t_key][0].replace('network-object','')))
            elif 'network-object object' in this_item:
                OBJ_GRP_NET_ONE.append(t_key)
                Old_Name = t_key
                if 'host ' in Obj_Net_Dic[this_item.split()[2]]:
                    New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('H_')) else ('H_%s' %t_key.replace('-','_').upper())
                elif 'subnet ' in Obj_Net_Dic[this_item.split()[2]]:
                    New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('N_')) else ('N_%s' %t_key.replace('-','_').upper())
                elif 'range ' in Obj_Net_Dic[this_item.split()[2]]:
                    New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('R_')) else ('R_%s' %t_key.replace('-','_').upper())
                else:
                    print('ekkekkazzo!!!!')
                    exit(763)
                Old_to_New[Old_Name] = New_Name
                TEMP_Config_Change.append('!object network %s' %New_Name)
                TEMP_Config_Change.append('!%s' %(Obj_Net_Dic[this_item.split()[2]]))
                TEMP_Config_Change.append('! but object network "%s" will be used' %(this_item.split()[2]))
                Old_to_New[Old_Name] = this_item.split()[2]
            elif (this_item.count('.') == 6) and (len(this_item.split()) == 3):
                OBJ_GRP_NET_ONE.append(t_key)
                Old_Name = t_key
                New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('N_')) else ('N_%s' %t_key.replace('-','_').upper())
                Old_to_New[Old_Name] = New_Name
                TEMP_Config_Change.append('object network %s' %New_Name)
                TEMP_Config_Change.append('%s' %(this_item.replace('network-object','subnet')))

    Declared_OBJ_GRP_NET_ONE = len(OBJ_GRP_NET_ONE)
    TEMP_Config_Change.append('')
    for t_key in OBJ_GRP_NET_Dic:
        for t_item in OBJ_GRP_NET_Dic[t_key]:
            for tt_key in Old_to_New:
                if 'group-object ' in t_item:
                    if tt_key == t_item.split()[1]:
                        TEMP_Config_Change.append('object-group network %s' %t_key)
                        TEMP_Config_Change.append(' network-object object %s' %Old_to_New[tt_key])
                        TEMP_Config_Change.append(' no group-object %s\n' %tt_key)

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines"
    Show_ACL_Lines = utils_v2.Shelve_Read_Try(tf_name,'')

    TEMP_Config_Change.append('')
    for t_acl_line in Show_ACL_Lines:
        if ' inactive' not in t_acl_line:
            Print_Line = False
            t_acl_line_split = t_acl_line.split()
            for n in range(0,len(t_acl_line_split)):
                if t_acl_line_split[n] == 'object-group':
                    for t_grp in OBJ_GRP_NET_ONE:
                        if t_acl_line_split[n+1] == t_grp:
                            t_acl_line_split[n] = 'object'
                            t_acl_line_split[n+1] = Old_to_New[t_grp]
                            Print_Line = True
            if Print_Line == True:
                t_acl_line_new = (' '.join(t_acl_line_split)).split('(hitc')[0]
                TEMP_Config_Change.append(t_acl_line_new)
                TEMP_Config_Change.append('no %s' %(re10.sub('',t_acl_line.split('(hitc')[0])))
    TEMP2_Config_Change = []
    percent = round(Declared_OBJ_GRP_NET_ONE/Declared_OBJ_GRP_NET_Dic*100,2) if Declared_OBJ_GRP_NET_Dic else 0
    TEMP2_Config_Change.append('--- %s over %s "object-group network" entries (%s%%)' %(Declared_OBJ_GRP_NET_ONE,Declared_OBJ_GRP_NET_Dic,percent))

    for n in TEMP_Config_Change:
        TEMP2_Config_Change.append(n)

    Fix_FName   = FW_log_folder + '/' + hostname___ + '-ObjGrpNet_1Entry-Watch.html'
    Write_Think_File(Fix_FName, TEMP2_Config_Change)

    return Config_Change


##=============================================================================================================================
## ____  __  __  ____  __    ____  ___    __   ____  ____  ____     _____  ____   ____  ____  ___  ____  ___
##(  _ \(  )(  )(  _ \(  )  (_  _)/ __)  /__\ (_  _)( ___)(  _ \   (  _  )(  _ \ (_  _)( ___)/ __)(_  _)/ __)
## )(_) ))(__)(  )___/ )(__  _)(_( (__  /(__)\  )(   )__)  )(_) )   )(_)(  ) _ <.-_)(   )__)( (__   )(  \__ \
##(____/(______)(__)  (____)(____)\___)(__)(__)(__) (____)(____/   (_____)(____/\____) (____)\___) (__) (___/

def Duplicated_Objects(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    FW_log_folder  = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    hostname = t_device

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            WTF_Log    = db.Table('WTF_Log',    db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    text = f'Duplicated Objects @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Undeclared_NetObj_List"
    Undeclared_NetObj_List = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_GRP_NET_Dic"
    OBJ_GRP_NET_Dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obejct_by_value_Dict"
    Obejct_by_value_Dict = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Declared_OBJ_NET"
    Declared_OBJ_NET = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obj_Net_Dic"
    Obj_Net_Dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_GRP_SVC_Dic"
    OBJ_GRP_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,'')


##    (=================================================)
##    (==      Search_For_Duplicated_Obj_Network      ==)
##    (=================================================)
    Dup_OBJ_NET_List = []
    N_of_Duplicated_OBJ_NET = 0
    N_of_unique_Duplicated_OBJ_NET = 0
    for t_key in Obejct_by_value_Dict:
        if len(Obejct_by_value_Dict[t_key]) > 1:
            N_of_Duplicated_OBJ_NET += 1
            N_of_unique_Duplicated_OBJ_NET += len(Obejct_by_value_Dict[t_key])
            Dup_OBJ_NET_List.append([t_key, Obejct_by_value_Dict[t_key]])

    #Prcnt_N_of_unique_Dup_OBJ_NET = round(100*N_of_unique_Duplicated_OBJ_NET/len(Declared_OBJ_NET),1) if (len(Declared_OBJ_NET)!=0) else 0

    Watch_Flist = []
    Watch_Flist.append('<div class="card-body">\n')
    Watch_Flist.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_Flist.append('       <thead><tr>\n')
    Watch_Flist.append('           <th class="px-2">IP</th>\n')
    Watch_Flist.append('           <th class="px-2">Object Name</th>\n')
    Watch_Flist.append('       </tr></thead>\n')
    Watch_Flist.append('       <tbody>\n')
    for item in Dup_OBJ_NET_List:
        Watch_Flist.append('       <tr>\n')
        Watch_Flist.append('           <td class="font-weight-bold text-nowrap px-2">%s</td>\n' %item[0])
        Watch_Flist.append('       <td class="px-2">\n')
        for n in range(0,len(item[1])):
            Watch_Flist.append('%s<br>' %item[1][n])
        Watch_Flist.append('       </td>\n')
        Watch_Flist.append('       </tr>\n')
    Watch_Flist.append('       </tbody>\n')
    Watch_Flist.append('   </table>\n')
    Watch_Flist.append('</div>\n')

    Watch_FName = FW_log_folder + '/' + hostname___ + '-ObjNet_Duplicated-Watch.html'
    log_msg = File_Save_Try2(Watch_FName, Watch_Flist, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

##    (=================================================)
##    (==    Search_For_Duplicated_Obj-Grp_Network    ==)
##    (=================================================)
    # apri OBJ_GRP_NET_Dic ed esplode ricorsivamente tutte le entry per ottenere solo ip
    # controlla se ci sono duplicati

    OBJ_GRP_NET_Dic_explode = {}
##    Duplicated_Object_List = []
    Duplicated_Object_Dic = {}
    for t_key in OBJ_GRP_NET_Dic:
        t_vals = []
        for t_item in OBJ_GRP_NET_Dic[t_key]:
            if 'network-object host ' in t_item:
##                if t_item.split()[-1] in t_vals:
##                    print(f'Duplicated Object in {t_key}: {t_item.split()[-1]}')
##                    Duplicated_Object_List.append(f'{t_key}: {t_item.split()[-1]}')
                t_vals.append(t_item.split()[-1])
                if f'{t_key}|{t_item.split()[-1]}' not in Duplicated_Object_Dic:
                    Duplicated_Object_Dic[f'{t_key}|{t_item.split()[-1]}'] = [f'{t_key} => {t_item}']
                else:
                    Duplicated_Object_Dic[f'{t_key}|{t_item.split()[-1]}'].append(f'{t_key} => {t_item}')
            elif 'network-object object ' in t_item:
                if t_item.split()[-1] in Obj_Net_Dic:
                    temp = Obj_Net_Dic[t_item.split()[-1]]
                    temp = temp.replace('host ','')
                    temp = temp.replace('range ','')
                    temp = temp.replace('subnet ','')
                    temp = temp.replace('fqdn ','')
    ##                if temp in t_vals:
    ##                    print(f'Duplicated Object in {t_key}: {temp}')
    ##                    Duplicated_Object_List.append(f'{t_key}: {temp}')
                else:
                    print(f"Key not found: {t_item.split()[-1]}")
                    print(f"network-object object {t_item} # can be safely removed from {t_key}")
                    Config_Change.append(f"Key not found: {t_item.split()[-1]}\n")
                    Config_Change.append(f"network-object object {t_item} # can be safely removed from {t_key}\n")
                t_vals.append(temp)
                if f'{t_key}|{temp}' not in Duplicated_Object_Dic:
                    Duplicated_Object_Dic[f'{t_key}|{temp}'] = [f'{t_key} => {t_item}']
                else:
                    Duplicated_Object_Dic[f'{t_key}|{temp}'].append(f'{t_key} => {t_item}')
            elif 'group-object ' in t_item:
                tt_key = t_item.split()[-1]
                if tt_key in OBJ_GRP_NET_Dic:
                    for tt_item in OBJ_GRP_NET_Dic[tt_key]:
                        if 'network-object host ' in tt_item:
    ##                        if tt_item.split()[-1] in t_vals:
    ##                            print(f'Duplicated Object in {t_key}: {tt_item.split()[-1]}')
    ##                            Duplicated_Object_List.append(f'{t_key}: {tt_item.split()[-1]}')
                            t_vals.append(tt_item.split()[-1])
                            if f'{t_key}|{tt_item.split()[-1]}' not in Duplicated_Object_Dic:
                                Duplicated_Object_Dic[f'{t_key}|{tt_item.split()[-1]}'] = [f'{t_key} => {tt_key} => {tt_item}']
                            else:
                                Duplicated_Object_Dic[f'{t_key}|{tt_item.split()[-1]}'].append(f'{t_key} => {tt_key} => {tt_item}')
                        elif 'network-object object ' in tt_item:
                            if tt_item.split()[-1] in Obj_Net_Dic:
                                temp = Obj_Net_Dic[tt_item.split()[-1]]
                                temp = temp.replace('host ','')
                                temp = temp.replace('range ','')
                                temp = temp.replace('subnet ','')
                                temp = temp.replace('fqdn ','')
                            else:
                                print(f"Key not found: {tt_item.split()[-1]}")
                                print(f"network-object object {tt_item} # can be safely removed from {tt_key}")
                                Config_Change.append(f"Key not found: {tt_item.split()[-1]}\n")
                                Config_Change.append(f"network-object object {tt_item} # can be safely removed from {tt_key}\n")
    ##                        if temp in t_vals:
    ##                            print(f'Duplicated Object in {t_key}: {temp}')
    ##                            Duplicated_Object_List.append(f'{t_key}: {temp}')
                            t_vals.append(temp)
                            if f'{t_key}|{temp}' not in Duplicated_Object_Dic:
                                Duplicated_Object_Dic[f'{t_key}|{temp}'] = [f'{t_key} => {tt_key} => {tt_item}']
                            else:
                                Duplicated_Object_Dic[f'{t_key}|{temp}'].append(f'{t_key} => {tt_key} => {tt_item}')
                        elif 'group-object ' in tt_item:
                            ttt_key = tt_item.split()[-1]
                            if ttt_key in OBJ_GRP_NET_Dic:
                                for ttt_item in OBJ_GRP_NET_Dic[ttt_key]:
                                    if 'network-object host ' in ttt_item:
        ##                                if ttt_item.split()[-1] in t_vals:
        ##                                    print(f'Duplicated Object in {t_key}: {ttt_item.split()[-1]}')
        ##                                    Duplicated_Object_List.append(f'{t_key}: {ttt_item.split()[-1]}')
                                        t_vals.append(ttt_item.split()[-1])
                                        if f'{t_key}|{ttt_item.split()[-1]}' not in Duplicated_Object_Dic:
                                            Duplicated_Object_Dic[f'{t_key}|{ttt_item.split()[-1]}'] = [f'{t_key} => {tt_key} => {ttt_key} => {ttt_item}']
                                        else:
                                            Duplicated_Object_Dic[f'{t_key}|{ttt_item.split()[-1]}'].append(f'{t_key} => {tt_key} => {ttt_key} => {ttt_item}')
                                    elif 'network-object object ' in ttt_item:
                                        if ttt_item.split()[-1] in Obj_Net_Dic:
                                            temp = Obj_Net_Dic[ttt_item.split()[-1]]
                                            temp = temp.replace('host ','')
                                            temp = temp.replace('range ','')
                                            temp = temp.replace('subnet ','')
                                            temp = temp.replace('fqdn ','')
                                        else:
                                            print(f"Key not found: {ttt_item.split()[-1]}")
                                            print(f"network-object object {ttt_item} # can be safely removed from {ttt_key}")
                                            Config_Change.append(f"Key not found: {ttt_item.split()[-1]}\n")
                                            Config_Change.append(f"network-object object {ttt_item} # can be safely removed from {ttt_key}\n")
        ##                                if temp in t_vals:
        ##                                    print(f'Duplicated Object in {t_key}: {temp}')
        ##                                    Duplicated_Object_List.append(f'{t_key}: {temp}')
                                        t_vals.append(temp)
                                        if f'{t_key}|{temp}' not in Duplicated_Object_Dic:
                                            Duplicated_Object_Dic[f'{t_key}|{temp}'] = [f'{t_key} => {tt_key} => {ttt_key} => {ttt_item}']
                                        else:
                                            Duplicated_Object_Dic[f'{t_key}|{temp}'].append(f'{t_key} => {tt_key} => {ttt_key} => {ttt_item}')
                                    elif 'group-object ' in ttt_item:
                                        ttt_key = ttt_item.split()[-1]
                                    else:
                                        # network-object 10.10.100.0 255.255.254.0
        ##                                if (ttt_item.replace('network-object ','')) in t_vals:
        ##                                    print(f"Duplicated Object in {t_key}: {ttt_item.replace('network-object ','')}")
        ##                                    Duplicated_Object_List.append(f"{t_key}: {ttt_item.replace('network-object ','')}")
                                        t_vals.append(ttt_item.replace('network-object ',''))
                                        temp = ttt_item.replace('network-object ','')
                                        if f'{t_key}|{temp}' not in Duplicated_Object_Dic:
                                            Duplicated_Object_Dic[f'{t_key}|{temp}'] = [f"{t_key} => {tt_key} => {ttt_key} => {temp}"]
                                        else:
                                            Duplicated_Object_Dic[f'{t_key}|{temp}'].append(f"{t_key} => {tt_key} => {ttt_key} => {temp}")
                            else:
                                print(f"Undeclared object '{ttt_key}' used in '{t_key}': REMOVE IT!")
                                Config_Change.append(f"Undeclared object '{ttt_key}' used in '{t_key}': REMOVE IT!\n")
                        else:
                            # network-object 10.10.100.0 255.255.254.0
    ##                        if (tt_item.replace('network-object ','')) in t_vals:
    ##                            print(f"Duplicated Object in {t_key}: {tt_item.replace('network-object ','')}")
    ##                            Duplicated_Object_List.append(f"{t_key}: {tt_item.replace('network-object ','')}")
                            t_vals.append(tt_item.replace('network-object ',''))
                            temp = tt_item.replace('network-object ','')
                            if f'{t_key}|{temp}' not in Duplicated_Object_Dic:
                                Duplicated_Object_Dic[f'{t_key}|{temp}'] = [f"{t_key} => {tt_key} => {temp}"]
                            else:
                                Duplicated_Object_Dic[f'{t_key}|{temp}'].append(f"{t_key} => {tt_key} => {temp}")
                else:
                    print(f"Undeclared object '{tt_key}' used in '{t_key}': REMOVE IT!")
                    Config_Change.append(f"Undeclared object '{tt_key}' used in '{t_key}': REMOVE IT!\n")

            else:
                # network-object 10.10.100.0 255.255.254.0
##                if (t_item.replace('network-object ','')) in t_vals:
##                    print(f"Duplicated Object in {t_key}: {t_item.replace('network-object ','')}")
##                    Duplicated_Object_List.append(f"{t_key}: {t_item.replace('network-object ','')}")
                t_vals.append(t_item.replace('network-object ',''))
                temp = t_item.replace('network-object ','')
                if f'{t_key}|{temp}' not in Duplicated_Object_Dic:
                    Duplicated_Object_Dic[f'{t_key}|{temp}'] = [f"{t_key} => {temp}"]
                else:
                    Duplicated_Object_Dic[f'{t_key}|{temp}'].append(f"{t_key} => {temp}")
        OBJ_GRP_NET_Dic_explode[t_key] = t_vals

    Dup_OBJGRP_NET_List = []
    Found_keys = []
    t_key_List = list(OBJ_GRP_NET_Dic_explode)
    for n1 in range(0,len(t_key_List)):
        if t_key_List[n1] in Found_keys:
            continue
        temp_Dup_OBJGRP_NET_List = [t_key_List[n1]]
        t1_vals = OBJ_GRP_NET_Dic_explode[t_key_List[n1]]
        for n2 in range(n1+1,len(t_key_List)):
            t2_vals = OBJ_GRP_NET_Dic_explode[t_key_List[n2]]
            if len(t1_vals) == len(t2_vals):
                Flags = [0]*len(t1_vals)
                for n3 in range(0,len(t1_vals)):
                    if t1_vals[n3] in t2_vals:
                        Flags[n3] = 1
                if sum(Flags) == len(t1_vals):
                    temp_Dup_OBJGRP_NET_List.append(t_key_List[n2])
                    Found_keys.append(t_key_List[n2])
        if len(temp_Dup_OBJGRP_NET_List) > 1:
            Dup_OBJGRP_NET_List.append(temp_Dup_OBJGRP_NET_List)

    t_N_OBJ_GRP_NET_Duplicated = sum(len(sublist) for sublist in Dup_OBJGRP_NET_List)

    print('Number of OBJ NET Duped = %s' %t_N_OBJ_GRP_NET_Duplicated)
    print('len(Dup_OBJGRP_NET_List) = %s' %len(Dup_OBJGRP_NET_List))

    Watch_Flist = []
    Watch_Flist.append('<div class="card-body">\n')
    Watch_Flist.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_Flist.append('       <thead><tr>\n')
    Watch_Flist.append('           <th class="px-2">Obj-Grp Network</th>\n')
    Watch_Flist.append('           <th class="px-2">Object Name</th>\n')
    Watch_Flist.append('       </tr></thead>\n')
    Watch_Flist.append('       <tbody>\n')
    for n in range(0,len(Dup_OBJGRP_NET_List)):
        Watch_Flist.append('       <tr>\n')
        t_group = Dup_OBJGRP_NET_List[n]
        Watch_Flist.append('       <td class="font-weight-bold text-nowrap px-2">\n')
        for t_obj in OBJ_GRP_NET_Dic_explode[t_group[0]]:
            Watch_Flist.append('       %s<br>\n' %t_obj)
        Watch_Flist.append('       </td>\n')
        Watch_Flist.append('       <td class="px-2">\n')
        for m in range (0,len(t_group)):
            Watch_Flist.append('       %s<br>\n' %t_group[m])
        Watch_Flist.append('       </td>\n')
        Watch_Flist.append('       </tr>\n')
    Watch_Flist.append('       </tbody>\n')
    Watch_Flist.append('   </table>\n')
##    Watch_Flist.append('   <br>\n')
##    Watch_Flist.append('   <ul>\n')
##    for t_line in Duplicated_Object_List:
##        Watch_Flist.append(f'   <li>{t_line}</li>\n')
##    Watch_Flist.append('   </ul>\n')
    Watch_Flist.append('   <br>\n')
    for t_key in Duplicated_Object_Dic:
        if len(Duplicated_Object_Dic[t_key]) > 1:
            Watch_Flist.append(f'   <ul><li>{t_key}\n')
            Watch_Flist.append('   <ul>\n')
            for t_item in Duplicated_Object_Dic[t_key]:
                #Watch_Flist.append(f'   <li>{t_item.replace("=>","&nbsp;<b>=></b>&nbsp;")}</li>\n')
                t_item = utils_v2.Color_Line(t_item)
                Watch_Flist.append('   <li>%s</li>\n' %t_item.replace("=>"," &nbsp; <b><font color='#ba1e28'>=></font></b> &nbsp; "))
            Watch_Flist.append('   </ul>\n')
            Watch_Flist.append('   </li></ul>\n')
    Watch_Flist.append('</div>\n')

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-ObjGrpNet_Duplicated-Watch.html'
    log_msg = File_Save_Try2(Watch_FName, Watch_Flist, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))


##    (=================================================)
##    (==     Search_For_Duplicated_Obj_Service_      ==)
##    (=================================================)
    N_of_Duplicated_OBJ_SVC = 0
    Duplicated_OBJ_SVC = {}
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_SVC_Dic"
    OBJ_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    for m in range(0,len(OBJ_SVC_Dic)):
        tm_key = list(OBJ_SVC_Dic)[m]
        tm_item = OBJ_SVC_Dic[tm_key]
        for mm in range(m+1,len(OBJ_SVC_Dic)):
            tmm_key = list(OBJ_SVC_Dic)[mm]
            tmm_item = OBJ_SVC_Dic[tmm_key]
            if tmm_item == tm_item:
                Duplicated_OBJ_SVC[tm_item] = [tm_key]
                if tmm_key not in Duplicated_OBJ_SVC[tm_item]:
                    Duplicated_OBJ_SVC[tm_item].append(tmm_key)
    if len(Duplicated_OBJ_SVC)>0:
        for t_key in Duplicated_OBJ_SVC:
            temp = '|'.join(Duplicated_OBJ_SVC[t_key])

    N_of_Duplicated_OBJ_SVC = sum(len(sublist) for sublist in list(Duplicated_OBJ_SVC.values()))
    #Prcnt_N_of_Duplicated_OBJ_SVC = round(100*N_of_Duplicated_OBJ_SVC/len(OBJ_SVC_Dic),1) if (len(OBJ_SVC_Dic)!=0) else 0

    Watch_Flist = []
    Watch_Flist.append('<div class="card-body">\n')
    Watch_Flist.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_Flist.append('       <thead><tr>\n')
    Watch_Flist.append('           <th class="px-2">Service</th>\n')
    Watch_Flist.append('           <th class="px-2">Service Name</th>\n')
    Watch_Flist.append('       </tr></thead>\n')
    Watch_Flist.append('       <tbody>\n')
    for t_key in Duplicated_OBJ_SVC:
        Watch_Flist.append('       <tr>\n')
        Watch_Flist.append('           <td class="font-weight-bold text-nowrap px-2">%s</td>\n' %t_key)
        Watch_Flist.append('       <td class="px-2">\n')
        for n in range(0,len(Duplicated_OBJ_SVC[t_key])):
            Watch_Flist.append('%s<br>' %Duplicated_OBJ_SVC[t_key][n])
        Watch_Flist.append('       </td>\n')
        Watch_Flist.append('       </tr>\n')
    Watch_Flist.append('       </tbody>\n')
    Watch_Flist.append('   </table>\n')
    Watch_Flist.append('</div>\n')

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-ObjSvc_Duplicated-Watch.html'
    log_msg = File_Save_Try2(Watch_FName, Watch_Flist, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    Think_Flist = []
    Think_Flist.append('<div class="card-body">\n')
    Think_Flist.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Think_Flist.append('       <thead><tr>\n')
    Think_Flist.append('           <th>Object Service</th>\n')
    Think_Flist.append('       </tr></thead>\n')
    Think_Flist.append('       <tbody>\n')
    for t_key in Duplicated_OBJ_SVC:
        Think_Flist.append('       <tr><td class="text-nowrap mr-2">\n')
        Think_Flist.append('<ul>\n')
        Think_Flist.append('      <br><li>\n')
        Think_Flist.append('      %s<br>\n' %t_key)
        Think_Flist.append('      </li>\n')
        Think_Flist.append('<ul>\n')
        for t_item in Duplicated_OBJ_SVC[t_key]:
            Think_Flist.append('      <br><li>\n')
            Think_Flist.append('      <mark>%s</mark><br>\n' %t_item)
            Out = []
            t_Out = Where_Used(t_device, t_item, FW_log_folder, Out)
            if t_Out:
                for line in t_Out:
                    Think_Flist.append(line+'<br>')

            Think_Flist.append('      </li>\n')
        Think_Flist.append('</ul>\n')
        Think_Flist.append('       </ul></td></tr>\n')
    Think_Flist.append('       </tbody>\n')
    Think_Flist.append('   </table>\n')
    Think_Flist.append('</div>\n')

    for i in range(0,len(Think_Flist)):
        t_line = Think_Flist[i]
        if t_line.split()[0] == '<_CODE_>':
            t_line = ' '.join(t_line.split()[1:])
            t_line = utils_v2.Color_Line(t_line)
            Think_Flist[i] = f'{t_line}\n'
        elif t_line.split()[0] == '<_L1_TEXT_>':
            Think_Flist[i] = ('%s\n' %' '.join(t_line.split()[1:]))
        elif t_line.split()[0] == '<_L2_TEXT_>':
            Think_Flist[i] = ('%s\n' %' '.join(t_line.split()[1:]))

    Think_FName   = FW_log_folder + '/' + hostname___ + '-ObjSvc_Duplicated-Think.html'
    log_msg = File_Save_Try2(Think_FName, Think_Flist, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))


##    (=================================================)
##    (==    Search_For_Duplicated_Obj-Grp_Service    ==)
##    (=================================================)
    # apri OBJ_GRP_SVC_Dic ed esplode ricorsivamente tutte le entry per ottenere solo ip
    # controlla se ci sono duplicati

##FW-01/act/pri(config)# object-group service ttt
##  description     Specify description text
##  group-object    Configure an object group as an object
##  help            Help for service object-group configuration commands
##  no              Remove an object or description from object-group
##  service-object  Configure a service object
##
##FW-01/act/pri(config)# object-group service tttt tcp
##  description   Specify description text
##  group-object  Configure an object group as an object
##  help          Help for service object-group configuration commands
##  no            Remove an object or description from object-group
##  port-object   Configure a port object

    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic:
        if len(t_OBJ_GRP_SVC_Dic_key.split()) == 2:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)

    OBJ_GRP_SVC_Dic_explode = {}
    for t_key in OBJ_GRP_SVC_Dic_2:
        t_vals = []
        for t_item in OBJ_GRP_SVC_Dic_2[t_key]:
            if 'port-object ' in t_item:
                t_vals.append(t_item.strip().replace('port-object ',''))
            elif 'service-object ' in t_item:
                t_vals.append(t_item.strip().replace('service-object ',''))
            elif 'group-object ' in t_item:
                tt_key = t_item.strip().replace('group-object ','')
                if tt_key in OBJ_GRP_SVC_Dic_2:
                    for tt_item in OBJ_GRP_SVC_Dic_2[tt_key]:
                        if 'port-object ' in tt_item:
                            t_vals.append(tt_item.strip().replace('port-object ',''))
                        elif 'service-object ' in tt_item:
                            t_vals.append(tt_item.strip().replace('service-object ',''))
                        elif 'group-object ' in tt_item:
                            ttt_key = tt_item.strip().replace('group-object ','')
                            if ttt_key in OBJ_GRP_SVC_Dic_2:
                                if ttt_key == 'ephemeral_port':
                                    print('stop')
                                for ttt_item in OBJ_GRP_SVC_Dic_2[ttt_key]:
                                    if 'port-object ' in ttt_item:
                                        t_vals.append(ttt_item.strip().replace('port-object ',''))
                                    elif 'service-object ' in ttt_item:
                                        t_vals.append(ttt_item.strip().replace('service-object ',''))
                                    elif 'group-object ' in ttt_item:
                                        ttt_key = ttt_item.strip().replace('group-object ','')
                                    else:
                                        print('... there is some problem here')
                            else:
                                print(f"Key not found: {ttt_key}")
                                print(f"group-object {ttt_key} # can be safely removed from {tt_key}")
                                Config_Change.append(f"Key not found: {ttt_key}\n")
                                Config_Change.append(f"group-object {ttt_key} # can be safely removed from {tt_key}\n")
                        else:
                            print('... there is some problem here')
                else:
                    print(f"Key not found: {tt_key}")
                    print(f"group-object {tt_key} # can be safely removed from {t_key}")
                    Config_Change.append(f"Key not found: {tt_key}\n")
                    Config_Change.append(f"group-object {tt_key} # can be safely removed from {t_key}\n")

            else:
                print('... there is some problem here')
        OBJ_GRP_SVC_Dic_explode[t_key] = t_vals

    Dup_OBJGRP_SVC_List = []
    Found_keys = []
    t_key_List = list(OBJ_GRP_SVC_Dic_explode)
    for n1 in range(0,len(t_key_List)):
        if t_key_List[n1] in Found_keys:
            continue
        temp_Dup_OBJGRP_SVC_List = [t_key_List[n1]]
        t1_vals = OBJ_GRP_SVC_Dic_explode[t_key_List[n1]]
        for n2 in range(n1+1,len(t_key_List)):
            t2_vals = OBJ_GRP_SVC_Dic_explode[t_key_List[n2]]
            if len(t1_vals) == len(t2_vals):
                Flags = [0]*len(t1_vals)
                for n3 in range(0,len(t1_vals)):
                    if t1_vals[n3] in t2_vals:
                        Flags[n3] = 1
                if sum(Flags) == len(t1_vals):
                    temp_Dup_OBJGRP_SVC_List.append(t_key_List[n2])
                    Found_keys.append(t_key_List[n2])
        if len(temp_Dup_OBJGRP_SVC_List) > 1:
            Dup_OBJGRP_SVC_List.append(temp_Dup_OBJGRP_SVC_List)

    t_N_OBJ_GRP_SVC_Duplicated = sum(len(sublist) for sublist in Dup_OBJGRP_SVC_List)

    print('Number of OBJ SVC Duped = %s' %t_N_OBJ_GRP_SVC_Duplicated)
    print('len(Dup_OBJGRP_SVC_List) = %s' %len(Dup_OBJGRP_SVC_List))

    Watch_Flist = []
    Watch_Flist.append('<div class="card-body">\n')
    Watch_Flist.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_Flist.append('       <thead><tr>\n')
    Watch_Flist.append('           <th class="px-2">Obj-Grp Service</th>\n')
    Watch_Flist.append('           <th class="px-2">Object Name</th>\n')
    Watch_Flist.append('       </tr></thead>\n')
    Watch_Flist.append('       <tbody>\n')
    for n in range(0,len(Dup_OBJGRP_SVC_List)):
        Watch_Flist.append('       <tr>\n')
        t_group = Dup_OBJGRP_SVC_List[n]
        Watch_Flist.append('       <td class="font-weight-bold text-nowrap px-2">\n')
        for t_obj in OBJ_GRP_SVC_Dic_explode[t_group[0]]:
            Watch_Flist.append('       %s<br>\n' %t_obj)
        Watch_Flist.append('       </td>\n')
        Watch_Flist.append('       <td class="px-2">\n')
        for m in range (0,len(t_group)):
            Watch_Flist.append('       %s<br>\n' %t_group[m])
        Watch_Flist.append('       </td>\n')
        Watch_Flist.append('       </tr>\n')
    Watch_Flist.append('       </tbody>\n')
    Watch_Flist.append('   </table>\n')
    Watch_Flist.append('</div>\n')

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-ObjGrpSvc_Duplicated-Watch.html'
    log_msg = File_Save_Try2(Watch_FName, Watch_Flist, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    netobjusedList = []
    Undeclared_NetObj_Used_List = []
    for n in Undeclared_NetObj_List:
        if n in Obejct_by_value_Dict:
            netobjusedList.append('object <b>%s</b> declared as network-object but object network %s exists' %(n,Obejct_by_value_Dict[n]))
            Undeclared_NetObj_Used_List.append(n)

    netobjusedList.append('\n\nNumber of undeclared "network-object" = %s' %len(Undeclared_NetObj_List))
    netobjusedList.append('Number of equivalent "object network" = %s' %len(Undeclared_NetObj_Used_List))
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-netobjused-Watch.html'
    Write_Think_File(Fix_FName, netobjusedList)

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Undeclared_NetObj_Used_List"
    retries = utils_v2.Shelve_Write_Try(tf_name,Undeclared_NetObj_Used_List)

    #Config_Change.append('')
    for t_key in OBJ_GRP_NET_Dic:
        Printed_Header = False
        for t_item in OBJ_GRP_NET_Dic[t_key]:
            if t_item.startswith(' network-object host '):
                temp = t_item.split()[2]
                if temp in Obejct_by_value_Dict:
                    if Printed_Header == False:
                        Config_Change.append('!\nobject-group network %s' %t_key)
                        Printed_Header = True
                    Config_Change.append(' network-object object %s' %Obejct_by_value_Dict[temp][0])
                    Config_Change.append(' no network-object host %s' %temp)
            elif t_item.startswith(' network-object '):
                if len(t_item.replace(' ','.').split('.')) == 10:
                    temp = t_item.split()[1] + ' ' + t_item.split()[2]
                    if temp in Obejct_by_value_Dict:
                        if Printed_Header == False:
                            Config_Change.append('!\nobject-group network %s' %t_key)
                            Printed_Header = True
                        Config_Change.append(' network-object object %s' %Obejct_by_value_Dict[temp][0])
                        Config_Change.append(' no network-object %s' %temp)

##    (=================================================)
##    (==              Update_Db_Values               ==)
##    (=================================================)
    if DB_Available:
        Updated_Vals = dict(
                            N_OBJ_NET_Duplicated  = N_of_unique_Duplicated_OBJ_NET,
                            N_OBJ_GRP_NET_Duplicated = t_N_OBJ_GRP_NET_Duplicated,
                            N_OBJ_SVC_Duplicated = N_of_Duplicated_OBJ_SVC,
                            N_OBJ_GRP_SVC_Duplicated = t_N_OBJ_GRP_SVC_Duplicated,
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)
        engine.dispose()

    return Config_Change

##=============================================================================================================================
##   __    ___  __      ___  _____  __  __  ____   ___  ____    _  _  ___    ____  _____  __  __  ____  ____  _  _  ___    ____   __    ____  __    ____
##  /__\  / __)(  )    / __)(  _  )(  )(  )(  _ \ / __)( ___)  ( \/ )/ __)  (  _ \(  _  )(  )(  )(_  _)(_  _)( \( )/ __)  (_  _) /__\  (  _ \(  )  ( ___)
## /(__)\( (__  )(__   \__ \ )(_)(  )(__)(  )   /( (__  )__)    \  / \__ \   )   / )(_)(  )(__)(   )(   _)(_  )  (( (_-.    )(  /(__)\  ) _ < )(__  )__)
##(__)(__)\___)(____)  (___/(_____)(______)(_)\_) \___)(____)    \/  (___/  (_)\_)(_____)(______) (__) (____)(_)\_)\___/   (__)(__)(__)(____/(____)(____)

def ACL_Source_Vs_Routing_Table(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    FW_log_folder = log_folder + '/' + hostname___
    html_folder = FW_log_folder

    re_space = re.compile(r'  +') # two or more spaces

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            WTF_Log = db.Table('WTF_Log', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_List_Dict"
    ACL_List_Dict = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_ACL"
    Accessgroup_Dic_by_ACL = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ROUTE_DF"
    ROUTE_DF = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Name_dic"
    Name_dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_GRP_NET_Dic"
    OBJ_GRP_NET_Dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obj_Net_Dic"
    Obj_Net_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    Printed_Lines = set()
    NoActive_NoRoute_Root_ACL = []
    #SiActive_NoRoute_Root_ACL = []
    #NoActive_NoRoute_Child_ACL = []
    #SiActive_NoRoute_Child_ACL = []
    #NoActive_Noroute_Hash_ACL_Dic = {}
    SiActive_Noroute_Hash_ACL_Dic = {}

    Double_NO_Active_Hash = []
    Double_SI_Active_Hash = []
    Totally_Wrong_Routing_Active_ACL = []
    #Partlly_Wrong_Routing_Active_ACL = []
    Partlly_Wrong_Routing_Active_ACL_Dic = {}
    Totally_Wrong_Routing_Active_ACL_Counting = []

    text = f'Check Acl Source Vs Routing Table @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    Config_Change.append('Check if URPF (Unicast Reverse Path Forwarding) is enabled\n')

    Obj_vs_Route_Lookup = {}
    Obj_vs_Iface_Lookup = {}
    ROUTE_IP_DF = ROUTE_DF.copy()

    ACL_WiderThanRouting = {}
    BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List_Dict)
    #for t_key in list(ACL_List_Dict):
    for t_key, acl in ACL_List_Dict.items():
        t_Root__Hash = t_key.split()[-1]
        t_Child_Hash = []

        LOOP_INDEX = LOOP_INDEX + 1
        if LOOP_INDEX > (ITEMS/STEPS)*BINS:
            print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1

        t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_key])
        t_ACL_If_Name = ''
        try:
            t_ACL_Name = t_ACL_Lines_DF.Name[0]
        except:
            print(f'DEBUG: ACL index 0 is out of bounds t_ACL_Lines_DF.Name[0] for {t_ACL_Lines_DF}')
            continue
        try:
            t_ACL_If_Name = Accessgroup_Dic_by_ACL[t_ACL_Name]
        except:
            print(f'DEBUG: ACL If_Name not associated with any interface: {t_ACL_If_Name}')
            continue

        for row in t_ACL_Lines_DF.itertuples():
            #print(f'row = {row}')
            this_Src_Obj = utils_v2.ASA_ACL_Obj_to_Net(row.Source)
            if this_Src_Obj == []: # ipv6 to be done
                continue
            for t_this_Src_Obj in this_Src_Obj:
##                if '10.10.10.6' in t_this_Src_Obj:
##                    print('row')
##                else:
##                    break
                #print(f't_this_Src_Obj = {t_this_Src_Obj}')
                temp = t_this_Src_Obj.split()
                try:
                    t_this_Src_Obj = temp[0] + Sub_Mask_2[temp[1]]
                except:
                    text_line = f'>>>   ERROR... non conventional subnet mask for "{t_this_Src_Obj}"'
                    if text_line not in Printed_Lines:
                        #print(text_line)
                        Config_Change.append(text_line)
                        Printed_Lines.add(text_line)
                        row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                               'Level'     : 'WARNING',
                               'Message'   : (f'Non Conventional Subnet Mask for "{t_this_Src_Obj}" in {t_device}')}
                        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
                    continue
                try:
                    this_Src_Obj_IP = ipaddress.IPv4Network(t_this_Src_Obj, strict=False)
                except:
                    this_Src_Obj_IP = ipaddress.IPv4Network(Name_dic[t_this_Src_Obj] + '/32', strict=False)
                    print('--- Name_dic object in ACL_Source_Vs_Routing %s:' %t_this_Src_Obj)

                #Wider_Object_Found = False
                BEST_ROUTE_IF = ''
                BEST_ROUTE_IP = ''

                if this_Src_Obj_IP in Obj_vs_Route_Lookup:
                    BEST_ROUTE_IP = Obj_vs_Route_Lookup[this_Src_Obj_IP]
                    BEST_ROUTE_IF = Obj_vs_Iface_Lookup[this_Src_Obj_IP]
                else:
                    for _, this_route in ROUTE_IP_DF.iterrows():
                        # Check if this_Src_Obj_IP is a subnet of this_route['Network']
                        if this_Src_Obj_IP.subnet_of(this_route['Network']):
                            BEST_ROUTE_IP = this_route['Network']
                            Obj_vs_Route_Lookup[this_Src_Obj_IP] = BEST_ROUTE_IP
                            BEST_ROUTE_IF = this_route['Interface']
                            Obj_vs_Iface_Lookup[this_Src_Obj_IP] = BEST_ROUTE_IF
                            break

                WIDE_ROUTE_List = []
                if isinstance(BEST_ROUTE_IP, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    best_prefixlen = BEST_ROUTE_IP.prefixlen
                else:
                    best_prefixlen = -1
                Bool_check = ('Interface == "%s"') %(t_ACL_If_Name)
                if (best_prefixlen == 0) or (BEST_ROUTE_IF == ''): #no best route found
                    if t_this_Src_Obj != '0.0.0.0/0':
                        t_ROUTE_IP_DF = ROUTE_IP_DF.loc[ROUTE_IP_DF['Interface'] == t_ACL_If_Name]
                        ROUTE_IP_DF_Hi = t_ROUTE_IP_DF.loc[t_ROUTE_IP_DF['PrefixLength'] > this_Src_Obj_IP.prefixlen]
                        ROUTE_IP_DF_Hi_Net_List = ROUTE_IP_DF_Hi['Network'].tolist()
                        for this_route in ROUTE_IP_DF_Hi_Net_List:
                            try:
                                if this_route.subnet_of(this_Src_Obj_IP):
                                    WIDE_ROUTE_List.append(str(this_route))
                            except:
                                print('Error at line 2333:')
                                print('this_route = %s' %this_route)
                                print('this_Src_Obj_IP = %s' %this_Src_Obj_IP)
                                exit()

                if WIDE_ROUTE_List != []:
                    ACL_WiderThanRouting[t_key] = []
                    text_line = f' - Surce_Object is <b>{t_this_Src_Obj}</b>, interface is <b>{t_ACL_If_Name}</b>, routing is:'
                    ACL_WiderThanRouting[t_key].append(text_line)
                    temp = []
                    for n in WIDE_ROUTE_List:
                        temp.append(n)
                    ACL_WiderThanRouting[t_key].append(temp)

                if t_this_Src_Obj != '0.0.0.0/0':
                    #if ((BEST_ROUTE_IF=='') and (WIDE_ROUTE_List==[])) or ((BEST_ROUTE_DF.Interface!='-') and (BEST_ROUTE_DF.Interface!=t_ACL_If_Name)):
                    if ((BEST_ROUTE_IF!=t_ACL_If_Name) and (WIDE_ROUTE_List==[])) or ((BEST_ROUTE_IF!='-') and (BEST_ROUTE_IF!=t_ACL_If_Name)):
                        temp1 = [row.ACL, row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, row.Hitcnt, row.Hash]
                        if 'inactive' in row.Inactive:
                            if row.Hash not in t_Child_Hash:
                                t_Child_Hash.append(row.Hash)
                            else:
                                if 'range' not in row.Source:
                                    Double_NO_Active_Hash.append(re_space.sub(' ',' '.join(temp1)))
                        else:
                            if row.Hash not in t_Child_Hash:
                                t_Child_Hash.append(row.Hash)
                            else:
                                if 'range' not in row.Source:
                                    Double_SI_Active_Hash.append(re_space.sub(' ',' '.join(temp1)))
                            SiActive_Noroute_Hash_ACL_Dic[t_Root__Hash] = t_Child_Hash

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            ACL_GROSS = db.Table('ACL_GROSS', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    if DB_Available:
        query = db.select(ACL_GROSS).where(ACL_GROSS.c.HostName=="%s" %hostname___)
        with engine.connect() as connection:
            ACL_GROSS_df = pd.DataFrame(connection.execute(query).fetchall())
        if ACL_GROSS_df.shape[0] > 0:
            ACL_GROSS_df = ACL_GROSS_df.drop(labels='ID', axis=1)

    re_space = re.compile(r'  +') # two or more spaces
    ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict.keys())
    for t_key in list(SiActive_Noroute_Hash_ACL_Dic):
        Bool_check = ('Hash == "%s"') %(t_key)
        for row in ACL_Lines_DF.query(Bool_check).itertuples(): # one item
            if row.Inactive == 'inactive':
                continue
            ACL_Lines_DF.loc[row.Index, 'Hitcnt'] = "(hitcnt=%s)" %row.Hitcnt
            temp1 = [row.ACL, row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, '(hitcnt='+row.Hitcnt+')', row.Hash]
            t_Root_key = re_space.sub(' ',' '.join(temp1))

            try:
                t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_Root_key])
            except Exception as e:
                print('t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_Root_key])')
                print(f"error is: {e}")
                continue
            t_ACL_Lines_DF_check = t_ACL_Lines_DF.copy()
            for t_row in t_ACL_Lines_DF.itertuples():
                for t_hash in SiActive_Noroute_Hash_ACL_Dic[t_key]:
                    if t_row.Hash == t_hash:
                        t_ACL_Lines_DF_check = t_ACL_Lines_DF_check.drop(t_row.Index)
            if len(t_ACL_Lines_DF_check) == 0:
                Totally_Wrong_Routing_Active_ACL.append(t_Root_key)
                # check if the acl is incrementing
                # ==> wrong return routing but still traffic coming in... this is a problem!
                if DB_Available:
                    Bool_check = ('Hash == "%s"') %(t_key)
                    t_Delta_HitCnt = ACL_GROSS_df.query(Bool_check)['Delta_HitCnt']
                    if len(t_Delta_HitCnt) > 1:
                        print(f'too many rows with the same hash = {t_key}')
                        print(f'row = {row}')
                        continue
                    elif t_Delta_HitCnt.item() > 0:
                        Totally_Wrong_Routing_Active_ACL_Counting.append([t_Delta_HitCnt.item(),t_Root_key])
            else:
                temp = []
                for t_row in t_ACL_Lines_DF.itertuples():
                    if t_row.Hash in SiActive_Noroute_Hash_ACL_Dic[t_key]:
                        temp1 = [t_row.ACL, t_row.Name, t_row.Line, t_row.Type, t_row.Action, t_row.Service, t_row.Source, t_row.S_Port, t_row.Dest, t_row.D_Port, t_row.Rest, t_row.Inactive, '(hitcnt='+t_row.Hitcnt+')', t_row.Hash]
                        temp.append(re_space.sub(' ',' '.join(temp1)))
                Partlly_Wrong_Routing_Active_ACL_Dic[t_Root_key] = temp

    text_line = '\n--- Double Hash and Inactive ACL ---'
    print(text_line)
    Config_Change.append(text_line)
    for n in Double_NO_Active_Hash:
        Config_Change.append(n)

    text_line = '\n--- Double Hash and Active ACL ---'
    print(text_line)
    Config_Change.append(text_line)
    for n in Double_SI_Active_Hash:
        Config_Change.append(n)

    # OUTPUT HTML FILE for Wrong_Routing_for_ACL_Still_Matching --------------------------------------------------------
    text_line = '\n--- Totally Wrong Routing for ACL still matching ---'
    t_html_file = []
    if len(Totally_Wrong_Routing_Active_ACL_Counting) > 0:
        t_html_file.append('''\n
            <table class="table-bordered table-condensed table-striped" width="100%" cellspacing="0" data-order='[[ 0, "desc" ]]' data-page-length="50" >\n
            <thead>\n
              <tr>\n
                <th class="px-2">HitCnt</th>\n
                <th class="px-2">ACL</th>\n
              </tr>\n
            </thead>\n
            <tbody>\n''')
        for t_line in Totally_Wrong_Routing_Active_ACL_Counting:
            t_html_file.append('       <tr>')
            t_html_file.append('           <td class="px-2">%s</td>\n' %t_line[0])
            t_html_file.append('           <td class="px-2">%s</td>\n' %utils_v2.Color_Line(t_line[1]))
            t_html_file.append('       </tr>\n')
        t_html_file.append('''\n
            </tbody>\n
            </table>\n''')
    else:
        t_html_file.append('nothing to show\n')

    Watch_FName = f"{html_folder}/{hostname___}-WR4ACLCounting-Watch.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))


    # OUTPUT HTML FILE for ACL_WiderThanRouting -------------------------------------------------------------------------
    t_html_file = []
    if len(ACL_WiderThanRouting) > 0:
        t_html_file.append('<ul>')
        for t_key in ACL_WiderThanRouting:
            t_html_file.append('<li> %s<br>' %utils_v2.Color_Line(t_key))
            t_html_file.append('%s' %ACL_WiderThanRouting[t_key][0])
            t_html_file.append('<p class="text-dark small">')
            for t_route in ACL_WiderThanRouting[t_key][1]:
                t_html_file.append('&nbsp;' + t_route +'<br>')

            t_html_file.append('</p></li>')
        t_html_file.append('</ul>')
    else:
        t_html_file.append('nothing to show\n')

    Watch_FName = f"{html_folder}/{hostname___}-ACL_WiderThanRouting-Watch.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))


    # OUTPUT HTML FILE for Totally_Wrong_Routing_Active_ACL -------------------------------------------------------------------------
    t_html_file = []
    if len(Totally_Wrong_Routing_Active_ACL) > 0:
        Totally_Wrong_Routing_Active_ACL.reverse()
        for n in Totally_Wrong_Routing_Active_ACL:
            t_html_file.append('%s<br>' %utils_v2.Color_Line(n))
    else:
        t_html_file.append('nothing to show\n')

    Watch_FName = f"{html_folder}/{hostname___}-TotWrongRouteACL-Watch.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))


    # OUTPUT HTML FILE for Partlly_Wrong_Routing_Active_ACL_Dic -------------------------------------------------------------------------
    PartlyWrongRouteACL = {}
    text_line = '\n--- Partially Wrong Routing for ACL ---'
    print(text_line)
    Config_Change.append(text_line)
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines_DF"
    Show_ACL_Lines_DF = utils_v2.Shelve_Read_Try(tf_name,'')
    Processed_line = []
    Processed_ACL_line = []
    for t_key in Partlly_Wrong_Routing_Active_ACL_Dic:
        Root_ACL_df  = utils_v2.ASA_ACL_to_DF_light([t_key])
        check_point = Root_ACL_df['Name'][0] + ' ' + Root_ACL_df['Source'][0]
        if check_point not in Processed_ACL_line:
            PartlyWrongRouteACL[t_key] = []
            Processed_ACL_line.append(check_point)

            Child_ACL_Df = utils_v2.ASA_ACL_to_DF_light(Partlly_Wrong_Routing_Active_ACL_Dic[t_key])
            Child_ACL_Df = Child_ACL_Df.drop(['Service','S_Port','Dest','Rest'], axis=1)
            Child_ACL_Df = Child_ACL_Df.drop_duplicates()
            t_OBJ_Src = Root_ACL_df['Source'][0]

            Bool_check = ('Source == "%s"') %(t_OBJ_Src)
            t_Where_OBJ_Src_df = Show_ACL_Lines_DF.query(Bool_check)
            Bool_check = ('Dest == "%s"') %(t_OBJ_Src)
            t_Where_OBJ_Dst_df = Show_ACL_Lines_DF.query(Bool_check)

            if len(t_Where_OBJ_Src_df['Name'].drop_duplicates()) == 1:
                PartlyWrongRouteACL[t_key].append('Object "%s" used as source in this ACL only' %t_OBJ_Src)
                if len(t_Where_OBJ_Dst_df) == 0:
                    PartlyWrongRouteACL[t_key].append('Object "%s" not used as destination' %t_OBJ_Src)
                    #print('Object can be removed...')

                    if (t_OBJ_Src.split()[0]) == 'object':
                        this_src_OBJ = t_OBJ_Src.split()[1]
                        print(".. object... WTF???? Dovrebbe essere un totally wrong routing.... ")
                        print('t_OBJ_Src = %s' %t_OBJ_Src)
                        print('t_key = %s' %t_key)
                    elif(t_OBJ_Src.split()[0]) == 'object-group':
                        this_src_OBJ = t_OBJ_Src.split()[1]
                        PartlyWrongRouteACL[t_key].append('object-group network %s' %this_src_OBJ)
                        this_Obj_Grp = OBJ_GRP_NET_Dic[this_src_OBJ]

                        for row in Child_ACL_Df.itertuples():
                            src_to_find = row.Source
                            PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)

                            if 'host ' in src_to_find:
                                src_to_find = src_to_find.split()[1]
                                for item in this_Obj_Grp:
                                    if 'network-object host' in item:
                                        if item.split()[2] == src_to_find:
                                            PartlyWrongRouteACL[t_key].append('no %s' %item)
                                    elif 'network-object object' in item:
                                        objnet_2_find = item.split()[2]
                                        objnet_item = Obj_Net_Dic[objnet_2_find]
                                        if src_to_find in objnet_item:
                                            PartlyWrongRouteACL[t_key].append('no %s' %item)
                                    elif 'group-object' in item:
                                        # ----- nested host, recursive lookup to be done -----
                                        continue
                                    elif 'network-object ' in item:
                                        if src_to_find in item:
                                            PartlyWrongRouteACL[t_key].append('no %s' %item)
                                    else:
                                        print('eccezione da gestire!!!!!')
                                        print('src_to_find = %s' %src_to_find)
                                        print('item = %s' %item)
                                        print('t_key = %s' %t_key)
                                        print('row = %s' %row)
                                        exit(12345)

                            else:
                                item_Found = False
                                for item in this_Obj_Grp:
                                    if 'network-object host' in item:
                                        # this should be handled by the upper if
                                        continue
                                    elif 'network-object object' in item:
                                        objnet_2_find = item.split()[2]
                                        objnet_item = Obj_Net_Dic[objnet_2_find]
                                        if src_to_find in objnet_item:
                                            PartlyWrongRouteACL[t_key].append('no %s' %item)
                                        item_Found = True
                                    elif 'group-object' in item:
                                        # ----- nested host, recursive lookup to be done -----
                                        item_Found = True
                                        continue
                                    elif 'network-object ' in item:
                                        if src_to_find in item:
                                            PartlyWrongRouteACL[t_key].append('no network-object %s' %item)
                                        item_Found = True
                                if item_Found == False:
                                    print('exception to be handled!!!!!')
                                    print('src_to_find = %s' %src_to_find)
                                    print('item = %s' %item)
                                    print('t_key = %s' %t_key)
                                    print('row = %s' %row)
                                    exit(67890)

                    elif(t_OBJ_Src.split()[0]) == 'host':
                        this_src_OBJ = t_OBJ_Src.split()[1]
                        print(".. host... WTF???? should be a totally wrong routing.... ")
                    elif '.' in t_OBJ_Src.split()[0]:
                        try:
                            t_this_Src_ip = t_OBJ_Src.split()[0] + Sub_Mask_2[t_OBJ_Src.split()[1]]
                            ipaddress.IPv4Network(t_this_Src_ip, strict=False)
                            PartlyWrongRouteACL[t_key].append('no %s' %t_OBJ_Src)
                        except:
                            print('check what is passed @%s' %t_this_Src_ip)
                            exit('0000')
                else:
                    PartlyWrongRouteACL[t_key].append('Object "%s" used as destination in other ACL' %t_OBJ_Src)
                    temp = tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False).split('\n')
                    for line in temp:
                        PartlyWrongRouteACL[t_key].append(line.replace(' ','&nbsp;'))
                    for row in Child_ACL_Df.itertuples():
                        src_to_find = row.Source
                        PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)
            else:
                check_line = '%s in %s' %(t_OBJ_Src, ', '. join(list(t_Where_OBJ_Src_df['Name'].unique())))
                if check_line not in Processed_line:
                    Processed_line.append(check_line)
                    PartlyWrongRouteACL[t_key].append('Object "%s" used as source in other ACL' %(t_OBJ_Src))
                    temp = tabulate(t_Where_OBJ_Src_df,t_Where_OBJ_Src_df,tablefmt='psql',showindex=False).split('\n')
                    for line in temp:
                        PartlyWrongRouteACL[t_key].append(line.replace(' ','&nbsp;'))
                    for row in Child_ACL_Df.itertuples():
                        src_to_find = row.Source
                        PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)
                    #more than one ACL woth this SRC_OBJ
                    if len(t_Where_OBJ_Dst_df) == 0:
                        PartlyWrongRouteACL[t_key].append('Object "%s" not used as destination' %t_OBJ_Src)
                        for row in t_Where_OBJ_Src_df.itertuples():
                            line_Check = '%s %s' %(row.Name, row.Source)
                            if line_Check not in Processed_line:
                                Processed_line.append(line_Check)
                    else:
                        PartlyWrongRouteACL[t_key].append('Object "%s" used as destination in other ACL' %t_OBJ_Src)
                        temp = tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False).split('\n')
                        for line in temp:
                            PartlyWrongRouteACL[t_key].append(line.replace(' ','&nbsp;'))
                        for row in Child_ACL_Df.itertuples():
                            src_to_find = row.Source
                            PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)
                        continue
                else:
                    PartlyWrongRouteACL[t_key].append('%s already processed' %t_OBJ_Src)

    ### handle IPv6 in "utils_v2.ASA_ACL_Obj_to_Net(row.Source)"
    t_html_file = []
    if len(PartlyWrongRouteACL) > 0:
        t_html_file.append('<ul>')
        for t_key in PartlyWrongRouteACL:
            t_html_file.append('<li> %s<br>' %utils_v2.Color_Line(t_key))
            t_html_file.append('<p class="text-dark small" style="overflow-x: auto; overflow-y: hidden; white-space: nowrap;">')
            for t_line in PartlyWrongRouteACL[t_key]:
                if t_line.startswith('!'):
                    t_line = '<font color="#1cb836">%s</font>' %(t_line)
                t_html_file.append('&nbsp;' + t_line +'<br>')
            t_html_file.append('</p></li>')
        t_html_file.append('</ul>')
    else:
        t_html_file.append('nothing to show\n')

    Watch_FName = f"{html_folder}/{hostname___}-PtlyWrongRouteACL-Watch.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    return Config_Change


##=============================================================================================================================
##   __    ___  __      ____   ___  ____    _  _  ___    ____  _____  __  __  ____  ____  _  _  ___    ____   __    ____  __    ____
##  /__\  / __)(  )    (  _ \ / __)(_  _)  ( \/ )/ __)  (  _ \(  _  )(  )(  )(_  _)(_  _)( \( )/ __)  (_  _) /__\  (  _ \(  )  ( ___)
## /(__)\( (__  )(__    )(_) )\__ \  )(     \  / \__ \   )   / )(_)(  )(__)(   )(   _)(_  )  (( (_-.    )(  /(__)\  ) _ < )(__  )__)
##(__)(__)\___)(____)  (____/ (___/ (__)     \/  (___/  (_)\_)(_____)(______) (__) (____)(_)\_)\___/   (__)(__)(__)(____/(____)(____)

# for each ACL expanded row:
    # check roting DEST => out IF
    # reorder ACL per SRC_IF VS DST_IF

def ACL_Dest_Vs_Routing_Table(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    FW_log_folder = log_folder + '/' + hostname___
    html_folder = FW_log_folder

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            WTF_Log = db.Table('WTF_Log', db.MetaData(), autoload_with=engine)
            Top_ICMP_Open_Detail = db.Table('Top_ICMP_Open_Detail', db.MetaData(), autoload_with=engine)
            Top_TCP_Open_Detail = db.Table('Top_TCP_Open_Detail', db.MetaData(), autoload_with=engine)
            Top_UDP_Open_Detail = db.Table('Top_UDP_Open_Detail', db.MetaData(), autoload_with=engine)
            Top_IP_Open_Detail = db.Table('Top_IP_Open_Detail', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_List_Dict"
    ACL_List_Dict = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_ACL"
    Accessgroup_Dic_by_ACL = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ROUTE_DF"
    ROUTE_DF = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Name_dic"
    Name_dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Nameif_List"
    Nameif_List = utils_v2.Shelve_Read_Try(tf_name,'')

    Printed_Lines = []
    Redundant_Routes = []
    Redundant_Routes_Warnign = []

    text = f'Check Acl Destination Vs Routing Table @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    ACL_OUT_IF_COUNTER_dic = {}
    for t_IN_ifName in Nameif_List:
        for t_OUT_ifName in Nameif_List:
            ACL_OUT_IF_COUNTER_dic[(t_IN_ifName,t_OUT_ifName)] = 0
        ACL_OUT_IF_COUNTER_dic[(t_IN_ifName,'Null0')] = 0
    ACL_OUT_IF_ACLs_dic = {}
    for t_IN_ifName in Nameif_List:
        for t_OUT_ifName in Nameif_List:
            ACL_OUT_IF_ACLs_dic[(t_IN_ifName,t_OUT_ifName)] = []
        ACL_OUT_IF_ACLs_dic[(t_IN_ifName,'Null0')] = []

    # add column "IPv4_Network" to ROUTE_IP_DF
    #ROUTE_IP_DF = ROUTE_DF.copy()
    ROUTE_IP_DF = ROUTE_DF
    ROUTE_IP_DF['IPv4_Network'] = ''

    t_N_Total_Routes = ROUTE_IP_DF.shape[0]
    t_N_Redun_Routes = 0

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

    ROUTE_IP_DF["IPv4_Network"] = ROUTE_IP_DF["Network"].apply(safe_ipv4network)
    ROUTE_IP_DF["IPv4_Network"]
    bad_rows = ROUTE_IP_DF[ROUTE_IP_DF["IPv4_Network"].isna()]

    if not bad_rows.empty:
        for _, row in bad_rows.iterrows():
            msg = f'ERROR 2794 while converting {row.IPv4_Network} to ipaddress in {t_device}\n'
            Config_Change.append(msg)
            print(msg)

            log_entry = {
                'TimeStamp': datetime.datetime.now().astimezone(),
                'Level': 'WARNING',
                'Message': msg
            }
            with engine.begin() as connection:
                connection.execute(WTF_Log.insert().values(**log_entry))

        ROUTE_IP_DF = ROUTE_IP_DF.drop(bad_rows.index)

    ROUTE_IP_DF_copy = ROUTE_IP_DF.copy()

    Routing_Space_IN = {}
    for t_IN_ifName in list(ROUTE_IP_DF.Interface.unique()):
        Routing_Space_IN[t_IN_ifName] = 0
    for t_IN_ifName in Nameif_List:
        if t_IN_ifName not in Routing_Space_IN:
            Routing_Space_IN[t_IN_ifName] = 0
    Routing_Space_IN['Null0'] = 0
    Routing_Space_OUT = Routing_Space_IN.copy()
    ACL_Space_ICMP = Routing_Space_IN.copy()
    ACL_Space_TCP  = Routing_Space_IN.copy()
    ACL_Space_UDP  = Routing_Space_IN.copy()

    # ----- Check for redundant routes ----------------------------------------------
    for row1 in ROUTE_IP_DF.itertuples():
        Routing_Space_IN[row1.Interface] += row1.IPv4_Network.num_addresses
        Interface1 = row1.Interface
        BEST_ROUTE = []
        for row2 in ROUTE_IP_DF.itertuples():
            if row1.Index == row2.Index:
                continue
            Interface2 = row2.Interface
            if row1.IPv4_Network.subnet_of(row2.IPv4_Network):
                if Interface1 != Interface2:
                    Routing_Space_IN[Interface2] -= row1.IPv4_Network.num_addresses
            if row2.Network == '0.0.0.0/0':
                continue
            if (row1.IPv4_Network).subnet_of(row2.IPv4_Network):
                if BEST_ROUTE == []:
                    BEST_ROUTE = [row2.IPv4_Network, Interface2, row2.NextHop]
                elif row2.IPv4_Network.subnet_of(BEST_ROUTE[0]): # swap routes
                    if row1.NextHop == row2.NextHop:
                        BEST_ROUTE = [row2.IPv4_Network, Interface2, row2.NextHop]
                    else:
                        Redundant_Routes_Warnign.append('\n')
                        Redundant_Routes_Warnign.append('route %s %s %s\n' %(Interface2, row2.IPv4_Network, row2.NextHop))
                        Redundant_Routes_Warnign.append('route %s %s %s\n' %(Interface1, row1.IPv4_Network, row1.NextHop))

        if BEST_ROUTE != []:
            if Interface1 == BEST_ROUTE[1]:
                if row1.Type == 'C':
                    #print('CONNECTED!!!')
                    Redundant_Routes.append('\n CONNECTED!!!')
                    Redundant_Routes.append('! %s @ %s ==> %s' %(row1.IPv4_Network, Interface1, BEST_ROUTE[0]))
                else:
                    Redundant_Routes.append('\n! %s @ %s ==> %s' %(row1.IPv4_Network, Interface1, BEST_ROUTE[0]))
                    Redundant_Routes.append('no route %s %s %s %s ' %((row1.Interface), str(row1.IPv4_Network.network_address), str(row1.IPv4_Network.netmask), row1.NextHop))
                ROUTE_IP_DF = ROUTE_IP_DF.drop(row1.Index)
                t_N_Redun_Routes += 1

    Fix_FName   = FW_log_folder + '/' + hostname___ + '-redundant_routes-Fix.html'
    Write_Think_File(Fix_FName, Redundant_Routes)
    if len(Redundant_Routes_Warnign) > 0:
        try:
            with open("%s"%(Fix_FName),mode="a") as html_file:
                html_file.write('<br><font class="mark">WARNING!</font><br>\n')
                html_file.write('The Following Routes are Overlapping and have Different Next Hop:<br>\n')
                html_file.write('<p class="text-dark small">\n')
                for t in Redundant_Routes_Warnign:
                    html_file.write(utils_v2.Color_Line(t.replace('\n','<br>')))
                html_file.write('</p>\n')
            print('... saved file "%s" '%(Fix_FName))
        except:
            raise OSError("Can't write to destination file (%s)!" % (Fix_FName))

    print ('N_Redun_Routes = %s' %t_N_Redun_Routes)
    print ('N_Total_Routes = %s' %t_N_Total_Routes)
    Prc_N_Redun_Routes = round(100*t_N_Redun_Routes/t_N_Total_Routes,1) if not (t_N_Total_Routes==0) else 0
    print ('Prc_N_Redun_Routes = %s' %Prc_N_Redun_Routes)

    for t_key1 in Routing_Space_IN:
        sum_delta = 0
        for t_key2 in Routing_Space_IN:
            if t_key1 != t_key2:
                sum_delta += Routing_Space_IN[t_key2]
        Routing_Space_OUT[t_key1] = Routing_Space_IN[t_key1]*sum_delta
    #print('routing check done!') --------------------------------------------------------------------------------

    t_html_file = ['<ul>']
    Founded_Routes = {}
    acl_too_open = []
    BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List_Dict)
    ACL_Space_ICMP_Detail = {}
    ACL_Space_TCP__Detail = {}
    ACL_Space_UDP__Detail = {}
    ACL_Space_IP___Detail = {}
    for t_key in ACL_List_Dict:
        ACL_Space_ICMP_Detail[t_key] = 0
        ACL_Space_TCP__Detail[t_key] = 0
        ACL_Space_UDP__Detail[t_key] = 0
        ACL_Space_IP___Detail[t_key] = 0

        LOOP_INDEX += 1
        if LOOP_INDEX > (ITEMS / STEPS) * BINS:
            print(f'....{int(BINS * 100 / STEPS)}%')
            BINS += 1

        t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_key])
        #t_ACL_Name = t_ACL_Lines_DF.Name[0]
        t_If_Name = ''
        try:
            t_ACL_Name = t_ACL_Lines_DF.Name[0]
        except:
            print(f'DEBUG: ACL index 0 is out of bounds t_ACL_Lines_DF.Name[0] for {t_ACL_Lines_DF}')
            continue
        try:
            t_If_Name = Accessgroup_Dic_by_ACL[t_ACL_Name]
        except:
            continue #silently skip acl not applied to any interface

        for row in t_ACL_Lines_DF.itertuples():
            ACL_text = ' '.join([row.ACL, row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Hitcnt, row.Hash])
            #print('DBG:' + ' '.join(row)) if (DBG == 1) else ''
            this_Dst_Obj = utils_v2.ASA_ACL_Obj_to_Net(row.Dest)
            if not this_Dst_Obj: # ipv6 to be done
                continue
            if 'inactive' in row.Inactive:
                continue

            source_ip_obj = utils_v2.ASA_ACL_Obj_to_IP(row.Source)[0]
            if source_ip_obj == -1: #ipv6
                continue
            elif source_ip_obj == ipaddress.IPv4Network('0.0.0.0/0'):
                SRC = Routing_Space_IN[t_If_Name]
            else:
                SRC = source_ip_obj.num_addresses

            DST = utils_v2.ASA_ACL_Obj_to_IP(row.Dest)[0].num_addresses

            if 'range' in row.D_Port:
                Port1 = row.D_Port.split('range')[1].split()[0]
                if Port1.isnumeric() == True:
                    Port1 = int(Port1)
                else:
                    try:
                        Port1 = int(Port_Converter[Port1])
                    except:
                        print('port1 %s not a number and not a known' %Port1)
                Port2 = row.D_Port.split('range')[1].split()[1]
                if Port2.isnumeric() == True:
                    Port2 = int(Port2)
                else:
                    try:
                        Port2 = int(Port_Converter[Port2])
                    except:
                        print('port2 %s not a number and not a known' %Port2)
                N_of_Ports = Port2 - Port1 + 1
            elif 'eq' in row.D_Port:
                N_of_Ports = 1
            else:
                N_of_Ports = 65536

            ACL_Openess = 100*SRC*DST/Routing_Space_OUT[t_If_Name] if Routing_Space_OUT[t_If_Name]!=0 else 0
            ACL_Openess = ACL_Openess if ACL_Openess<100 else 100
            if ACL_Openess > 0.0005:
                acl_too_open.append([round(ACL_Openess,2), ACL_text])
            if row.Action == 'permit':
                if row.Service == 'icmp':
                    ACL_Space_ICMP[t_If_Name] += SRC*DST
                elif row.Service == 'udp':
                    ACL_Space_UDP[t_If_Name] += SRC*DST*N_of_Ports
                elif row.Service == 'tcp':
                    ACL_Space_TCP[t_If_Name] += SRC*DST*N_of_Ports
                elif row.Service == 'ip':
                    ACL_Space_UDP[t_If_Name] += SRC*DST*N_of_Ports
                    ACL_Space_TCP[t_If_Name] += SRC*DST*N_of_Ports

            if row.Service == 'icmp':
                ACL_Space_ICMP_Detail[t_key] += SRC*DST
                ACL_Space_IP___Detail[t_key] += SRC*DST
            elif row.Service == 'udp':
                ACL_Space_UDP__Detail[t_key] += SRC*DST*N_of_Ports
                ACL_Space_IP___Detail[t_key] += SRC*DST*N_of_Ports
            elif row.Service == 'tcp':
                ACL_Space_TCP__Detail[t_key] += SRC*DST*N_of_Ports
                ACL_Space_IP___Detail[t_key] += SRC*DST*N_of_Ports
            elif row.Service == 'ip':
                ACL_Space_UDP__Detail[t_key] += SRC*DST*N_of_Ports
                ACL_Space_TCP__Detail[t_key] += SRC*DST*N_of_Ports
                ACL_Space_IP___Detail[t_key] += SRC*DST*N_of_Ports*2

            if this_Dst_Obj[0] in list(Founded_Routes):
                if this_Dst_Obj[0] != '0.0.0.0 0.0.0.0':
                    Out_Interface = Founded_Routes[this_Dst_Obj[0]]
                    ACL_OUT_IF_COUNTER_dic[(t_If_Name,Out_Interface)] += 1
                    ACL_OUT_IF_ACLs_dic[(t_If_Name,Out_Interface)].append(ACL_text)
                    continue

            for t_this_Dst_Obj in this_Dst_Obj:
                temp = t_this_Dst_Obj.split()
                try:
                    t_this_Dst_Obj = temp[0] + Sub_Mask_2[temp[1]]
                except:
                    text_line = f'>>>   ERROR... non conventional subnet mask for "{t_this_Dst_Obj}"'
                    if text_line not in Printed_Lines:
                        Config_Change.append(text_line)
                        Printed_Lines.append(text_line)
                        row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                               'Level'     : 'WARNING',
                               'Message'   : (f'Non Conventional Subnet Mask for "{t_this_Dst_Obj}" in {t_device}')}
                        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
                    continue
                try:
                    this_Dst_Obj_IP = ipaddress.IPv4Network(t_this_Dst_Obj, strict=False)
                except:
                    this_Dst_Obj_IP = ipaddress.IPv4Network(Name_dic[t_this_Dst_Obj] + '/32', strict=False)
                    print('--- Name_dic object in ACL_Dest_Vs_Routing %s:' %t_this_Dst_Obj)

                BEST_ROUTE = ''
                for row_1 in ROUTE_IP_DF_copy.itertuples():
                    this_route = row_1.IPv4_Network
                    if this_Dst_Obj_IP.subnet_of(this_route):
                        if BEST_ROUTE == '':
                            BEST_ROUTE = this_route
                        elif this_route.subnet_of(BEST_ROUTE): # swap routes
                            BEST_ROUTE = this_route

                WIDE_ROUTE_List = []
                if t_this_Dst_Obj != '0.0.0.0/0':
                    if BEST_ROUTE != '': # best route found but still...
                        Out_Interface = ROUTE_IP_DF_copy.loc[ROUTE_IP_DF_copy['IPv4_Network'] == BEST_ROUTE].Interface.to_list()[0]
                        Route_Type = ROUTE_IP_DF_copy.loc[ROUTE_IP_DF_copy['IPv4_Network'] == BEST_ROUTE].Type.to_list()[0]
                        if Route_Type == 'V':
                            continue
                        ACL_OUT_IF_COUNTER_dic[(t_If_Name,Out_Interface)] += 1
                        ACL_OUT_IF_ACLs_dic[(t_If_Name,Out_Interface)].append(ACL_text)
                        if this_Dst_Obj[0] not in list(Founded_Routes):
                            Founded_Routes[this_Dst_Obj[0]] = Out_Interface

                        ROUTE_IP_DF_bis = ROUTE_IP_DF_copy.copy()
                        ROUTE_IP_DF_bis = ROUTE_IP_DF_bis.loc[ROUTE_IP_DF_bis['Type']!='V']
                        Best_Route_Index = ROUTE_IP_DF_copy.index[ROUTE_IP_DF_copy['IPv4_Network'] == BEST_ROUTE].to_list()[0]
                        ROUTE_IP_DF_bis = ROUTE_IP_DF_bis.drop(Best_Route_Index)

                        for this_route in ROUTE_IP_DF_bis['IPv4_Network'].to_list():
                            if this_route.subnet_of(this_Dst_Obj_IP):
                                Out_Interface = ROUTE_IP_DF_bis.loc[ROUTE_IP_DF_bis['IPv4_Network'] == this_route].Interface.to_list()[0]
                                WIDE_ROUTE_List.append([str(this_route), Out_Interface])
                                ACL_OUT_IF_COUNTER_dic[(t_If_Name,Out_Interface)] += 1
                                ACL_OUT_IF_ACLs_dic[(t_If_Name,Out_Interface)].append(ACL_text)
                else:
                    for t_OUT_ifName in Nameif_List:
                        if row.Action == 'permit':
                            ACL_OUT_IF_COUNTER_dic[(t_If_Name,t_OUT_ifName)] += 1
                        ACL_OUT_IF_ACLs_dic[(t_If_Name,t_OUT_ifName)].append(ACL_text)

                if WIDE_ROUTE_List != []:
                    text_line = f'<li> {t_key}'
                    t_html_file.append(text_line)
                    t_this_Dst_Obj = this_Dst_Obj[0].split()
                    try:
                        text_line = f' - Dest_Object is "{t_this_Dst_Obj[0]}{Sub_Mask_2[t_this_Dst_Obj[1]]}", interface IN is "{t_If_Name}"\n'
                    except:
                        text_line = f' - Dest_Object is "{this_Dst_Obj[0]}", interface IN is "{t_If_Name}"\n'
                    BEST_ROUTE = ''
                    OUT_IF = ''
                    for row_1 in ROUTE_IP_DF_copy.itertuples():
                        this_route = row_1.IPv4_Network
                        if this_Dst_Obj_IP.subnet_of(this_route):
                            if BEST_ROUTE == '':
                                BEST_ROUTE = this_route
                                OUT_IF = row_1.Interface
                            elif this_route.subnet_of(BEST_ROUTE): # swap routes
                                BEST_ROUTE = this_route
                                OUT_IF = row_1.Interface
                    text_line = text_line + ('   Best Route = %s @ interface %s\n' %(BEST_ROUTE, OUT_IF))
                    text_line = text_line + ('   other routing is:')
                    t_html_file.append(text_line)
                    t_html_file.append('<p class="text-dark small">')
                    for n in WIDE_ROUTE_List:
                        temp = f"{n[0]:<20} {n[1]:<5}"
                        t_html_file.append(temp.replace(' ','&nbsp;'))
                    t_html_file.append('</p></li>')

    SCALEFACTOR = 100000
    ACL_Space_ICMP_Detail_list = ACL_Space_ICMP_Detail.items()
    ACL_Space_ICMP_Detail_Df = pd.DataFrame(ACL_Space_ICMP_Detail_list, columns = ['ACL' , 'Opening'])
    ACL_Space_ICMP_Detail_Df = ACL_Space_ICMP_Detail_Df.sort_values(by=['Opening'], ascending=[False], ignore_index=True)
    ACL_Space_ICMP_Detail_Df = ACL_Space_ICMP_Detail_Df[0:99]
    ACL_Space_ICMP_Detail_Df['Opening'] = ACL_Space_ICMP_Detail_Df['Opening'] / SCALEFACTOR

    #print(ACL_Space_ICMP_Detail_Df)
    if DB_Available:
        delete_stmt = db.delete(Top_ICMP_Open_Detail).where(Top_ICMP_Open_Detail.c.HostName == hostname___)
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)

        for t_row in ACL_Space_ICMP_Detail_Df.itertuples():
            Insert_Vals = dict(
                            HostName = hostname___,
                            ACL_Line = t_row.ACL,
                            ICMP_Open_Val = t_row.Opening
                            )
            insert_stmt = Top_ICMP_Open_Detail.insert().values(**Insert_Vals)
            with engine.begin() as connection:
                results = connection.execute(insert_stmt)

    ACL_Space_TCP__Detail_list = ACL_Space_TCP__Detail.items()
    ACL_Space_TCP__Detail_Df = pd.DataFrame(ACL_Space_TCP__Detail_list, columns = ['ACL' , 'Opening'])
    ACL_Space_TCP__Detail_Df = ACL_Space_TCP__Detail_Df.sort_values(by=['Opening'], ascending=[False], ignore_index=True)
    ACL_Space_TCP__Detail_Df = ACL_Space_TCP__Detail_Df[0:99]
    ACL_Space_TCP__Detail_Df['Opening'] = ACL_Space_TCP__Detail_Df['Opening'] / SCALEFACTOR
    #print(ACL_Space_TCP__Detail_Df)
    if DB_Available:
        delete_stmt = db.delete(Top_TCP_Open_Detail).where(Top_TCP_Open_Detail.c.HostName == hostname___)
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)

        for t_row in ACL_Space_TCP__Detail_Df.itertuples():
            Insert_Vals = dict(
                            HostName = hostname___,
                            ACL_Line = t_row.ACL,
                            TCP_Open_Val = t_row.Opening
                            )
            insert_stmt = Top_TCP_Open_Detail.insert().values(**Insert_Vals)
            with engine.begin() as connection:
                results = connection.execute(insert_stmt)

    ACL_Space_UDP__Detail_list = ACL_Space_UDP__Detail.items()
    ACL_Space_UDP__Detail_Df = pd.DataFrame(ACL_Space_UDP__Detail_list, columns = ['ACL' , 'Opening'])
    ACL_Space_UDP__Detail_Df = ACL_Space_UDP__Detail_Df.sort_values(by=['Opening'], ascending=[False], ignore_index=True)
    ACL_Space_UDP__Detail_Df = ACL_Space_UDP__Detail_Df[0:99]
    ACL_Space_UDP__Detail_Df['Opening'] = ACL_Space_UDP__Detail_Df['Opening'] / SCALEFACTOR
    #print(ACL_Space_UDP__Detail_Df)
    if DB_Available:
        delete_stmt = db.delete(Top_UDP_Open_Detail).where(Top_UDP_Open_Detail.c.HostName == hostname___)
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)

        for t_row in ACL_Space_UDP__Detail_Df.itertuples():
            Insert_Vals = dict(
                            HostName = hostname___,
                            ACL_Line = t_row.ACL,
                            UDP_Open_Val = t_row.Opening
                            )
            insert_stmt = Top_UDP_Open_Detail.insert().values(**Insert_Vals)
            with engine.begin() as connection:
                results = connection.execute(insert_stmt)

    ACL_Space_IP___Detail_list = ACL_Space_IP___Detail.items()
    ACL_Space_IP___Detail_Df = pd.DataFrame(ACL_Space_IP___Detail_list, columns = ['ACL' , 'Opening'])
    ACL_Space_IP___Detail_Df = ACL_Space_IP___Detail_Df.sort_values(by=['Opening'], ascending=[False], ignore_index=True)
    ACL_Space_IP___Detail_Df = ACL_Space_IP___Detail_Df[0:99]
    ACL_Space_IP___Detail_Df['Opening'] = ACL_Space_IP___Detail_Df['Opening'] / SCALEFACTOR
    #print(ACL_Space_IP___Detail_Df)
    if DB_Available:
        delete_stmt = db.delete(Top_IP_Open_Detail).where(Top_IP_Open_Detail.c.HostName == hostname___)
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)

        for t_row in ACL_Space_IP___Detail_Df.itertuples():
            Insert_Vals = dict(
                            HostName = hostname___,
                            ACL_Line = t_row.ACL,
                            IP_Open_Val = t_row.Opening
                            )
            insert_stmt = Top_IP_Open_Detail.insert().values(**Insert_Vals)
            with engine.begin() as connection:
                results = connection.execute(insert_stmt)


    html_file = []
    t_html_file.append('</ul>')
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-DST_vs_Route-Watch.html'
    Write_Think_File(Fix_FName, t_html_file)

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            ACL_Summary = db.Table('ACL_Summary', db.MetaData(), autoload_with=engine)
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    if DB_Available:
        for t_key in ACL_Space_ICMP:
            if Routing_Space_OUT[t_key] != 0:
                if round(100*ACL_Space_ICMP[t_key]/Routing_Space_OUT[t_key],2) > 100:
                    ACL_Space_ICMP_Percent = 100
                else:
                    ACL_Space_ICMP_Percent = round(100*ACL_Space_ICMP[t_key]/Routing_Space_OUT[t_key],2)

                if round(100*ACL_Space_UDP[t_key]/(Routing_Space_OUT[t_key]*65536),2) > 100:
                    ACL_Space_UDP_Percent = 100
                else:
                    ACL_Space_UDP_Percent = round(100*ACL_Space_UDP[t_key]/(Routing_Space_OUT[t_key]*65536),2)

                if round(100*ACL_Space_TCP[t_key]/(Routing_Space_OUT[t_key]*65536),2) > 100:
                    ACL_Space_TCP_Percent = 100
                else:
                    ACL_Space_TCP_Percent = round(100*ACL_Space_TCP[t_key]/(Routing_Space_OUT[t_key]*65536),2)
            else:
                ACL_Space_ICMP_Percent = 0
                ACL_Space_UDP_Percent = 0
                ACL_Space_TCP_Percent = 0

            if t_key in list(Accessgroup_Dic_by_ACL.values()):
                Updated_Vals = dict(
                                    ACL_Space_ICMP = ACL_Space_ICMP_Percent,
                                    ACL_Space_TCP  = ACL_Space_TCP_Percent,
                                    ACL_Space_UDP  = ACL_Space_UDP_Percent
                                    )
                query = db.update(ACL_Summary).where(db.and_(ACL_Summary.c.HostName==hostname___, ACL_Summary.c.Nameif==t_key)).values(**Updated_Vals)
                with engine.begin() as connection:
                    results = connection.execute(query)

        query = db.select(ACL_Summary).where(ACL_Summary.columns.HostName==hostname___)
        with engine.connect() as connection:
            ACL_Summary_db = pd.DataFrame(connection.execute(query).fetchall())

        if ACL_Summary_db.shape[0] > 0:
            t_Prct_ACL_Space_TCP = round(sum(ACL_Summary_db.ACL_Space_TCP)/len(ACL_Summary_db.ACL_Space_TCP),1) if not (len(ACL_Summary_db.ACL_Space_TCP)==0) else 0
            t_Prct_ACL_Space_UDP = round(sum(ACL_Summary_db.ACL_Space_UDP)/len(ACL_Summary_db.ACL_Space_UDP),1) if not (len(ACL_Summary_db.ACL_Space_UDP)==0) else 0
            t_Prct_ACL_Space_ICMP = round(sum(ACL_Summary_db.ACL_Space_ICMP)/len(ACL_Summary_db.ACL_Space_ICMP),1) if not (len(ACL_Summary_db.ACL_Space_ICMP)==0) else 0

            Updated_Vals = dict(
                                    Prct_ACL_Space_TCP = t_Prct_ACL_Space_TCP,
                                    Prct_ACL_Space_UDP = t_Prct_ACL_Space_UDP,
                                    Prct_ACL_Space_ICMP = t_Prct_ACL_Space_ICMP,
                                    N_Redun_Routes = t_N_Redun_Routes,
                                    N_Total_Routes = t_N_Total_Routes
                                )
            query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
            with engine.begin() as connection:
                results = connection.execute(query)
    else:
        print('ERROR in ACL_Dest_Vs_Routing_Table: DB NOT Available!')

    ACL_OUT_IF_COUNTER_list = []
    for t_key in ACL_OUT_IF_COUNTER_dic:
        if ACL_OUT_IF_COUNTER_dic[t_key] != 0:
            ACL_OUT_IF_COUNTER_list.append([t_key[0], t_key[1], ACL_OUT_IF_COUNTER_dic[t_key]])
    #ACL_OUT_IF_COUNTER_df = pd.DataFrame(ACL_OUT_IF_COUNTER_list, columns = ['IF_in' , 'IF_Out', 'Count'])

    # OUTPUT HTML FILE 'acl_too_open-Watch.html' ------------------------------------------
    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
            raise OSError("Can't create destination directory (%s)!" % (html_folder))
    t_html_file = []
    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('<table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="100" >\n')
    t_html_file.append('  <thead><tr>\n')
    t_html_file.append('    <th>Rank</th>\n')
    t_html_file.append('    <th>ACL</th>\n')
    t_html_file.append('    <th>HitCnt</th>\n')
    t_html_file.append('    <th>Hash</th>\n')
    t_html_file.append('  </tr></thead>\n')
    t_html_file.append('  <tbody>\n')
    for t_item in acl_too_open:
        if ' deny ' in t_item[1]:
            t_html_file.append('  <tr class="table-danger">\n')
        else:
            t_html_file.append('  <tr>\n')
        t_html_file.append('    <td>%s</td>\n' %t_item[0])
        new_line = utils_v2.Color_Line(' '.join(t_item[1].split()[:-2]))
        t_html_file.append('    <td>%s</td>\n' %new_line)
        t_html_file.append('    <td>%s</td>\n' %utils_v2.Color_Line(t_item[1].split()[-2]))
        t_html_file.append('    <td>%s</td>\n' %t_item[1].split()[-1])
        t_html_file.append('  </tr>\n')
    t_html_file.append('  </tbody>\n')
    t_html_file.append('</table>\n')
    t_html_file.append('<script>\n')
    t_html_file.append('    $(document).ready(function() {\n')
    t_html_file.append('        // Initialize DataTable with pageLength set to 10\n')
    t_html_file.append("        var table = $('#dataTable').DataTable({\n")
    t_html_file.append('            "pageLength": 10,   // Set default page length to 10 entries\n')
    t_html_file.append('            "ordering": false   // Disable sorting for all columns\n')
    t_html_file.append('        });\n')
    t_html_file.append('    });\n')
    t_html_file.append('</script>\n')
    t_html_file.append('</div>\n')

    Watch_FName = f"{html_folder}/{hostname___}-acl_too_open-Watch.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    # OUTPUT HTML FILE 'drill_down_acls-Watch.html' ---------------------------------------------------
    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
            raise OSError("Can't create destination directory (%s)!" % (html_folder))
    t_html_file = []
    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('<table class="table-bordered table-condensed table-striped" id="MyDataTable1" width="100%" cellspacing="0" data-page-length="50" >\n')
    t_html_file.append('<style>\n')
    t_html_file.append('p.small {\n')
    t_html_file.append('  line-height: 1.0;\n')
    t_html_file.append('  font-family:"Courier New";\n')
    t_html_file.append('  font-size: 1rem;\n')
    t_html_file.append('}\n')
    t_html_file.append('</style>\n')
    t_html_file.append('  <thead><tr>\n')
    t_html_file.append('    <th>IF_IN</th>\n')
    t_html_file.append('    <th>IF_OUT</th>\n')
    t_html_file.append('    <th>ACL</th>\n')
    t_html_file.append('    <th>HitCnt</th>\n')
    t_html_file.append('    <th>Hash</th>\n')
    t_html_file.append('  </tr></thead>\n')
    t_html_file.append('  <tfoot><tr>\n')
    t_html_file.append('  <th>\n')
    t_html_file.append('    <select class="form-control form-control-sm">\n')
    t_html_file.append('      <option value="">Filter IF_IN</option>\n')
    done_if = []
    for t_key in ACL_OUT_IF_ACLs_dic:
        if len(ACL_OUT_IF_ACLs_dic[t_key]) != 0:
            if t_key[0] not in done_if:
                t_html_file.append('      <option value="%s">%s</option>\n' %(t_key[0],t_key[0]))
                done_if.append(t_key[0])
    t_html_file.append('    </select>\n')
    t_html_file.append('  </th>\n')
    t_html_file.append('    <th><input type="text" class="form-control form-control-sm" placeholder="Filter IF_OUT"></th>\n')
    t_html_file.append('    <th><input type="text" class="form-control form-control-sm" placeholder="Filter ACL"></th>\n')
    t_html_file.append('    <th><input type="text" class="form-control form-control-sm" placeholder="Filter HitCnt"></th>\n')
    t_html_file.append('    <th><input type="text" class="form-control form-control-sm" placeholder="Filter Hash"></th>\n')
    t_html_file.append('  </tr></tfoot>\n')
    t_html_file.append('  <tbody>\n')
    for t_key in ACL_OUT_IF_ACLs_dic:
        if len(ACL_OUT_IF_ACLs_dic[t_key]) != 0:
            for t_ACL in ACL_OUT_IF_ACLs_dic[t_key]:
                t_html_file.append('  <tr>\n')
                t_html_file.append('    <th>%s</th>\n' %t_key[0])
                t_html_file.append('    <th>%s</th>\n' %t_key[1])
                new_line = utils_v2.Color_Line(' '.join(t_ACL.split()[:-2]))
                t_html_file.append('    <th>%s</th>\n' %new_line)
                t_html_file.append('    <th>%s</th>\n' %t_ACL.split()[-2])
                t_html_file.append('    <th>%s</th>\n' %t_ACL.split()[-1])
                t_html_file.append('  </tr>\n')
    t_html_file.append('  </tbody>\n')
    t_html_file.append('</table>\n')
    t_html_file.append('</div>\n')
    t_html_file.append('''
        <script>
        $(document).ready(function() {
            // Initialize DataTable
            var table = $('#MyDataTable1').DataTable({
                "pageLength": 50   // Set default page length to 50 entries
            });

            // Apply search for text input fields
            $('#MyDataTable1 tfoot input').on('keyup change', function() {
                var columnIndex = $(this).parent().index(); // Get the index of the column
                table.column(columnIndex).search(this.value).draw(); // Filter the column based on the input value
            });

            // Apply search for select dropdown fields
            $('#MyDataTable1 tfoot select').on('change', function() {
                var columnIndex = $(this).parent().index(); // Get the index of the column
                table.column(columnIndex).search(this.value).draw(); // Filter the column based on the selected value
            });
        });
        </script>

        <style>
            table tfoot {
                display: table-header-group;
            }
        </style>
    ''')

    Watch_FName = f"{html_folder}/{hostname___}-drill_down_acls-Watch.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    connection.close()
    engine.dispose()

#  (=================================================)
#  (==                Sankey_Chart                 ==)
#  (=================================================)
    try:
        with open("Sankey_ACL_Chart.js","r") as f:
            l = f.readlines()
    except:
        print('ERROR!!! file Sankey_ACL_Chart.js not found!')

    temp = ''
    #CONST_Height_Scale_Factor = 2
    for n in range(0,len(l)):
        if "_DATA_GOES_HERE_" in l[n]:
            for m in ACL_OUT_IF_COUNTER_list:
                temp = temp + "['"+m[0]+"','"+m[1]+"_',"+str(m[2])+"],\n"
            l[n] = temp
        elif "_HEIGHT_GOES_HERE_" in l[n]:
            if len(ACL_OUT_IF_COUNTER_dic) < 600:
                CONST_Height_Scale_Factor = round(600 / len(ACL_OUT_IF_COUNTER_dic))
                if_number = len(ACL_OUT_IF_COUNTER_dic)*CONST_Height_Scale_Factor
            else:
                if_number = len(ACL_OUT_IF_COUNTER_dic)
            l[n] = '    height: %s\n,' %if_number
            #    height: window.innerHeight*2,

    t_fname = ("%s/Sankey_ACL_Chart.js"%(html_folder))
    File_Save_Try(t_fname,l)

    engine.dispose()
    return Config_Change




##=============================================================================================================================
##   __    ___  ____  ____  _  _  ____     ___    __    ____  ____  __  __  ____  ____
##  /__\  / __)(_  _)(_  _)( \/ )( ___)   / __)  /__\  (  _ \(_  _)(  )(  )(  _ \( ___)
## /(__)\( (__   )(   _)(_  \  /  )__)   ( (__  /(__)\  )___/  )(   )(__)(  )   / )__)
##(__)(__)\___) (__) (____)  \/  (____)   \___)(__)(__)(__)   (__) (______)(_)\_)(____)

def F_Active_Capture(t_device, Config_Change, log_folder):

    t_N_Capture = 0
    t_N_Capture_CircBuff = 0
    t_N_Capture_Active = 0
    t_N_Capture_Old = 0

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            Active_Capture = db.Table('Active_Capture', db.MetaData(), autoload_with=engine)
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            Global_Settings = db.Table('Global_Settings', db.MetaData(), autoload_with=engine)
            WTF_Log = db.Table('WTF_Log', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    hostname___ = t_device.replace('/','___')
    hostname = t_device

    #Max_Capture_Age = 20 #days

    if DB_Available:
        query = db.select(Active_Capture).where(Active_Capture.c.HostName==hostname___)
        with engine.connect() as connection:
            Capture_db = pd.DataFrame(connection.execute(query).fetchall())
        query = db.select(Global_Settings).where(Global_Settings.c.Name=='Global_Settings')
        with engine.connect() as connection:
            Global_Settings_df = pd.DataFrame(connection.execute(query).fetchall())
    else:
        print('@ Active_Capture: DB_Available=False')
    today = datetime.datetime.now().strftime('%Y-%m-%d')

    Max_Capture_Age = Global_Settings_df.Max_Capture_Age[0]
    text = ('Active Capture older than %s days @ %s' %(Max_Capture_Age,hostname___))
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    re13 = re.compile('\\[.*\\]')
    re5 = re.compile(r'^\s*$') # empty line

    FW_log_folder = log_folder + '/' + hostname___
    with open("%s/%s___Show_Capture.log"%(FW_log_folder,hostname___),"r") as f:
        l = f.readlines()
    Capture_Line = []
    Capture_Line_List = []
    for n in range(0,len(l)):
        if re5.match(l[n]):
            continue
        elif  'show capture' in l[n]:
            continue
        else:
            Capture_Line.append(l[n])
    Capture_Line.append('')
    for n in range(0,len(Capture_Line)):
        if 'capture ' in Capture_Line[n]:
            t_capture_name = Capture_Line[n].split()[1]
            t_capture_content=[Capture_Line[n]]
            m=n+1
            if ' circular-buffer ' in Capture_Line[n]:
                t_N_Capture_CircBuff += 1
            if ' [Capturing ' in Capture_Line[n]:
                t_N_Capture_Active += 1

            while ('capture' not in Capture_Line[m]) and (Capture_Line[m]!=''):
                t_capture_content.append(Capture_Line[m])
                m = m+1

            temp_line = [hostname___, t_capture_name, today, t_capture_content]
            Capture_Line_List.append(temp_line)

    t_N_Capture = len(Capture_Line_List)

    #print(Capture_Line_List) # --- debug ---
    Capture_df = pd.DataFrame(Capture_Line_List, columns = ['HostName','Name','First_Seen','Content'])
    Clear_Capture = []
    if len(Capture_db) > 0:
        Capture_db = Capture_db.drop('ID',axis=1)
        #check if capture is new
        for row in Capture_df.itertuples():
            t_name = row.Name
            query = db.select(Active_Capture).where(db.and_(Active_Capture.columns.HostName==hostname___, Active_Capture.columns.Name==t_name))
            with engine.connect() as connection:
                t_Capture_db = pd.DataFrame(connection.execute(query).fetchall())
            if len(t_Capture_db) == 0: #capture is new
                Config_Change.append(f'inserting new capture @ {row.HostName} : {row.Name} in DB')
                insert_stmt = Active_Capture.insert().values(HostName=row.HostName, Name=row.Name, First_Seen=row.First_Seen, Content=row.Content)
                with engine.begin() as connection:
                    connection.execute(insert_stmt)
                Capture_df.iloc[row.Index].First_Seen = 0
            else: #check if is different
                t_n = ''.join(row.Content)
                t_n = re13.sub('', t_n) # remove counters
                t_m = ''.join(t_Capture_db['Content'][0])
                t_m = re13.sub('', t_m) # remove counters
                if t_n == t_m:
                    t_today = datetime.date(int(today.split('-')[0]),int(today.split('-')[1]),int(today.split('-')[2]))
                    if (t_today-t_Capture_db['First_Seen'][0]).days >= Max_Capture_Age:
                        Clear_Capture.append('no capture %s' %row.Name)
                    Capture_df.iloc[row.Index].First_Seen = (t_today-t_Capture_db['First_Seen'][0]).days
                else:
                    #capture with same name but modified
                    delete_stmt = db.delete(Active_Capture).where(db.and_(Active_Capture.columns.HostName==row.HostName, Active_Capture.columns.Name==row.Name))
                    with engine.begin() as connection:
                        result = connection.execute(delete_stmt)
                    Config_Change.append(f'{result.rowcount} row(s) deleted.')
                    Config_Change.append(f'modified new capture @ {row.HostName} : {row.Name} in DB')
                    insert_stmt = Active_Capture.insert().values(HostName=row.HostName, Name=row.Name, First_Seen=row.First_Seen, Content=row.Content)
                    with engine.begin() as connection:
                        connection.execute(insert_stmt)
                    Capture_df.iloc[row.Index].First_Seen = 0
        # delete from db capture deleted
        if len(Capture_df) > 0:
            for row in Capture_db.itertuples():
                Bool_check = ('HostName == "%s" & Name == "%s"') %(row.HostName,row.Name)
                t_Capture_df = Capture_df.query(Bool_check)
                if len(t_Capture_df) == 0:
                    Config_Change.append(f'deleting capture @ {row.HostName} : {row.Name} from DB')
                    delete_stmt = db.delete(Active_Capture).where(db.and_(Active_Capture.columns.HostName==row.HostName, Active_Capture.columns.Name==row.Name))
                    with engine.begin() as connection:
                        result = connection.execute(delete_stmt)
                    Config_Change.append(f"{result.rowcount} row(s) deleted.")
        else:
            # rimuovo tutte le capture dal DB
            delete_stmt = db.delete(Active_Capture).where(Active_Capture.columns.HostName==hostname___)
            with engine.begin() as connection:
                result = connection.execute(delete_stmt)
            Config_Change.append(f'{result.rowcount} row(s) deleted.')
    else:
        #capture is new
        Config_Change.append(f'new device, inserting {len(Capture_df)} captures for {hostname___} in DB')
        for row in Capture_df.itertuples():
            insert_stmt = Active_Capture.insert().values(HostName=row.HostName, Name=row.Name, First_Seen=row.First_Seen, Content=row.Content)
            with engine.begin() as connection:
                connection.execute(insert_stmt)
            Capture_df.iloc[row.Index].First_Seen = 0

    t_N_Capture_Old = len(Clear_Capture)

    Capture_df = Capture_df.sort_values('First_Seen', ascending=(False))
    Capture_df = Capture_df.reset_index(drop=True)
    html_folder = FW_log_folder
    Watch_FName = hostname___ + '-Capture-Watch.html'
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Capture-Fix.html'
    Watch_Flist = []

    Watch_Flist.append('<div class="card-body">\n')
    Watch_Flist.append('''
       <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n
       ''')
    my_index = 0
    N_Cols = 2
    Watch_Flist.append('       <thead><tr>\n')
    Watch_Flist.append('           <th style="text-align: center;">Days</th>\n')
    Watch_Flist.append('           <th>Capture</th>\n')
    Watch_Flist.append('       </tr></thead>\n')
    Watch_Flist.append('       <tbody>\n')
    Red_Color = '#ba1e28'
    for row in Capture_df.itertuples():
        Watch_Flist.append('       <tr>\n')
        for t_col_index in range(2,4):
            if t_col_index == 3:
                new_line = ''
                for t_line in Capture_df.iloc[row.Index,t_col_index]:
                    if t_line.startswith('  match '):
                        t_line = '&nbsp;&nbsp; ' + t_line
                    t_line = t_line.replace('\n','<br>')
                    t_line = utils_v2.Color_Line(t_line)
                    new_line = new_line + t_line
                Watch_Flist.append('           <td>%s</td>\n' %new_line)
            else:
                if Capture_df.iloc[row.Index,t_col_index] > Max_Capture_Age:
                    Watch_Flist.append('           <td style="text-align: center;"><font color="%s">%s</font></td>\n' %(Red_Color, Capture_df.iloc[row.Index,t_col_index]))
                else:
                    Watch_Flist.append('           <td style="text-align: center;">%s</td>\n' %Capture_df.iloc[row.Index,t_col_index])
        Watch_Flist.append('       </tr>\n')
    Watch_Flist.append('       </tbody>\n')
    Watch_Flist.append('   </table>\n')
    Watch_Flist.append('</div>\n')

    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for n in Watch_Flist:
                html_file.write(n)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
        Config_Change.append(f'... saved file "{html_folder}/{Watch_FName}"')
    except Exception as e:
        print(f"error is: {e}")

        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write(f"ERROR! Can't write to destination file {html_folder}/{Watch_FName}")
            f.write(f"error is: {e}")
        row = {'TimeStamp' : datetime.datetime.now().astimezone(),
               'Level'     : 'ERROR',
               'Message'   : (f"Can't write to destination file {html_folder}/{Watch_FName}")}
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    Write_Think_File(Fix_FName, Clear_Capture)

    if DB_Available:
        Updated_Vals = {
            'N_Capture': t_N_Capture,
            'N_Capture_CircBuff': t_N_Capture_CircBuff,
            'N_Capture_Active': t_N_Capture_Active,
            'N_Capture_Old': t_N_Capture_Old
        }
        query = db.update(My_Devices).where(My_Devices.c.HostName == hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)

    engine.dispose()
    return Config_Change


##=============================================================================================================================
## __  __  ___  ____    ____  ____  ___  __      __    ____  ____  ____     _____  ____   ____  ____  ___  ____  ___
##(  )(  )/ __)( ___)  (  _ \( ___)/ __)(  )    /__\  (  _ \( ___)(  _ \   (  _  )(  _ \ (_  _)( ___)/ __)(_  _)/ __)
## )(__)( \__ \ )__)    )(_) ))__)( (__  )(__  /(__)\  )   / )__)  )(_) )   )(_)(  ) _ <.-_)(   )__)( (__   )(  \__ \
##(______)(___/(____)  (____/(____)\___)(____)(__)(__)(_)\_)(____)(____/   (_____)(____/\____) (____)\___) (__) (___/

def Use_Declared_Objects(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Undeclared_NetObj_Used_List"
    Undeclared_NetObj_Used_List = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obejct_by_value_Dict"
    Obejct_by_value_Dict = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_GRP_NET_Dic"
    OBJ_GRP_NET_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    Watch_Flist = []
    text = ('Use Declared Object @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    with open("%s/%s___Show_Running-Config.log"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
        show_run = f.readlines()

    for find_this in Undeclared_NetObj_Used_List:
        if len(find_this.split()) == 1:
            line_to_find = ' network-object host %s' %find_this
        elif len(find_this.split()) == 2:
            line_to_find = ' network-object %s' %find_this
        else:
            print ('WARNING!!! @ Use_Declared_Objects\n Unexpected object lengthfor "%s"' %find_this)
            Config_Change.append('WARNING!!! @ Use_Declared_Objects\n Unexpected object lengthfor "%s"' %find_this)
            continue

        for n in range(1,len(show_run)):
            if show_run[n].startswith(line_to_find):
                #go back and find "object-group network"
                m = n-1
                while not show_run[m].startswith('object-group network'):
                    m = m-1
                if len(OBJ_GRP_NET_Dic[show_run[m].rstrip().split()[2]]) > 1:
                    Watch_Flist.append(show_run[m].rstrip())
                    try:
                        Watch_Flist.append(' network-object object %s' %Obejct_by_value_Dict[find_this][0])
                        Watch_Flist.append(' no%s' %line_to_find)
                        Watch_Flist.append('!')
                    except:
                        Watch_Flist.append('!%s is not a "network-object object"... ' %(find_this))
                        Watch_Flist.append('!')
                else:
                    Watch_Flist.append('!'+ show_run[m].rstrip())
                    Watch_Flist.append('!convert this to "object network ..."')
                    Watch_Flist.append('!')

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-UseDeclaredObj-Watch.html'
    Write_Think_File(Watch_FName, Watch_Flist)
    return Config_Change

##=============================================================================================================================
## ____  _  _  ____  __    ____  ___  ____  ____    ____  ____  _  _  _  _    ____  ____      __    _  _  _  _      __    _  _  _  _
##( ___)( \/ )(  _ \(  )  (_  _)/ __)(_  _)(_  _)  (  _ \( ___)( \( )( \/ )  (_  _)(  _ \    /__\  ( \( )( \/ )    /__\  ( \( )( \/ )
## )__)  )  (  )___/ )(__  _)(_( (__  _)(_   )(     )(_) ))__)  )  (  \  /    _)(_  )___/   /(__)\  )  (  \  /    /(__)\  )  (  \  /
##(____)(_/\_)(__)  (____)(____)\___)(____) (__)   (____/(____)(_)\_) (__)   (____)(__)    (__)(__)(_)\_) (__)   (__)(__)(_)\_) (__)

def Explicit_Deny_IP_Any_Any(t_device, Config_Change, log_folder):

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___

    text = ('Explicit Deny Ip Any Any @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines_DF"
    Show_ACL_Lines_DF = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_ACL"
    Accessgroup_Dic_by_ACL = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Unused_ACL_List"
    Unused_ACL_List = utils_v2.Shelve_Read_Try(tf_name,'')

    Bool_check = ('Action == "deny" & Service == "ip" & "%s" in Source & "%s" in Dest' %('any','any'))
    temp = Show_ACL_Lines_DF.query(Bool_check)

    # check it only for ACL in "access-group"
    for n in range(0,len(Accessgroup_Dic_by_ACL)):
        t_ACL = list(Accessgroup_Dic_by_ACL)[n]
        if t_ACL not in temp.Name.tolist():
            if t_ACL not in Unused_ACL_List:
                Config_Change.append('! --- WARNING ---')
                Config_Change.append('! - No explicit "deny ip any any" in access-list "%s"' %t_ACL)
                Config_Change.append('access-list %s extended deny ip any any log' %t_ACL)
                Config_Change.append('!')

    if len(temp) > 0:
        for row in temp.itertuples():
            if row.Name in Unused_ACL_List:
                temp = temp.drop(row.Index)
    if len(temp) > 0:
        for row in temp.itertuples():
            Last_Line_at  = (Show_ACL_Lines_DF.loc[Show_ACL_Lines_DF['Name']== row.Name].iloc[-1]).Line.split()[1]
            this_Line_at = row.Line.split()[1]
            if int(this_Line_at) < int(Last_Line_at):
                Config_Change.append('! --- WARNING ---')
                Config_Change.append('! - No explicit "deny ip any any" at the end of access-list "%s" but at line %s of %s' %(row.Name,this_Line_at,Last_Line_at))
                Config_Change.append('before moving the line, be sure there is no a "permit ip any any..."')
                Config_Change.append('no access-list %s extended deny ip any any' %row.Name)
                Config_Change.append('access-list %s extended deny ip any any log' %row.Name)
                Config_Change.append('!')

    return Config_Change


##=============================================================================================================================
## ____  ____    ____  _____  ____      __    ___  __
##(  _ \(  _ \  ( ___)(  _  )(  _ \    /__\  / __)(  )
## )(_) )) _ <   )__)  )(_)(  )   /   /(__)\( (__  )(__
##(____/(____/  (__)  (_____)(_)\_)  (__)(__)\___)(____)

def DB_For_ACL(t_device, Config_Change, log_folder):

    DB_Available = True
    try:
        engine = db.create_engine(f"postgresql://{PostgreSQL_User}:{PostgreSQL_PW}@{PostgreSQL_Host}:{PostgreSQL_Port}/{db_Name}")
        with engine.connect() as connection:
            My_Devices         = db.Table('My_Devices',        db.MetaData(), autoload_with=engine)
            ACL_GROSS          = db.Table('ACL_GROSS',         db.MetaData(), autoload_with=engine)
            Global_Settings    = db.Table('Global_Settings',   db.MetaData(), autoload_with=engine)
            WTF_Log            = db.Table('WTF_Log',           db.MetaData(), autoload_with=engine)

    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

#    import ipaddress

    hostname___ = t_device.replace('/','___')
    FW_log_folder  = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    hostname = t_device

##    Max_ACL_HitCnt0_Age  = 180
##    Max_ACL_Inactive_Age = 180
##    Min_Hitcnt_Threshold = 20
##    N_ACL_Most_Triggered = 10
##    Max_ACL_Expand_Ratio = 100

    if DB_Available:
        query = db.select(Global_Settings).where(Global_Settings.c.Name=='Global_Settings')
        with engine.connect() as connection:
            Global_Settings_df = pd.DataFrame(connection.execute(query).fetchall())
        query = db.select(ACL_GROSS).where(ACL_GROSS.columns.HostName=="%s" %hostname___)
        with engine.connect() as connection:
            ACL_GROSS_db = pd.DataFrame(connection.execute(query).fetchall())
    else:
        print('@ DB_For_ACL: DB_Available=False')

    Max_ACL_HitCnt0_Age  = Global_Settings_df.Max_ACL_HitCnt0_Age[0]
    Max_ACL_Inactive_Age = Global_Settings_df.Max_ACL_Inactive_Age[0]
    Min_Hitcnt_Threshold = Global_Settings_df.Min_Hitcnt_Threshold[0]
    N_ACL_Most_Triggered = Global_Settings_df.N_ACL_Most_Triggered[0]
    Max_ACL_Expand_Ratio = Global_Settings_df.Max_ACL_Expand_Ratio[0]

    temp_no_inactive = []           # inactive lines to be deleted
    N_temp_no_inactive = 0
    temp_inactive_below = []        # inactive lines below threshold
    N_temp_inactive_below = 0
    temp_yo_inactive = []           # active lines to be turned inactive
    N_temp_yo_inactive = 0
    temp_yo_inactive_below = []     # active lines below threshold
    N_temp_yo_inactive_below = 0
    temp_few_hitcnt  = []
    N_of_ACL_Incremented = 0
    N_of_ACL_Resetted = 0
    N_of_ACL_Deleted = 0
    N_of_ACL_NEW = 0
    ACL_Deleted_List = []

    Fix_FList_Inactive   = []
    Fix_FList_DeltaHit0  = []

    re_space = re.compile(r'  +') # two or more spaces
    text = ('DB for ACL @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_remark_Lines"
    ACL_remark_Lines = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_if"
    Accessgroup_Dic_by_if = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines_DF"
    Show_ACL_Lines_DF = utils_v2.Shelve_Read_Try(tf_name,'')

    ACL_Lines_DF = Show_ACL_Lines_DF
    for row in ACL_Lines_DF.itertuples(): #only interfaces
        if row.Name not in list(Accessgroup_Dic_by_if.values()):
            ACL_Lines_DF = ACL_Lines_DF.drop(row.Index)

    today = datetime.datetime.now().strftime('%Y-%m-%d')


    if len(ACL_GROSS_db) == 0: # New Device
        print('Device not in DB... writing %s lines' %len(ACL_Lines_DF))
        Config_Change.append('Device not in DB... writing %s lines' %len(ACL_Lines_DF))
        with engine.begin() as connection:
            for row in ACL_Lines_DF.itertuples():
                N_of_ACL_NEW += 1
                New_Vals = dict(
                                HostName    =hostname___,
                                First_Seen  =today,
                                Name        =row.Name,
                                Line        =row.Line,
                                Type        =row.Type,
                                Action      =row.Action,
                                Service     =row.Service,
                                Source      =row.Source,
                                S_Port      =row.S_Port,
                                Dest        =row.Dest,
                                D_Port      =row.D_Port,
                                Rest        =row.Rest,
                                Inactive    =row.Inactive,
                                Hitcnt      =row.Hitcnt,
                                Hash        =row.Hash,
                                Delta_HitCnt=0
                )
                insert_stmt = ACL_GROSS.insert().values(**New_Vals)
                result = connection.execute(insert_stmt)

        # make empty report files:
        Watch_FName   = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Watch.html'
        Watch_FName_2 = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Watch_2.html'
        Fix_FName     = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Fix.html'

        Write_Think_File(Watch_FName,   ['\n'])
        Write_Think_File(Watch_FName_2, ['\n'])
        Write_Think_File(Fix_FName,     ['\n'])

        Watch_FName   = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Watch.html'
        Watch_FName_2 = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Watch_2.html'
        Fix_FName     = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Fix.html'

        Write_Think_File(Watch_FName,   ['\n'])
        Write_Think_File(Watch_FName_2, ['\n'])
        Write_Think_File(Fix_FName,     ['\n'])

    else:
        ACL_GROSS_db = ACL_GROSS_db.drop(labels='ID', axis=1)
        t_today = datetime.date(int(today.split('-')[0]),int(today.split('-')[1]),int(today.split('-')[2]))

        N_ACL_Lines = ACL_Lines_DF.shape[0]
        BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = N_ACL_Lines
        with engine.begin() as connection:
            #for row in ACL_Lines_DF.itertuples():
            for t_iteration, row in enumerate(ACL_Lines_DF.itertuples(), start=1):
                LOOP_INDEX = LOOP_INDEX + 1
                if LOOP_INDEX > (ITEMS/STEPS)*BINS:
                    print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1
                #t_hash = row.Hash
                Bool_check = (('Name=="%s" & Action=="%s" & Service=="%s"& Source=="%s" & Dest=="%s" & D_Port=="%s" & Hash=="%s"') %(row.Name, row.Action, row.Service, row.Source, row.Dest, row.D_Port, row.Hash))
                t_ACL_GROSS_db = (ACL_GROSS_db.query(Bool_check))

                # there can not be two identical ACL lines
                if len(t_ACL_GROSS_db) > 1:
                    Log_Message = (f'@ ACL_GROSS for {hostname} has to be cleaned'); print(Log_Message); Config_Change.append(Log_Message)
                    Log_row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
                    connection.execute(WTF_Log.insert().values(**Log_row))
                    Log_Message = (f'@ ACL = access-list {row.Name} {row.Action} {row.Service} {row.Source} {row.Dest} {row.D_Port} {row.Hash}'); print(Log_Message); Config_Change.append(Log_Message)
                    Log_row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
                    connection.execute(WTF_Log.insert().values(**Log_row))
                    exit()

                if len(t_ACL_GROSS_db) == 0: # ACL LINE is new
                    N_of_ACL_NEW += 1
                    t_line = 'access-list %s %s %s %s %s %s %s %s %s %s %s %s %s' %(row.Name,row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest,row.Inactive, row.Hitcnt, row.Hash)
                    t_line = re_space.sub(' ',t_line)
                    Config_Change.append(t_line)
                    Config_Change.append('ACL LINE is new... writing to DB')

                    New_Vals = dict(
                                    HostName    =hostname___,
                                    First_Seen  =today,
                                    Name        =row.Name,
                                    Line        =row.Line,
                                    Type        =row.Type,
                                    Action      =row.Action,
                                    Service     =row.Service,
                                    Source      =row.Source,
                                    S_Port      =row.S_Port,
                                    Dest        =row.Dest,
                                    D_Port      =row.D_Port,
                                    Rest        =row.Rest,
                                    Inactive    =row.Inactive,
                                    Hitcnt      =row.Hitcnt,
                                    Hash        =row.Hash,
                                    Delta_HitCnt=0
                    )
                    insert_stmt = ACL_GROSS.insert().values(**New_Vals)
                    result = connection.execute(insert_stmt)
                else:
                    # check if Hitcnt incremented
                    try:
                        if int(row.Hitcnt) > int(t_ACL_GROSS_db.Hitcnt.item()):
                            pass
                    except:
                        print('ERROR Triggered in DB_For_ACL ...int(t_ACL_GROSS_db.Hitcnt)... ----------------------------------------------------------------------------')
                        for n in t_ACL_GROSS_db:
                            print(n)

                    t_row_HitCnt = int(row.Hitcnt)
                    t_ACL_GROSS_db_Hitcnt = int(t_ACL_GROSS_db.Hitcnt.item())

                    if t_row_HitCnt > t_ACL_GROSS_db_Hitcnt:
                        if t_row_HitCnt-t_ACL_GROSS_db_Hitcnt <= Min_Hitcnt_Threshold:
                            temp_few_hitcnt.append('\n%s Hitcount in %s days' %(t_row_HitCnt-t_ACL_GROSS_db_Hitcnt, (t_today-t_ACL_GROSS_db.First_Seen.item()).days))
                            t_line = 'access-list %s %s %s %s %s %s %s %s %s %s %s' %(row.Name, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Hitcnt, row.Hash)
                            t_line = re_space.sub(' ',t_line)
                            temp_few_hitcnt.append(t_line)

                        N_of_ACL_Incremented += 1
                        Delta = t_row_HitCnt - t_ACL_GROSS_db_Hitcnt
                        Updated_Vals = dict(
                                            First_Seen  = today,
                                            Line        = row.Line,
                                            Hitcnt      = row.Hitcnt,
                                            Delta_HitCnt= Delta,
                                            Inactive    = row.Inactive,
                                            Rest        = row.Rest
                                            )
                        query = db.update(ACL_GROSS).where(db.and_( ACL_GROSS.c.HostName==hostname___,
                                                                    ACL_GROSS.c.Name==row.Name,
                                                                    ACL_GROSS.c.Action==row.Action,
                                                                    ACL_GROSS.c.Service==row.Service,
                                                                    ACL_GROSS.c.Source==row.Source,
                                                                    ACL_GROSS.c.Dest==row.Dest,
                                                                    ACL_GROSS.c.D_Port==row.D_Port,
                                                                    ACL_GROSS.c.Hash==row.Hash)).values(**Updated_Vals)
                        results = connection.execute(query)

                    # turn inactive
                    elif t_row_HitCnt == t_ACL_GROSS_db_Hitcnt:
                        #First_Seen = t_ACL_GROSS_db.First_Seen.item()
                        t_Days = (t_today-t_ACL_GROSS_db.First_Seen.item()).days
                        t_line = 'access-list %s %s %s %s %s %s %s %s %s %s %s (hitcnt=%s) %s' %(row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, row.Hitcnt, row.Hash)
                        t_line = re_space.sub(' ',t_line)
                        t_line_clean = 'access-list %s %s %s %s %s %s %s %s %s inactive' %(row.Name, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest)
                        t_line_clean = re_space.sub(' ',t_line_clean)

                        if 'inactive' in row.Inactive:
                            # check if it is the first time we see it as inactive
                            # if yes, reset First_Seen
                            if 'inactive' not in t_ACL_GROSS_db.Inactive.item(): # --- was not inactive
                                Updated_Vals = dict(
                                                    First_Seen  = today,
                                                    Line        = row.Line,
                                                    Hitcnt      = row.Hitcnt,
                                                    Delta_HitCnt= 0,
                                                    Inactive    = row.Inactive,
                                                    Rest        = row.Rest
                                                    )
                                query = db.update(ACL_GROSS).where(db.and_( ACL_GROSS.c.HostName==hostname___,
                                                                            ACL_GROSS.c.Name==row.Name,
                                                                            ACL_GROSS.c.Action==row.Action,
                                                                            ACL_GROSS.c.Service==row.Service,
                                                                            ACL_GROSS.c.Source==row.Source,
                                                                            ACL_GROSS.c.Dest==row.Dest,
                                                                            ACL_GROSS.c.D_Port==row.D_Port,
                                                                            ACL_GROSS.c.Hash==row.Hash)).values(**Updated_Vals)
                                results = connection.execute(query)
                            else:
                                # check if to be deleted
                                if t_Days >= Max_ACL_Inactive_Age:
                                    # --- Max_ACL_Inactive_Age expired => delete it ---
                                    # Check line before if is a remark
                                    tmp_line = 'access-list %s line %s remark ' %(row.Name, str(int(row.Line.split()[1])-1))
                                    for t_ACL_remark_Lines in ACL_remark_Lines:
                                        if t_ACL_remark_Lines.startswith(tmp_line):
                                            #temp_no_inactive.append(['',t_ACL_remark_Lines])
                                            temp_no_inactive.append([t_iteration, '', t_ACL_remark_Lines])
                                            #Fix_FList_Inactive.append('no %s' %(t_ACL_remark_Lines))
                                            cleaned = re.sub(r'\bline\s+\d+\s*', '', t_ACL_remark_Lines)
                                            Fix_FList_Inactive.append([t_iteration, t_Days, f'no {cleaned}'])
                                    #temp_no_inactive.append([t_Days, t_line])
                                    temp_no_inactive.append([t_iteration, t_Days, t_line])
                                    #Fix_FList_Inactive.append('no %s' %(t_line_clean))
                                    Fix_FList_Inactive.append([t_iteration, t_Days, f'no {t_line_clean}'])
                                    N_temp_no_inactive += 1
                                else:
                                    # Max_ACL_Inactive_Age not expired => Report it
                                    #temp_inactive_below.append([t_Days, t_line])
                                    temp_inactive_below.append([t_iteration, t_Days, t_line])
                                    N_temp_inactive_below += 1
                        else:
                            if 'inactive' in t_ACL_GROSS_db.Inactive.item(): # --- was inactive and has been activated
                                Updated_Vals = dict(
                                                    First_Seen  = today,
                                                    Line        = row.Line,
                                                    Hitcnt      = row.Hitcnt,
                                                    Delta_HitCnt= 0,
                                                    Inactive    = row.Inactive,
                                                    Rest        = row.Rest
                                                    )
                                query = db.update(ACL_GROSS).where(db.and_( ACL_GROSS.c.HostName==hostname___,
                                                                            ACL_GROSS.c.Name==row.Name,
                                                                            ACL_GROSS.c.Action==row.Action,
                                                                            ACL_GROSS.c.Service==row.Service,
                                                                            ACL_GROSS.c.Source==row.Source,
                                                                            ACL_GROSS.c.Dest==row.Dest,
                                                                            ACL_GROSS.c.D_Port==row.D_Port,
                                                                            ACL_GROSS.c.Hash==row.Hash)).values(**Updated_Vals)
                                results = connection.execute(query)
                            else:
                                # check if to make inactive
                                if row.Action.lower() == 'deny':
                                    continue
                                elif t_Days >= Max_ACL_HitCnt0_Age:
                                    # Max_ACL_HitCnt0_Age expired => turn it to inactive
                                    temp_yo_inactive.append([t_iteration, t_Days, t_line])
                                    Fix_FList_DeltaHit0.append([t_iteration, t_Days, t_line_clean])
                                    N_temp_yo_inactive += 1
                                else:
                                    # Max_ACL_HitCnt0_Age not expired => Report it
                                    t_line = t_line.replace(' inactive', '')
                                    temp_yo_inactive_below.append([t_iteration, t_Days, t_line])
                                    N_temp_yo_inactive_below += 1

                        Delta = 0
                        Updated_Vals = {
                                        'Line'        : row.Line,
                                        'Inactive'    : row.Inactive,
                                        'Delta_HitCnt': Delta,
                                        'Rest'        : row.Rest
                                        }
                        query = db.update(ACL_GROSS).where(db.and_( ACL_GROSS.c.HostName==hostname___,
                                                                    ACL_GROSS.c.Name==row.Name,
                                                                    ACL_GROSS.c.Action==row.Action,
                                                                    ACL_GROSS.c.Service==row.Service,
                                                                    ACL_GROSS.c.Source==row.Source,
                                                                    ACL_GROSS.c.Dest==row.Dest,
                                                                    ACL_GROSS.c.D_Port==row.D_Port,
                                                                    ACL_GROSS.c.Hash==row.Hash)).values(**Updated_Vals)
                        results = connection.execute(query)

                    else:
                        # resetted counters, update db
                        N_of_ACL_Resetted += 1
                        t_line = ['access-list',row.Name,row.Line,row.Type,row.Action,row.Service,row.Source,row.S_Port,row.Dest,row.D_Port,row.Rest,row.Inactive,row.Hitcnt,row.Hash]
                        t_line = ' '.join(t_line)
                        t_line = re_space.sub(' ',t_line)
                        Config_Change.append(t_line)
                        Config_Change.append('Hitcount resetted for ACL, updating DB...')
                        # update date
                        Updated_Vals = dict(
                                            First_Seen  = today,
                                            Line        = row.Line,
                                            Hitcnt      = row.Hitcnt,
                                            Delta_HitCnt= 0,
                                            Inactive    = row.Inactive,
                                            Rest        = row.Rest
                                            )
                        query = db.update(ACL_GROSS).where(db.and_( ACL_GROSS.c.HostName==hostname___,
                                                                    ACL_GROSS.c.Name==row.Name,
                                                                    ACL_GROSS.c.Action==row.Action,
                                                                    ACL_GROSS.c.Service==row.Service,
                                                                    ACL_GROSS.c.Source==row.Source,
                                                                    ACL_GROSS.c.Dest==row.Dest,
                                                                    ACL_GROSS.c.D_Port==row.D_Port,
                                                                    ACL_GROSS.c.Hash==row.Hash)).values(**Updated_Vals)
                        results = connection.execute(query)

        if not os.path.exists(html_folder):
            try:
                os.mkdir(html_folder)
            except:
                Config_Change.append("Can't create destination directory (%s)!" % (html_folder))
                raise OSError("Can't create destination directory (%s)!" % (html_folder))

        # writing f"{html_folder}/{hostname___}-Inactive_ACL-Watch.html" ---------------------------------
        temp_no_inactive_DF = pd.DataFrame(temp_no_inactive, columns = ['#', 'Days', 'Line'])

        t_html_file = []
        t_html_file.append('<div class="card-body">\n')
        t_html_file.append("""
                    <table class="table-bordered table-condensed table-striped"
                           id="dataTable1"
                           width="100%"
                           cellspacing="0"
                           data-page-length="100"
                           data-order='[[ 0, "asc" ]]'>
                    """)
        N_Cols = temp_no_inactive_DF.shape[1]
        t_html_file.append('       <thead><tr>\n')
        for t_col_index in range(0,N_Cols):
            t_html_file.append('           <th class="px-2 text-nowrap">%s</th>\n' %temp_no_inactive_DF.columns[t_col_index])
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        for row in temp_no_inactive_DF.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                t_line = temp_no_inactive_DF.iloc[row.Index][t_col_index]
                if t_col_index == N_Cols-1:
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
                else:
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')

        Watch_FName = f"{html_folder}/{hostname___}-Inactive_ACL-Watch.html"
        log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
        # ----------------------------------------------------------------------------------------------


        # writing f"{html_folder}/{hostname___}-Inactive_ACL-Watch_2.html" ---------------------------------
        temp_inactive_below_DF = pd.DataFrame(temp_inactive_below, columns = ['#', 'Days', 'Line'])

        t_html_file = []
        t_html_file.append('<div class="card-body">\n')
        t_html_file.append("""
                    <table class="table-bordered table-condensed table-striped"
                           id="dataTable2"
                           width="100%"
                           cellspacing="0"
                           data-page-length="100"
                           data-order='[[ 0, "asc" ]]'>
                    """)
        N_Cols = temp_inactive_below_DF.shape[1]
        t_html_file.append('       <thead><tr>\n')
        for t_col_index in range(0,N_Cols):
            t_html_file.append('           <th class="px-2 text-nowrap">%s</th>\n' %temp_inactive_below_DF.columns[t_col_index])
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        for row in temp_inactive_below_DF.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                t_line = temp_inactive_below_DF.iloc[row.Index][t_col_index]
                if t_col_index == N_Cols-1:
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
                else:
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')

        Watch_FName_2 = f"{html_folder}/{hostname___}-Inactive_ACL-Watch_2.html"
        log_msg = File_Save_Try2(Watch_FName_2, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
        # ----------------------------------------------------------------------------------------------


        # writing f"{html_folder}/{hostname___}-Inactive_ACL-Fix.html" ---------------------------------
        Fix_FList_Inactive_DF = pd.DataFrame(Fix_FList_Inactive, columns = ['#', 'Days', 'Line'])

        t_html_file = []
        t_html_file.append('<div class="card-body">\n')
        t_html_file.append("""
                    <table class="table-bordered table-condensed table-striped"
                           id="dataTable3"
                           width="100%"
                           cellspacing="0"
                           data-page-length="100"
                           data-order='[[ 0, "asc" ]]'>
                    """)
        N_Cols = Fix_FList_Inactive_DF.shape[1]
        t_html_file.append('       <thead><tr>\n')
        for t_col_index in range(0,N_Cols):
            t_html_file.append('           <th class="px-2 text-nowrap">%s</th>\n' %Fix_FList_Inactive_DF.columns[t_col_index])
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        for row in Fix_FList_Inactive_DF.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                t_line = Fix_FList_Inactive_DF.iloc[row.Index][t_col_index]
                if t_col_index == N_Cols-1:
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
                else:
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')

        Watch_FName_2 = f"{html_folder}/{hostname___}-Inactive_ACL-Fix.html"
        log_msg = File_Save_Try2(Watch_FName_2, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
        # ----------------------------------------------------------------------------------------------

        if not os.path.exists(html_folder):
            try:
                os.mkdir(html_folder)
            except:
                Config_Change.append("Can't create destination directory (%s)!" % (html_folder))
                raise OSError("Can't create destination directory (%s)!" % (html_folder))

        # writing f"{html_folder}/{hostname___}-Deltahitcnt0_ACL-Watch.html" ---------------------------------
        temp_yo_inactive_DF = pd.DataFrame(temp_yo_inactive, columns = ['#', 'Days', 'Line'])

        t_html_file = []
        t_html_file.append('<div class="card-body">\n')
        t_html_file.append("""
                            <table class="table-bordered table-condensed table-striped"
                                   id="dataTable1"
                                   width="100%"
                                   cellspacing="0"
                                   data-page-length="100"
                                   data-order='[[ 0, "asc" ]]'>
                            """)
        N_Cols = temp_yo_inactive_DF.shape[1]
        t_html_file.append('       <thead><tr>\n')
        for t_col_index in range(0,N_Cols):
            t_html_file.append('           <th class="px-2 text-nowrap">%s</th>\n' %temp_yo_inactive_DF.columns[t_col_index])
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        for row in temp_yo_inactive_DF.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                t_line = temp_yo_inactive_DF.iloc[row.Index][t_col_index]
                if t_col_index == N_Cols-1:
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
                else:
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')

        Watch_FName = f"{html_folder}/{hostname___}-Deltahitcnt0_ACL-Watch.html"
        log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
        # ----------------------------------------------------------------------------------------------


        # writing f"{html_folder}/{hostname___}-Deltahitcnt0_ACL-Watch_2.html" ---------------------------------
        temp_yo_inactive_below_DF = pd.DataFrame(temp_yo_inactive_below, columns = ['#', 'Days', 'Line'])

        t_html_file = []
        t_html_file.append('<div class="card-body">\n')
        t_html_file.append("""
                            <table class="table-bordered table-condensed table-striped"
                                   id="dataTable2"
                                   width="100%"
                                   cellspacing="0"
                                   data-page-length="100"
                                   data-order='[[ 0, "asc" ]]'>
                            """)
        N_Cols = temp_yo_inactive_below_DF.shape[1]
        t_html_file.append('       <thead><tr>\n')
        for t_col_index in range(0,N_Cols):
            t_html_file.append('           <th class="px-2 text-nowrap">%s</th>\n' %temp_yo_inactive_below_DF.columns[t_col_index])
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        for row in temp_yo_inactive_below_DF.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                t_line = temp_yo_inactive_below_DF.iloc[row.Index][t_col_index]
                if t_col_index == N_Cols-1:
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
                else:
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')

        Watch_FName_2 = f"{html_folder}/{hostname___}-Deltahitcnt0_ACL-Watch_2.html"
        log_msg = File_Save_Try2(Watch_FName_2, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
        # ----------------------------------------------------------------------------------------------


        # writing f"{html_folder}/{hostname___}-Deltahitcnt0_ACL-Fix.html" ---------------------------------
        Fix_FList_DeltaHit0_DF = pd.DataFrame(Fix_FList_DeltaHit0, columns = ['#', 'Days', 'Line'])

        t_html_file = []
        t_html_file.append('<div class="card-body">\n')
        t_html_file.append("""
                            <table class="table-bordered table-condensed table-striped"
                                   id="dataTable3"
                                   width="100%"
                                   cellspacing="0"
                                   data-page-length="100"
                                   data-order='[[ 0, "asc" ]]'>
                            """)
        N_Cols = Fix_FList_DeltaHit0_DF.shape[1]
        t_html_file.append('       <thead><tr>\n')
        for t_col_index in range(0,N_Cols):
            t_html_file.append('           <th class="px-2 text-nowrap">%s</th>\n' %Fix_FList_DeltaHit0_DF.columns[t_col_index])
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        for row in Fix_FList_DeltaHit0_DF.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                t_line = Fix_FList_DeltaHit0_DF.iloc[row.Index][t_col_index]
                if t_col_index == N_Cols-1:
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
                else:
                    t_html_file.append('           <td class="px-2 text-nowrap">%s</td>\n' %t_line)
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')

        Watch_FName = f"{html_folder}/{hostname___}-Deltahitcnt0_ACL-Fix.html"
        log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))
        # ----------------------------------------------------------------------------------------------

        if len(temp_few_hitcnt) > 0:
            Config_Change.append('\n\n!--- Too Few Hitcount for the following ACL (threshold at %s) ---' %Min_Hitcnt_Threshold)
            for n in temp_few_hitcnt:
                Config_Change.append(n)

        # remove deleted ines from DB -------------------------------
        Header_Printed = False
        with engine.begin() as connection:
            for row in ACL_GROSS_db.itertuples():
                t_hash = row.Hash
                Bool_check = (('Name=="%s" & Action=="%s" & Service=="%s"& Source=="%s" & Dest=="%s" & D_Port=="%s" & Hash=="%s"') %(row.Name, row.Action, row.Service, row.Source, row.Dest, row.D_Port, row.Hash))
                t_ACL_Lines_DF = ACL_Lines_DF.query(Bool_check)
                if len(t_ACL_Lines_DF) == 0: # ACL LINE is no longer in config
                    N_of_ACL_Deleted += 1
                    if Header_Printed == False:
                        Config_Change.append('\n!--- ACL removed from DB ---')
                        print('\n!--- ACL removed from DB ---')
                        Header_Printed = True
                    delete_stmt = db.delete(ACL_GROSS).where(db.and_(ACL_GROSS.c.HostName==hostname___,
                                                                     ACL_GROSS.c.Name==row.Name,
                                                                     ACL_GROSS.c.Action==row.Action,
                                                                     ACL_GROSS.c.Service==row.Service,
                                                                     ACL_GROSS.c.Source==row.Source,
                                                                     ACL_GROSS.c.Dest==row.Dest,
                                                                     ACL_GROSS.c.D_Port==row.D_Port,
                                                                     ACL_GROSS.c.Hash==row.Hash))

                    result = connection.execute(delete_stmt)
                    print(f"{result.rowcount} row(s) deleted.")
                    t_line = ['access-list',row.Name,row.Line,row.Type,row.Action,row.Service,row.Source,row.S_Port,row.Dest,row.D_Port,row.Rest,row.Inactive,row.Hitcnt,row.Hash]
                    ACL_Deleted_List.append(' '.join(t_line))

    # check unmatched entry in db
    # salva valore del numero di linee nel db con Delta_HitCnt=0 (solo per le ACL associate a interfaces)

    query = db.select(ACL_GROSS).where(db.and_(
                                                ACL_GROSS.c.HostName==hostname___,
                                                ACL_GROSS.c.Delta_HitCnt==0,
                                                ACL_GROSS.c.Inactive!='inactive'),
                                                ACL_GROSS.c.Name.in_(Accessgroup_Dic_by_if.values())
                                              )
    with engine.connect() as connection:
        ACL_GROSS_db = pd.DataFrame(connection.execute(query).fetchall())
    N_ACL_DeltaHitCnt_Zero = ACL_GROSS_db.shape[0]

    if DB_Available:
        Updated_Vals = dict(
                            N_ACL_HitCnt_Zero       = N_ACL_DeltaHitCnt_Zero,
                            N_ACL_Inactive_toDel    = N_temp_no_inactive,
                            N_ACL_HitCnt_Zero_toDel = N_temp_yo_inactive
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)

    print('Total number of Incremented ACL is %s' %N_of_ACL_Incremented)
    Config_Change.append('Total number of Incremented ACL is %s' %N_of_ACL_Incremented)
    print('Total number of resetted ACL is %s' %N_of_ACL_Resetted)
    Config_Change.append('Total number of resetted ACL is %s' %N_of_ACL_Resetted)
    print('Total number of new ACL is %s' %N_of_ACL_NEW)
    Config_Change.append('Total number of new ACL is %s' %N_of_ACL_NEW)
    print('Total number of Deleted ACL is %s' %N_of_ACL_Deleted)
    Config_Change.append('Total number of Deleted ACL is %s' %N_of_ACL_Deleted)
    for t_item in ACL_Deleted_List:
        t_item = re_space.sub(' ',t_item)
        print((f' - {t_item}'))
        Config_Change.append(f' - {t_item}')


# ===============================================
# =          Shows most triggered ACLs          =
# ===============================================

    Temp_Config_Change = []
    re_space = re.compile(r'  +') # two or more spaces
    text = ('First %s Triggered ACL' %N_ACL_Most_Triggered)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    query = db.select(ACL_GROSS).where(ACL_GROSS.columns.HostName=="%s" %hostname___)
    with engine.connect() as connection:
        ACL_GROSS_db = pd.DataFrame(connection.execute(query).fetchall())

    Deny_ACL_Triggering_TooMuch = []
    if ACL_GROSS_db.shape[0] > 0:
        ACL_GROSS_db = ACL_GROSS_db.drop(labels='ID', axis=1)
        ACL_Names = list(ACL_GROSS_db.Name.unique())
        ACL_Names.sort()

        Most_Hitted_ACL = {}
        for t_ACL in ACL_Names:
            #check only for applied ACL
            if t_ACL not in Accessgroup_Dic_by_if.values():
                continue
            Bool_check = ('Name == "%s"') %(t_ACL)
            temp_df = ACL_GROSS_db.query(Bool_check)
            temp_df_NRows = temp_df.shape[0]
            print('check_dec_shadowing for %s' %t_ACL )
            print(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))

            temp_df.insert(4,'#','-')
            BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = temp_df.shape[0]
            for row in temp_df.itertuples():
                LOOP_INDEX = LOOP_INDEX + 1
                if LOOP_INDEX > (ITEMS/STEPS)*BINS:
                    print ('....%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1
                temp_df.at[row.Index,'#'] = int(row.Line.split()[1])

            ttt = temp_df.sort_values('#')
            temp_df = ttt.reset_index()
            temp_df.drop(labels='index', axis=1)
            temp_df = temp_df.sort_values('Delta_HitCnt',ascending=False)

            Most_Hitted_ACL[t_ACL,temp_df_NRows] = []

            t_Processed_ACLs = 0
            Incremental_Line = 1

            for row in temp_df.itertuples():
                if t_Processed_ACLs == N_ACL_Most_Triggered:
                    break

                if row.Delta_HitCnt > 0:
                    percent = round(row.Index/(temp_df_NRows-1)*100,2) if temp_df_NRows-1 else 0
                    t0_line = 'Diff_HitCnt = %s' %(row.Delta_HitCnt)
                    t1_line = '%s%%' %(percent)
                    t2_line = 'access-list %s %s %s %s %s %s %s %s %s %s %s (hitcnt=%s) %s' %(
                        row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, row.Hitcnt, row.Hash)
                    t2_line = re_space.sub(' ', t2_line)
                    if row.Action == 'deny':
                        Deny_ACL_Triggering_TooMuch.append("{:<25}| {:>6} | {:<10}".format(t0_line, t1_line, t2_line))
                    else:
                        temp_item_4_MHACL = []
                        temp_item_4_MHACL.append(row.Delta_HitCnt)
                        temp_item_4_MHACL.append(percent)
                        temp_item_4_MHACL.append(t2_line)
                        [Move_to_Line, out_fnc] = Check_Dec_Shadowing(t_device, t2_line, FW_log_folder, Max_ACL_Expand_Ratio)
                        Temp_Config_Change.append('\n---'  + t2_line)
                        if Move_to_Line == -1: # ACL too big, split it
                            Log_Message = (f'@ Most Triggered ACL is too long: {out_fnc}'); print(Log_Message)
                            Config_Change.append(Log_Message)
                            row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'WARNING', 'Message':Log_Message}
                            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
                            Log_Message = (f'Skipping it and split it if to be processed'); print(Log_Message)
                            Config_Change.append(Log_Message)
                            temp_item_4_MHACL.append('ACL too long, split it! #')
                            temp_item_4_MHACL.append([])
                            Most_Hitted_ACL[t_ACL,temp_df_NRows].append(temp_item_4_MHACL)
                            continue
                        else:
                            if int(row.Line.split()[1]) == int(max(Incremental_Line,(Move_to_Line)+1)):
                                Temp_Config_Change.append('Line can not be moved...')
                                temp_item_4_MHACL.append('Line can not be moved #')
                            else:
                                Temp_Config_Change.append('can be moved up to line %s' %max(Incremental_Line,(Move_to_Line+1)))
                                temp_item_4_MHACL.append('Move to line %s' %max(Incremental_Line,(Move_to_Line+1)))
                            if (Incremental_Line >= Move_to_Line+1):
                                Incremental_Line += 1
                        Temp_Shadow_List = []
                        for n in out_fnc:
                            Temp_Config_Change.append(n)
                            Temp_Shadow_List.append(n)
                        temp_item_4_MHACL.append(Temp_Shadow_List)
                        Most_Hitted_ACL[t_ACL,temp_df_NRows].append(temp_item_4_MHACL)
                    t_Processed_ACLs += 1

    # OUTPUT HTML FILE for Most_Hitted_ACL-Watch
    t_html_file = ['\n']
    if ACL_GROSS_db.shape[0] > 0:
        t_all_zero = []
        for t_key in Most_Hitted_ACL:
            if len(Most_Hitted_ACL[t_key]) > 0:
                t_html_file.append('''\n
                <div class="card shadow mb-4">\n
                    <div class="card-header py-3">\n''')
                t_line = ('        <h6 class="m-0 font-weight-bold text-primary">%s (%s rows)</h6>\n') %(t_key[0], t_key[1])
                t_html_file.append(t_line)
                t_html_file.append('''\n
                    </div>\n
                <div class="card-body">\n
                    <table class="table-bordered table-condensed table-striped" width="100%" cellspacing="0" data-order='[[ 0, "desc" ]]' data-page-length="50" >\n
                    <thead>\n
                      <tr>\n
                        <th class="px-2">HitCnt</th>\n
                        <th class="px-2">%</th>\n
                        <th class="px-2">ACL</th>\n
                      </tr>\n
                    </thead>\n
                    <tbody>\n''')

                N_Cols = 3
                for row in Most_Hitted_ACL[t_key]:
                    t_html_file.append('       <tr>')
                    for t_col_index in range(0,N_Cols):
                        t_line = row[t_col_index]
                        if t_col_index == N_Cols-1:
                            t_line = utils_v2.Color_Line(t_line)
                            t_html_file.append('           <td>%s</td>\n' %t_line)
                        else:
                            t_html_file.append('           <td>%s</td>\n' %t_line)
                    t_html_file.append('       </tr>\n')
                t_html_file.append('''\n
                        </tbody>\n
                        </table>\n
                    </div>\n
                </div>\n
                ''')
            else:
                t_all_zero.append(1)

    if ACL_GROSS_db.shape[0] > 0:
        if sum(t_all_zero) == len(Most_Hitted_ACL):
            t_html_file.append('\n This is based on the Delta HitCnt from the previous run.<br> It needs a second run to be populated.<br>')

    Watch_FName = f"{html_folder}/{hostname___}-Most_Hitted_ACL-Watch.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    # OUTPUT HTML FILE for Most_Hitted_ACL-Think
    t_html_file = ['\n']
    if ACL_GROSS_db.shape[0] > 0:
        for t_key in Most_Hitted_ACL:
            if len(Most_Hitted_ACL[t_key]) > 0:
                t_html_file.append('<div class="card shadow mb-4">\n')
                t_html_file.append('<div class="card-header py-3">\n')
                t_line = ('<h6 class="m-0 font-weight-bold text-primary">%s (%s rows)</h6>\n') %(t_key[0], t_key[1])
                t_html_file.append(t_line)
                t_html_file.append('</div>\n')
                t_html_file.append('<div class="card-body">\n')
                N_rows = len(Most_Hitted_ACL[t_key]) - 1
                t_row_N = 0
                for row in Most_Hitted_ACL[t_key]:
                    t_html_file.append('<div class="alert alert-primary" role="alert">\n')
                    t_line = row[2]
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append(t_line+'\n')
                    t_html_file.append('</div>\n')
                    t_line = '<a class="btn btn-primary btn-icon-split btn-sm"><span class="text">&#916; HitCnt</span><span class="icon text-white-50" style="width:100px;"> %s </span></a>\n' %row[0]
                    t_html_file.append(t_line)
                    if float(row[1]) > 50:
                        t_line = '<a class="btn btn-danger btn-icon-split btn-sm"><span class="text">Position</span><span class="icon text-white-50" style="width:100px;"> %s%% </span></a>\n' %row[1]
                    else:
                        t_line = '<a class="btn btn-warning btn-icon-split btn-sm"><span class="text">Position</span><span class="icon text-white-50" style="width:100px;"> %s%% </span></a>\n' %row[1]
                    t_html_file.append(t_line)
                    try:
                        if row[3].split()[-1] == '#':
                            t_line = '<a class="btn btn-danger btn-icon-split btn-sm"><span class="text"> %s </span><span class="icon text-white-50" style="width:100px;"> %s </span></a>\n' %(' '.join(row[3].split()[0:-1]), row[3].split()[-1])
                        else:
                            t_line = '<a class="btn btn-success btn-icon-split btn-sm"><span class="text"> %s </span><span class="icon text-white-50" style="width:100px;"> %s </span></a>\n' %(' '.join(row[3].split()[0:-1]), row[3].split()[-1])
                    except Exception as e:
                        print('ERROR in Most Triggered ACL')
                        print(row)
                        print(f"An error occurred: {e}")
                    t_html_file.append(t_line)
                    t_html_file.append('<br><br>\n')
                    if len(row[4]) > 0:
                        table_id = 'TAB_'+row[2].split()[-1]
                        t_html_file.append('<style>\n')
                        t_html_file.append('  #%s {\n' %table_id)
                        t_html_file.append('    table-layout: auto;\n')
                        t_html_file.append('  }\n')
                        t_html_file.append('    #%s td, #%s th {\n'%(table_id, table_id))
                        t_html_file.append('      white-space: nowrap;')
                        t_html_file.append('  }\n')
                        t_html_file.append('</style>\n')

                        t_line = '<table class="table-bordered table-condensed table-striped table-responsive" id="%s" width="100%%" cellspacing="0">\n' %table_id
                        t_html_file.append(t_line)
                        t_html_file.append('<thead>\n')
                        t_html_file.append('  <tr>\n')
                        t_html_file.append('    <th class="text-center"> Shadow </th>\n')
                        t_html_file.append('    <th class="px-2"> Line </th>\n')
                        t_html_file.append('    <th class="text-center"> HitCnt </th>\n')
                        t_html_file.append('    <th class="text-center"> Hash </th>\n')
                        t_html_file.append('  </tr>\n')
                        t_html_file.append('</thead>\n')
                        t_html_file.append('<tbody>\n')

                        for n in range (0,len(row[4])):
                            if   ('H___' in row[4][n][0:4]):
                                t_html_file.append('  <tr class="table-info" data-toggle="tooltip" title="ACL Line Shadowed by:">\n')
                            elif ('H_n_' in row[4][n][0:4]):
                                t_html_file.append('  <tr class="table-warning" data-toggle="tooltip" title="ACL Line NOT Shadowed">\n')
                            elif ('  p ' in row[4][n][0:4]):
                                t_html_file.append('  <tr data-toggle="tooltip" title="Partially Shadowing">\n')
                            elif ('  t ' in row[4][n][0:4]):
                                t_html_file.append('  <tr data-toggle="tooltip" title="Totally Shadowing">\n')
                            else:
                                t_html_file.append('  <tr>\n')
                            t_line = row[4][n][0:4]
                            t_html_file.append('    <td class="px-2 text-center">%s</td>\n' %t_line)
                            temp = row[4][n][5:].split()
                            t_line = ' '.join(temp[0:-2])
                            t_line = utils_v2.Color_Line(t_line)
                            t_html_file.append('    <td class="px-2">%s</td>\n' %t_line)
                            t_html_file.append('    <td class="px-2 text-center">%s</td>\n' %temp[-2])
                            t_html_file.append('    <td class="px-2 text-center">%s</td>\n' %temp[-1])
                            t_html_file.append('  </tr>\n')
                        t_html_file.append('</tbody>\n')
                        t_html_file.append('</table>\n')
                        if t_row_N < N_rows:
                            t_html_file.append('<br>\n')
                        t_row_N = t_row_N + 1
                        t_html_file.append('<script>\n')
                        t_html_file.append('    $(document).ready(function() {\n')
                        t_html_file.append('        // Initialize DataTable with pageLength set to 10\n')
                        t_html_file.append("        var table = $('#%s').DataTable({\n" %table_id)
                        t_html_file.append('            "pageLength": 10,   // Set default page length to 10 entries\n')
                        t_html_file.append('            "ordering": false   // Disable sorting for all columns\n')
                        t_html_file.append('        });\n')
                        t_html_file.append('    });\n')
                        t_html_file.append('</script>\n')
                t_html_file.append('</div>\n')
                t_html_file.append('</div>\n')

    Watch_FName = f"{html_folder}/{hostname___}-Most_Hitted_ACL-Think.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    if len(Deny_ACL_Triggering_TooMuch) > 0:
        temp = []
        for line in Deny_ACL_Triggering_TooMuch:
            temp.append(line.split('|'))
        for line in temp:
            line[0] = int(line[0].split('=')[1].strip())
            line[1] = line[1].strip()
            line[2] = line[2].strip()

        Deny_ACL_Triggering_TooMuch_df = pd.DataFrame(temp, columns = ['Diff_HitCnt' , 'Percent', 'ACL'])
        Deny_ACL_Triggering_TooMuch_df = Deny_ACL_Triggering_TooMuch_df.sort_values(["Diff_HitCnt"], ascending = (False))
        Deny_ACL_Triggering_TooMuch_df = Deny_ACL_Triggering_TooMuch_df.reset_index(drop=True)

        # OUTPUT HTML FILE for Deny_ACL_Triggering_TooMuch
        t_html_file = []
        t_html_file.append('<div class="card-body">\n')
        t_html_file.append('''
           <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-order='[[ 0, "desc" ]]' data-page-length="50" >\n
           ''')
        t_html_file.append('       <thead><tr>\n')
        t_html_file.append('           <th>Diff_HitCnt</th>\n')
        t_html_file.append('           <th>%</th>\n')
        t_html_file.append('           <th>ACL</th>\n')
        t_html_file.append('       </tr></thead>\n')
        t_html_file.append('       <tbody>\n')
        N_Cols = 3
        for row in Deny_ACL_Triggering_TooMuch_df.itertuples():
            t_html_file.append('       <tr>\n')
            for t_col_index in range(0,N_Cols):
                t_line = Deny_ACL_Triggering_TooMuch_df.iloc[row.Index][t_col_index]
                if t_col_index == N_Cols-1:
                    t_line = utils_v2.Color_Line(t_line)
                    t_html_file.append('           <td>%s</td>\n' %t_line)
                else:
                    t_html_file.append('           <td>%s</td>\n' %t_line)
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')

        Watch_FName = f"{html_folder}/{hostname___}-Deny_ACL_Triggering_TooMuch-Watch.html"
        log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    else: # nothing to write... clean it!
        t_html_file=['\n This is based on the Delta HitCnt from the previous run.<br> It needs a second run to be populated.']
        Watch_FName = f"{html_folder}/{hostname___}-Deny_ACL_Triggering_TooMuch-Watch.html"
        log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
        if log_msg:
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    engine.dispose()
    return Config_Change


##===================================================================================================
##  ___  _   _  ____  ___  _  _       ____  ____  ___       ___  _   _    __    ____  _____  _    _  ____  _  _  ___
## / __)( )_( )( ___)/ __)( )/ )     (  _ \( ___)/ __)     / __)( )_( )  /__\  (  _ \(  _  )( \/\/ )(_  _)( \( )/ __)
##( (__  ) _ (  )__)( (__  )  (  ___  )(_) ))__)( (__  ___ \__ \ ) _ (  /(__)\  )(_) ))(_)(  )    (  _)(_  )  (( (_-.
## \___)(_) (_)(____)\___)(_)\_)(___)(____/(____)\___)(___)(___/(_) (_)(__)(__)(____/(_____)(__/\__)(____)(_)\_)\___/
##

# given an ACL it tries to move it up until it shadows something else
# if the ACL is partially shadowed stop the processing after "MAX_Partially_Shadowed_Lines" lines found

def Check_Dec_Shadowing(t_device, ACL_Line, log_folder, Max_ACL_Expand_Ratio):

    MAX_Partially_Shadowed_Lines = 15

    ACL_Line_DF = utils_v2.ASA_ACL_to_DF([ACL_Line])
    t_ACL_Name = ACL_Line_DF.Name[0]
    t_ACL_Line = ACL_Line_DF.Line[0]
    hostname___ = t_device.replace('/','___')

    Last_Hitted_Line = [0]
    Temp_Config_Change = []
    Temp_Overlapped = {}

    def restore_json(x):
        if pd.isna(x) or x in ('', 'None', None):
            return None
        try:
            return json.loads(x)
        except (json.JSONDecodeError, TypeError):
            return x

    tf_name = f"{log_folder}/VAR_{hostname___}___ACL_Expanded_DF"
    ACL_Expanded_DF2 = pd.read_feather(f"{tf_name}.feather")
    for c in ["S_Port", "D_Port", "Source", "Dest"]:
        if c in ACL_Expanded_DF2.columns:
            ACL_Expanded_DF2[c] = ACL_Expanded_DF2[c].apply(restore_json)

    Bool_check = ('Name == "%s" & Line == "%s"') %(t_ACL_Name, t_ACL_Line)
    ACL_Line_Expanded_DF = ACL_Expanded_DF2.query(Bool_check)
    t_ACL_ndex = ACL_Line_Expanded_DF.index[0]
    ACL_Line_Expanded_DF.reset_index(inplace=True, drop=True)
    ACL_Line_Expanded_DF_Print = pd.DataFrame(ACL_Line_Expanded_DF.Print)
    ACL_Line_Expanded_DF_Print['Shadowed'] = 0

    if len(ACL_Line_Expanded_DF_Print) > 2*Max_ACL_Expand_Ratio:
        print('ACL too big, split it!')
        print('--- %s' %ACL_Line)
        Temp_Config_Change.append('ACL too big, split it!')
        Temp_Config_Change.append('--- %s' %ACL_Line)
        return([-1, ('--- access-list %s %s' %(t_ACL_Name,t_ACL_Line))])

    Bool_check = ('Name == "%s"') %(t_ACL_Name)
    ACL_Slice_Expanded_DF = ACL_Expanded_DF2.query(Bool_check)
    ACL_Slice_Expanded_DF = ACL_Slice_Expanded_DF[ACL_Slice_Expanded_DF.index < t_ACL_ndex]
    ACL_Slice_Expanded_DF.reset_index(inplace=True, drop=True)

    #Printed_Lines = []
    for index_1 in range(len(ACL_Line_Expanded_DF)-1,-1,-1):
        Header_Printed = False
        row1 = ACL_Line_Expanded_DF.loc[index_1]
        item1_Servic = row1.Service
        item1_Source = row1.Source
        item1_Destin = row1.Dest
        item1_D_Port = row1.D_Port
        Temp_Overlapped[row1.Print] = []

        if (item1_Source == [[0,0]] and item1_Destin == [[0,0]]):
            Last_Hitted_Line.append(int(row1.Line.split()[1])-1)
            continue

        N_Partially_Shadowed_Lines = 0
        Break_Flag = False
        for index_2 in range(len(ACL_Slice_Expanded_DF)-1,-1,-1):
            if Break_Flag == True:
                break
            row2 = ACL_Slice_Expanded_DF.loc[index_2]
            item2_Servic = row2.Service
            item2_Source = row2.Source
            item2_Destin = row2.Dest
            item2_D_Port = row2.D_Port
            if item2_Servic not in PRTOTOCOLS:
                continue
            if row2.Inactive == 'inactive': # skip inactive lines
                break

            for t_item1_1_Source in item1_Source:
                if Break_Flag == True:
                    break
                for t_item2_2_Source in item2_Source:
                    Flag_Ship = [0,0,0,0]   # flags for: [SRC_IP, DST_IP, PROTO, PORT]
                                            # 0 = no shadow
                                            # 1 = totally shadowed => can cross item and go up
                                            # 2 = partly shadowed  => max moving is below the shadower

                    ip_Src_check = Is_Dec_Overlapping(t_item1_1_Source, t_item2_2_Source)
                    if ip_Src_check == 0:
                        #print('DBG__ t_item1_1_Source=%s,t_item2_2_Source=%s' %(row1.Print,row2.Print))
                        #___no_overlap___
                        continue
                    elif ip_Src_check == 1:
                        Flag_Ship[0] = 1
                        # 1 if a is totally shadowed by b (=subnet of)
                        # => item1 can cross item2 and go up
                    #    continue
                    elif ip_Src_check == 2:
                        Flag_Ship[0] = 2
                        # 2 if a is partly shadowed by b (=supernet of)
                        # => can move item1 under item2

                    if (Flag_Ship[0] == 1) or (Flag_Ship[0] == 2):
                        for t_item1_1_Destin in item1_Destin:
                            for t_item2_2_Destin in item2_Destin:
                                ip_dst_check = Is_Dec_Overlapping(t_item1_1_Destin, t_item2_2_Destin)
                                if ip_dst_check == 0:
                                    #___no_overlap___
                                    #print('DBG__ t_item1_1_Destin=%s,t_item2_2_Destin=%s' %(row1.Print,row2.Print))
                                    continue
                                elif ip_dst_check == 1:
                                    Flag_Ship[1] = 1
                                elif ip_dst_check == 2:
                                    Flag_Ship[1] = 2

                                try:
                                    Proto_Check_and = Proto_Map[item1_Servic] & Proto_Map[item2_Servic]
                                except:
                                    print('unexpected value in "Proto_Check_and"')
                                    print('row1 = %s' %row1)
                                    print('row2 = %s' %row2)
                                Proto_Check_or  = Proto_Map[item1_Servic] | Proto_Map[item2_Servic]
                                t_Proto_Check = Proto_Check_and+8 if item1_Servic=='ip' else Proto_Check_and
                                Proto_Check = Proto_Check_or * t_Proto_Check
                                try:
                                    Proto_Check in [0,1,4,12,16,24,56,60,72,84]
                                except:
                                    print('ERROR!!! Proto_Check Value not expected')

                                if Proto_Check in [0,56]:           # no shadow
                                    continue
                                elif Proto_Check in [1,12,24,84]:   # total shadow
                                    Flag_Ship[2] = 1
                                elif Proto_Check in [60,72]:        # partial shadow
                                    Flag_Ship[2] = 2
                                elif Proto_Check in [4,16]:         # check port to understand better
                                    Flag_Ship[2] = 1
                                    #Port_Found_List = [0]

                                    if len(item1_D_Port) == 1:
                                        if item1_D_Port[0] == '':
                                            Flag_Ship[3] = 2 # partially shadowed (can not cross the item)
                                        elif item2_D_Port[0] == '':
                                            Flag_Ship[3] = 1 # totally shadowed
                                        else:
                                            if len(item2_D_Port) == 1:
                                                if item1_D_Port[0] == item2_D_Port[0]:
                                                    Flag_Ship[3] = 1 # totally shadowed
                                                else:
                                                    Flag_Ship[3] = 0 # no shado
                                            elif len(item2_D_Port) == 2: # range x,y
                                                if item2_D_Port[0] <= item1_D_Port[0] <= item2_D_Port[1]:
                                                    Flag_Ship[3] = 1 # totally shadowed
                                                else:
                                                    Flag_Ship[3] = 0 # no shadow
                                            else:
                                                print('ERROR! This should not be possible!')
                                    elif len(item1_D_Port) == 2:
                                        if len(item2_D_Port) == 1:
                                            if item1_D_Port[0] == '':
                                                Flag_Ship[3] = 2
                                            else:
                                                if item1_D_Port[0] <= item2_D_Port[0] <= item1_D_Port[1]:
                                                    Flag_Ship[3] = 2 # partially shadowed
                                                else:
                                                    Flag_Ship[3] = 0 # no shadow
                                        elif len(item2_D_Port) == 2: # range x,y
                                            # if end1 <= start2 or  start1 >= end2
                                            if ((item1_D_Port[1]<=item2_D_Port[0]) or (item1_D_Port[0]>=item2_D_Port[1])):
                                                Flag_Ship[3] = 0 # no shadow
                                            # start1 < start2 and end1 > end2
                                            elif ((item1_D_Port[0]<item2_D_Port[1]) and (item1_D_Port[1]>item2_D_Port[0])):
                                                Flag_Ship[3] = 2 # partially shadowed (can not cross the item)
                                            else:
                                                Flag_Ship[3] = 1 # is not totally but can cross the item (totally like)
                                    else:
                                        print('ERROR! This should not be possible!')

                    if Flag_Ship == [1,1,1,1]: # = [1,1,1,1]
                        # 1 = totally shadowed => can cross item and go up (UNLESS different action)
                        if not(Header_Printed):
                            Temp_Config_Change.append('H___ '+row1.Print)
                            Header_Printed = True
                        Temp_Config_Change.append('  t  '+row2.Print)
                        Temp_Overlapped[row1.Print].append('  t  '+row2.Print)
                        ACL_Line_Expanded_DF_Print.loc[index_1,'Shadowed'] = 1
                    elif sum(Flag_Ship) > 4:
                        if not(Header_Printed):
                            Temp_Config_Change.append('H___ '+row1.Print)
                            Header_Printed = True
                        Temp_Config_Change.append('  p  '+row2.Print)
                        Last_Hitted_Line.append(int(row2.Line.split()[1]))
                        Temp_Overlapped[row1.Print].append('  p  '+row2.Print)
                        ACL_Line_Expanded_DF_Print.loc[index_1,'Shadowed'] = 1
                        N_Partially_Shadowed_Lines += 1
                        if N_Partially_Shadowed_Lines >= MAX_Partially_Shadowed_Lines:
                            Temp_Config_Change.append('  p  '+'... - -')
                            Break_Flag = True
                            break

    if sum(ACL_Line_Expanded_DF_Print.Shadowed) == len(ACL_Line_Expanded_DF_Print):
        #print('Totally shadowed found for this ACL')
        pass
    elif sum(ACL_Line_Expanded_DF_Print.Shadowed) != 0:
        #print('The following lines are not shadowed')
        for row_index, row in ACL_Line_Expanded_DF_Print.iterrows():
            if row.Shadowed == 0:
                #print(row.Print)
                Temp_Config_Change.append('H_n_ '+row.Print)
    #print('can be moved up to line %s\n\n' %str(1+max(Last_Hitted_Line)))
    return([max(Last_Hitted_Line), Temp_Config_Change])


##===================================================================================================
##  ___  _   _  ____  ___  _  _    _  _    __   ____
## / __)( )_( )( ___)/ __)( )/ )  ( \( )  /__\ (_  _)
##( (__  ) _ (  )__)( (__  )  (    )  (  /(__)\  )(
## \___)(_) (_)(____)\___)(_)\_)  (_)\_)(__)(__)(__)

##Max_NAT_ZeroHit_Age  = 180 #days
##Max_NAT_Inactive_Age = 180 #days
##Min_NAT_Hitcnt_Threshold   = 20
##N_ACL_Most_Triggered   = 10

def Check_NAT(t_device, Config_Change, log_folder):

    List_of_NAT_to_Remove = []
    List_of_NAT_aging_to_Remove = []
    List_of_NAT_to_Inactive = []
    List_of_NAT_aging_to_Inactive = []

    N_of_NAT_Incremented = 0
    N_of_NAT_Resetted = 0
    N_of_NAT_Deleted = 0
    N_of_NAT_New = 0
    t_N_NAT_HitCnt_Zero = 0
    t_N_NAT_HitCnt_Zero_toDel = 0
    t_N_NAT_Inactive = 0
    t_N_NAT_Inactive_toDel = 0
    DB_Available = True

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___
    hostname = t_device

    text = ('Check_NAT @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    # load Show_NAT_DF for this device
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_NAT_DF"
    Show_NAT_DF = utils_v2.Shelve_Read_Try(tf_name,'')

    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            Show_NAT_DB = db.Table('Show_NAT_DB', db.MetaData(), autoload_with=engine)
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            Global_Settings = db.Table('Global_Settings', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        Config_Change.append('=================[ Warning ]==================')
        Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    if DB_Available:
        query = db.select(Show_NAT_DB).where(Show_NAT_DB.columns.HostName=="%s" %hostname___)
        with engine.connect() as connection:
            Show_NAT_DB_df = pd.DataFrame(connection.execute(query).fetchall())

        query = db.select(Global_Settings).where(Global_Settings.c.Name=='Global_Settings')
        with engine.connect() as connection:
            Global_Settings_df = pd.DataFrame(connection.execute(query).fetchall())
    else:
        print('@ Check_NAT: DB_Available=False')

    Max_NAT_ZeroHit_Age      = Global_Settings_df.Max_NAT_ZeroHit_Age[0]
    Max_NAT_Inactive_Age     = Global_Settings_df.Max_NAT_Inactive_Age[0]
    Min_NAT_Hitcnt_Threshold = Global_Settings_df.Min_NAT_Hitcnt_Threshold[0]
    N_NAT_Most_Triggered     = Global_Settings_df.N_NAT_Most_Triggered[0]

    today = datetime.datetime.now().strftime('%Y-%m-%d')
    t_today = datetime.date(int(today.split('-')[0]),int(today.split('-')[1]),int(today.split('-')[2]))

    #check for nat removed -----------------------------
    Header_Printed = False
    if DB_Available:
        if len(Show_NAT_DB_df) > 0:
            Show_NAT_DB_df = Show_NAT_DB_df.drop(labels='id', axis=1)
        for row_index, row in Show_NAT_DB_df.iterrows():
            t_Nat_Line = row.Nat_Line
            Bool_check = ('Nat_Line == "%s"' %(t_Nat_Line))
            t_Show_NAT_DF = Show_NAT_DF.query(Bool_check)
            if len(t_Show_NAT_DF) == 0: # NAT LINE is no longer in config
                N_of_NAT_Deleted += 1
                if Header_Printed == False:
                    Config_Change.append('\n!--- NAT removed from DB ---')
                    print('\n!--- NAT removed from DB ---')
                    Header_Printed = True
                delete_stmt = db.delete(Show_NAT_DB).where(db.and_(Show_NAT_DB.c.HostName==hostname___, Show_NAT_DB.c.Nat_Line==t_Nat_Line))
                with engine.begin() as connection:
                    result = connection.execute(delete_stmt)
                Config_Change.append(t_Nat_Line)
                print(t_Nat_Line)


    if len(Show_NAT_DB_df) == 0:   # new device
        print('Device not in NAT DB... writing %s lines' %len(Show_NAT_DF))
        Config_Change.append('Device not in NAT DB... writing %s lines' %len(Show_NAT_DF))
        for row_index, row in Show_NAT_DF.iterrows():
            N_of_NAT_New += 1

            t_SRC_Origin = []
            for n in row.SRC_Origin:
                t_SRC_Origin.append(n)

            t_SRC_Natted = []
            for n in row.SRC_Natted:
                t_SRC_Natted.append(n)

            t_DST_Origin = []
            for n in row.DST_Origin:
                t_DST_Origin.append(n)

            t_DST_Natted = []
            for n in row.DST_Natted:
                t_DST_Natted.append(n)

            New_Vals = dict(
                            HostName     = hostname___,
                            Last_Seen    = today,
                            Section      = row.Section,
                            Line_N       = row.Line_N,
                            IF_IN        = row.IF_IN,
                            IF_OUT       = row.IF_OUT,
                            StaDin       = row.StaDin,
                            SRC_IP       = row.SRC_IP,
                            SNAT_IP      = row.SNAT_IP,
                            DST_IP       = row.DST_IP,
                            DNAT_IP      = row.DNAT_IP,
                            service      = row.service,
                            SRVC         = row.SRVC,
                            DSRVC        = row.DSRVC,
                            inactive     = row.inactive,
                            Direction    = row.Direction,
                            DESC         = row.DESC,
                            Tr_Hit       = row.Tr_Hit,
                            Un_Hit       = row.Un_Hit,
                            Delta_Tr_Hit = 0,
                            Delta_Un_Hit = 0,
                            Nat_Line     = row.Nat_Line,
                            SRC_Origin   = t_SRC_Origin,
                            SRC_Natted   = t_SRC_Natted,
                            DST_Origin   = t_DST_Origin,
                            DST_Natted   = t_DST_Natted
            )
            insert_stmt = Show_NAT_DB.insert().values(**New_Vals)
            with engine.begin() as connection:
                connection.execute(insert_stmt)

    else:
        for row_index, row in Show_NAT_DF.iterrows():
            Bool_check = ('Nat_Line == "%s"' %(row.Nat_Line))
            t_Show_NAT_DB = Show_NAT_DB_df.query(Bool_check)
            if len(t_Show_NAT_DB) == 0: # NAT line is new
                N_of_NAT_New += 1

                t_SRC_Origin = []
                for n in row.SRC_Origin:
                    t_SRC_Origin.append(n)

                t_SRC_Natted = []
                for n in row.SRC_Natted:
                    t_SRC_Natted.append(n)

                t_DST_Origin = []
                for n in row.DST_Origin:
                    t_DST_Origin.append(n)

                t_DST_Natted = []
                for n in row.DST_Natted:
                    t_DST_Natted.append(n)

                New_Vals = dict(
                            HostName     = hostname___,
                            Last_Seen    = today,
                            Section      = row.Section,
                            Line_N       = row.Line_N,
                            IF_IN        = row.IF_IN,
                            IF_OUT       = row.IF_OUT,
                            StaDin       = row.StaDin,
                            SRC_IP       = row.SRC_IP,
                            SNAT_IP      = row.SNAT_IP,
                            DST_IP       = row.DST_IP,
                            DNAT_IP      = row.DNAT_IP,
                            service      = row.service,
                            SRVC         = row.SRVC,
                            DSRVC        = row.DSRVC,
                            inactive     = row.inactive,
                            Direction    = row.Direction,
                            DESC         = row.DESC,
                            Tr_Hit       = row.Tr_Hit,
                            Un_Hit       = row.Un_Hit,
                            Delta_Tr_Hit = 0,
                            Delta_Un_Hit = 0,
                            Nat_Line     = row.Nat_Line,
                            SRC_Origin   = t_SRC_Origin,
                            SRC_Natted   = t_SRC_Natted,
                            DST_Origin   = t_DST_Origin,
                            DST_Natted   = t_DST_Natted
                )
                insert_stmt = Show_NAT_DB.insert().values(**New_Vals)
                with engine.begin() as connection:
                    connection.execute(insert_stmt)

            else:
                if ( (int(row.Tr_Hit) > int(t_Show_NAT_DB.Tr_Hit)) or (int(row.Un_Hit) > int(t_Show_NAT_DB.Un_Hit)) ):
                    N_of_NAT_Incremented += 1
                    if int(row.Tr_Hit)-int(t_Show_NAT_DB.Tr_Hit) <= Min_NAT_Hitcnt_Threshold:
                        if int(row.Tr_Hit)-int(t_Show_NAT_DB.Tr_Hit) != 0:
                            print('%s are too few NAT Tr_Hit in %s days' %(int(row.Tr_Hit)-int(t_Show_NAT_DB.Tr_Hit), (t_today-t_Show_NAT_DB.Last_Seen.item()).days))
                            Config_Change.append('%s are too few NAT Tr_Hit in %s days' %(int(row.Tr_Hit)-int(t_Show_NAT_DB.Tr_Hit), (t_today-t_Show_NAT_DB.Last_Seen.item()).days))
                    if int(row.Un_Hit)-int(t_Show_NAT_DB.Un_Hit) <= Min_NAT_Hitcnt_Threshold:
                        if int(row.Un_Hit)-int(t_Show_NAT_DB.Un_Hit) != 0:
                            print('%s are too few NAT Un_Hit in %s days' %(int(row.Un_Hit)-int(t_Show_NAT_DB.Un_Hit), (t_today-t_Show_NAT_DB.Last_Seen.item()).days))
                            Config_Change.append('%s are too few NAT Un_Hit in %s days' %(int(row.Un_Hit)-int(t_Show_NAT_DB.Un_Hit), (t_today-t_Show_NAT_DB.Last_Seen.item()).days))
                    if DB_Available:
                        if (int(row.Tr_Hit) - int(t_Show_NAT_DB.Tr_Hit)) > 0:
                            t_Delta_Tr_Hit = int(row.Tr_Hit) - int(t_Show_NAT_DB.Tr_Hit)
                        else:
                            t_Delta_Tr_Hit = 0

                        if (int(row.Un_Hit) - int(t_Show_NAT_DB.Un_Hit)) > 0:
                            t_Delta_Un_Hit = int(row.Un_Hit) - int(t_Show_NAT_DB.Un_Hit)
                        else:
                            t_Delta_Un_Hit = 0

                        Updated_Vals = dict(
                                            Tr_Hit      = row.Tr_Hit,
                                            Un_Hit      = row.Un_Hit,
                                            Last_Seen   = today,
                                            Delta_Tr_Hit= t_Delta_Tr_Hit,
                                            Delta_Un_Hit= t_Delta_Un_Hit,
                                            Section     = row.Section,
                                            Line_N      = row.Line_N
                                            )
                        query = db.update(Show_NAT_DB).where(db.and_(Show_NAT_DB.c.HostName==hostname___, Show_NAT_DB.c.Nat_Line==row.Nat_Line)).values(**Updated_Vals)
                        with engine.begin() as connection:
                            results = connection.execute(query)

                elif ( (int(row.Tr_Hit) == int(t_Show_NAT_DB.Tr_Hit)) and (int(row.Un_Hit) == int(t_Show_NAT_DB.Un_Hit)) ):
                    # check if to be deleted
                    t_Days = (t_today-t_Show_NAT_DB.Last_Seen.item()).days
                    t_N_NAT_HitCnt_Zero += 1
                    if 'inactive' in row.inactive:
                        if t_Days >= Max_NAT_Inactive_Age: #remove NAT from device
                            t_N_NAT_Inactive_toDel += 1
                            List_of_NAT_to_Remove.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
                        else:
                            List_of_NAT_aging_to_Remove.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])

                    else:
                        # check if to make inactive
                        if t_Days >= Max_NAT_ZeroHit_Age:  #make NAT inactive
                            # Following nat can be turned inactive
                            t_N_NAT_HitCnt_Zero_toDel += 1
                            List_of_NAT_to_Inactive.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
                        else: # nat is still aging
                            List_of_NAT_aging_to_Inactive.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
                    Updated_Vals = dict(
                                        Section      = row.Section,
                                        Line_N       = row.Line_N,
                                        Delta_Tr_Hit = 0,
                                        Delta_Un_Hit = 0
                                        )
                    query = db.update(Show_NAT_DB).where(db.and_(Show_NAT_DB.c.HostName==hostname___, Show_NAT_DB.c.Nat_Line==row.Nat_Line)).values(**Updated_Vals)
                    with engine.begin() as connection:
                        results = connection.execute(query)

                else:# counter cleared, update db
                    N_of_NAT_Resetted += 1
                    if DB_Available:
                        t_Delta_Tr_Hit = int(row.Tr_Hit)
                        t_Delta_Un_Hit = int(row.Un_Hit)
                        Updated_Vals = dict(
                                            Tr_Hit      = row.Tr_Hit,
                                            Un_Hit      = row.Un_Hit,
                                            Last_Seen   = today,
                                            Delta_Tr_Hit= t_Delta_Tr_Hit,
                                            Delta_Un_Hit= t_Delta_Un_Hit,
                                            Section     = row.Section,
                                            Line_N      = row.Line_N
                                            )
                        query = db.update(Show_NAT_DB).where(db.and_(Show_NAT_DB.c.HostName==hostname___, Show_NAT_DB.c.Nat_Line==row.Nat_Line)).values(**Updated_Vals)
                        with engine.begin() as connection:
                            results = connection.execute(query)
#---------------------------------------------------------------------------------------------------------------------------------
    Moved_NAT_Think = []
    Moved_NAT = []
    Moved_NAT_done = []
    Temp_Tr_Nat = []


    if DB_Available:
        query = db.select(Show_NAT_DB).where(db.and_(Show_NAT_DB.columns.HostName==hostname___), (Show_NAT_DB.columns.Section!=0))
        with engine.begin() as connection:
            Show_NAT_DB_df = pd.DataFrame(connection.execute(query).fetchall())

        NRows_Show_NAT_DB_df = 0
        N_Tr_Hit_Zero = 0
        N_Un_Hit_Zero = 0
        t_N_NAT_Inactive = 0
        N_NAT_Average_Position_4db = 0

        # ----- most triggered NAT -----
        tf_name = f"{FW_log_folder}/VAR_{hostname___}___Name_dic"
        Name_dic = utils_v2.Shelve_Read_Try(tf_name,'')
        if len(Show_NAT_DB_df) > 0:

            # ----- find most triggered -----
            Show_NAT_DB_df = Show_NAT_DB_df.drop(labels='id', axis=1)
            NRows_Show_NAT_DB_df = Show_NAT_DB_df.shape[0]
            N_Tr_Hit_Zero = Show_NAT_DB_df.loc[Show_NAT_DB_df['Tr_Hit'] == 0].shape[0]
            N_Tr_Hit_xcnt = round(N_Tr_Hit_Zero/NRows_Show_NAT_DB_df*100,2) if NRows_Show_NAT_DB_df else 0
            N_Un_Hit_Zero = Show_NAT_DB_df.loc[Show_NAT_DB_df['Un_Hit'] == 0].shape[0]
            N_Un_Hit_xcnt = round(N_Un_Hit_Zero/NRows_Show_NAT_DB_df*100,2) if NRows_Show_NAT_DB_df else 0
            t_N_NAT_Inactive = Show_NAT_DB_df.loc[Show_NAT_DB_df['inactive'] == 'inactive'].shape[0]
            N_inactive_xcnt = round(t_N_NAT_Inactive/NRows_Show_NAT_DB_df*100,2) if NRows_Show_NAT_DB_df else 0
            Config_Change.append('Tr_Hit == 0 for %s over %s NAT Lines (%s%%)' %(N_Tr_Hit_Zero, NRows_Show_NAT_DB_df, N_Tr_Hit_xcnt))
            Config_Change.append('Un_Hit == 0 for %s over %s NAT Lines (%s%%)' %(N_Un_Hit_Zero, NRows_Show_NAT_DB_df, N_Un_Hit_xcnt))
            Config_Change.append('inactive    for %s over %s NAT Lines (%s%%)' %(t_N_NAT_Inactive, NRows_Show_NAT_DB_df, N_inactive_xcnt))

            #move to the top the first X triggered nat ---------
            Show_NAT_DB_df['Delta_Tr_Hit_Un_Hit'] = 0
            Show_NAT_DB_df['Delta_Tr_Hit_Un_Hit'] = Show_NAT_DB_df['Delta_Tr_Hit'] + Show_NAT_DB_df['Delta_Un_Hit']
            Sum_Delta = sum(Show_NAT_DB_df['Delta_Tr_Hit_Un_Hit'])
            text = ('Most %s Tr_Hit+Un_Hit Triggered NAT' %N_NAT_Most_Triggered)
            utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
            Show_NAT_DB_df_sorted = Show_NAT_DB_df.sort_values('Delta_Tr_Hit_Un_Hit',ascending=False)
            Show_NAT_DB_df_sorted = Show_NAT_DB_df_sorted.reset_index(drop=True)
            Show_NAT_DB_df_sorted = Show_NAT_DB_df_sorted[0:N_NAT_Most_Triggered]
            Show_NAT_DB_df_sorted = Show_NAT_DB_df_sorted[Show_NAT_DB_df_sorted.Delta_Tr_Hit_Un_Hit != 0]
            Sum_Delta_sorted = sum(Show_NAT_DB_df_sorted['Delta_Tr_Hit_Un_Hit'])
            if Show_NAT_DB_df_sorted.shape[0] < N_NAT_Most_Triggered:
                N_NAT_Most_Triggered = Show_NAT_DB_df_sorted.shape[0]
            prcnt_lines = round(N_NAT_Most_Triggered/len(Show_NAT_DB_df['Line_N'])*100,2) if len(Show_NAT_DB_df['Line_N']) else 0
            prcnt_hitcnt = round(Sum_Delta_sorted/Sum_Delta*100,2) if Sum_Delta else 0
            print('%s lines out of %s (%s%%) trigger %s hitcnt out of %s (%s%%)' %(N_NAT_Most_Triggered, len(Show_NAT_DB_df['Line_N']), prcnt_lines, Sum_Delta_sorted, Sum_Delta, prcnt_hitcnt))

            if DB_Available:
                Updated_Vals = dict(
                                    N_NAT_Sum_Delta        = Sum_Delta,
                                    N_NAT_Sum_Delta_sorted = Sum_Delta_sorted
                                    )
                query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
                with engine.begin() as connection:
                    results = connection.execute(query)

            Show_NAT_DB_df = Show_NAT_DB_df.sort_values(["Section", "Line_N"], ascending = (True, True))
            Show_NAT_DB_df = Show_NAT_DB_df.reset_index(drop=True)
            t_Processed_NATs = 0
            #Incremental_Line = 1
            Section_1_NAT_Lines = Show_NAT_DB_df.loc[Show_NAT_DB_df['Section'] == 1].shape[0]
            Section_2_NAT_Lines = Show_NAT_DB_df.loc[Show_NAT_DB_df['Section'] == 2].shape[0]
            Section_3_NAT_Lines = Show_NAT_DB_df.loc[Show_NAT_DB_df['Section'] == 3].shape[0]

            for row_index, row in Show_NAT_DB_df_sorted.iterrows():
                if t_Processed_NATs == N_NAT_Most_Triggered:
                    break
                else:
                    if row.Delta_Tr_Hit_Un_Hit > 0:
                        if row['Section'] == 0:
                            continue
                        if row['Section'] == 1:
                            NAT_Position = row['Line_N']
                        elif row['Section'] == 2:
                            NAT_Position = row['Line_N'] + Section_1_NAT_Lines
                        elif row['Section'] == 3:
                            NAT_Position = row['Line_N'] + Section_1_NAT_Lines + Section_2_NAT_Lines
                        percent = round(NAT_Position/(NRows_Show_NAT_DB_df)*100) if NRows_Show_NAT_DB_df else 0
                        Temp_Tr_Nat.append(['%s' %(row.Delta_Tr_Hit_Un_Hit), '%s%%' %(percent), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
                        t_Processed_NATs += 1

            Temp_Tr_Nat_DF = pd.DataFrame(Temp_Tr_Nat, columns = ['Diff_Tr/Un' , '%', 'Section', 'NAT'])
            temp = 0
            for row_index, row in Temp_Tr_Nat_DF.iterrows():
                temp = temp + float(row['%'].strip('%'))
            temp = temp / N_NAT_Most_Triggered if N_NAT_Most_Triggered else 0
            N_NAT_Average_Position_4db = round(temp,1)

            # ---- move most triggered to the top -----
            for index_0, row_0 in Show_NAT_DB_df_sorted.iterrows():
                for index_1 in range(len(Show_NAT_DB_df)-1,-1,-1):
                    Header_Printed = False
                    row_1 = Show_NAT_DB_df.loc[index_1]
                    if row_0['Nat_Line'] == row_1['Nat_Line']:
                        if index_1 > 0:
                            for index_2 in range(index_1-1,-1,-1):

                                if index_2 == 0:
                                    # no shadow found
                                    if row_0.Nat_Line not in Moved_NAT_done:
                                        Moved_NAT.append([0, row_0.Section,  row_0.Line_N, row_0.Nat_Line.replace(') to (',',')])
                                        Moved_NAT_done.append(row_0.Nat_Line)

                                row_2 = Show_NAT_DB_df.loc[index_2]
                                if row_2['inactive'] == 'inactive':
                                    continue
                                flag_ship = [0,0,0,0,0,0]
                                # [IF_IN, IF_OUT, SRC_IP, DST_IP, SRVC, DSRVC]
                                # 0 = no overlap
                                # 1 = yes overlap
                                if (row_0['IF_IN'] == row_2['IF_IN']) or (row_2['IF_IN']=='any'):
                                    flag_ship[0] = 1
                                    if (row_0['IF_OUT'] == row_2['IF_OUT']) or (row_2['IF_OUT']=='any'):
                                        flag_ship[1] = 1

                                        for row_0_SRC in row_0['SRC_Origin']:
                                            try:
                                                try:
                                                    row_0_SRC_IP = ipaddress.IPv4Network(row_0_SRC, strict=False)
                                                except:
                                                    row_0_SRC_IP = ipaddress.IPv4Network(Name_dic[row_0_SRC.rsplit('/')[0]] +'/'+ row_0_SRC.rsplit('/')[1], strict=False)
                                            except:
                                                print(f'1. Cannot convert "{row_0_SRC}" to IPv4')
                                                continue
                                            for row_2_SRC in row_2['SRC_Origin']:
                                                try:
                                                    try:
                                                        row_2_SRC_IP = ipaddress.IPv4Network(row_2_SRC, strict=False)
                                                    except:
                                                        row_2_SRC_IP = ipaddress.IPv4Network(Name_dic[row_2_SRC.rsplit('/')[0]] +'/'+ row_2_SRC.rsplit('/')[1], strict=False)
                                                except:
                                                    print(f'2. Cannot convert "{row_2_SRC}" to IPv4')
                                                    continue
                                                if row_0_SRC_IP.subnet_of(row_2_SRC_IP) or row_0_SRC_IP.supernet_of(row_2_SRC_IP):
                                                    flag_ship[2] = 1

                                                    for row_0_DST in row_0['DST_Origin']:
                                                        try:
                                                            try:
                                                                row_0_DST_IP = ipaddress.IPv4Network(row_0_DST, strict=False)
                                                            except:
                                                                row_0_DST_IP = ipaddress.IPv4Network(Name_dic[row_0_DST.rsplit('/')[0]] +'/'+ row_0_DST.rsplit('/')[1], strict=False)
                                                        except:
                                                            print(f'3. Cannot convert "{row_0_DST}" to IPv4')
                                                            continue
                                                        for row_2_DST in row_2['DST_Origin']:
                                                            try:
                                                                try:
                                                                    row_2_DST_IP = ipaddress.IPv4Network(row_2_DST, strict=False)
                                                                except:
                                                                    row_2_DST_IP = ipaddress.IPv4Network(Name_dic[row_2_DST.rsplit('/')[0]] +'/'+ row_2_DST.rsplit('/')[1], strict=False)
                                                            except:
                                                                print(f'4. Cannot convert "{row_2_DST}" to IPv4')
                                                                continue
                                                            else:
                                                                if row_0_DST_IP.subnet_of(row_2_DST_IP) or row_0_DST_IP.supernet_of(row_2_DST_IP):
                                                                    flag_ship[3] = 1
                                                                    if row_0.SRVC == row_2.SRVC:
                                                                        flag_ship[4] = 1
                                                                        if row_0.DSRVC == row_2.DSRVC:
                                                                            flag_ship[5] = 1
                                                                            Moved_NAT_Think.append('\nForward NAT Shadow for %s and %s' %(row_2_SRC, row_2_DST))
                                                                            Moved_NAT_Think.append('line %s = %s' %(row_0.Line_N,row_0.Nat_Line))
                                                                            Moved_NAT_Think.append('line %s = %s' %(row_2.Line_N,row_2.Nat_Line))
                                                                            if row_0.Nat_Line not in Moved_NAT_done:
                                                                                Moved_NAT.append([row_2.Line_N, row_0.Section, row_0.Line_N, row_0.Nat_Line.replace(') to (',',')])
                                                                                Moved_NAT_done.append(row_0.Nat_Line)
                                                                            break
                                                else:
                                                    continue

                                        if (row_0['StaDin'] != 'dynamic') and (row_0['Direction'] != 'unidirectional'):
                                            for row_0_SRC in row_0['DST_Natted']:
                                                try:
                                                    try:
                                                        row_0_SRC_IP = ipaddress.IPv4Network(row_0_SRC, strict=False)
                                                    except:
                                                        row_0_SRC_IP = ipaddress.IPv4Network(Name_dic[row_0_SRC.rsplit('/')[0]] +'/'+ row_0_SRC.rsplit('/')[1], strict=False)
                                                except:
                                                    print(f'5. Cannot convert "{row_0_SRC}" to IPv4')
                                                    continue
                                                for row_2_SRC in row_2['DST_Natted']:
                                                    try:
                                                        try:
                                                            row_2_SRC_IP = ipaddress.IPv4Network(row_2_SRC, strict=False)
                                                        except:
                                                            row_2_SRC_IP = ipaddress.IPv4Network(Name_dic[row_2_SRC.rsplit('/')[0]] +'/'+ row_2_SRC.rsplit('/')[1], strict=False)
                                                    except:
                                                        print(f'6. Cannot convert "{row_2_SRC}" to IPv4')
                                                        continue
                                                    if row_0_SRC_IP.subnet_of(row_2_SRC_IP) or row_0_SRC_IP.supernet_of(row_2_SRC_IP):
                                                        flag_ship[2] = 1

                                                        for row_0_DST in row_0['SRC_Natted']:
                                                            try:
                                                                try:
                                                                    row_0_DST_IP = ipaddress.IPv4Network(row_0_DST, strict=False)
                                                                except:
                                                                    row_0_DST_IP = ipaddress.IPv4Network(Name_dic[row_0_DST.rsplit('/')[0]] +'/'+ row_0_DST.rsplit('/')[1], strict=False)
                                                            except:
                                                                print(f'7. Cannot convert "{row_0_DST}" to IPv4')
                                                                continue
                                                            for row_2_DST in row_2['SRC_Natted']:
                                                                try:
                                                                    try:
                                                                        row_2_DST_IP = ipaddress.IPv4Network(row_2_DST, strict=False)
                                                                    except:
                                                                        row_2_DST_IP = ipaddress.IPv4Network(Name_dic[row_2_DST.rsplit('/')[0]] +'/'+ row_2_DST.rsplit('/')[1], strict=False)
                                                                except:
                                                                    print(f'8. Cannot convert "{row_2_DST}" to IPv4')
                                                                    continue
                                                                else:
                                                                    if row_0_DST_IP.subnet_of(row_2_DST_IP or row_0_DST_IP.supernet_of(row_2_DST_IP)):
                                                                        flag_ship[3] = 1
                                                                        if row_0.SRVC == row_2.SRVC:
                                                                            flag_ship[4] = 1
                                                                            if row_0.DSRVC == row_2.DSRVC:
                                                                                flag_ship[5] = 1
                                                                                Moved_NAT_Think.append('\nBackward NAT Shadow  ----- ')
                                                                                Moved_NAT_Think.append("row_0['StaDin'] = %s" %row_0['StaDin'])
                                                                                Moved_NAT_Think.append("row_0['Direction'] = %s" %row_0['Direction'])
                                                                                Moved_NAT_Think.append('line %s = %s' %(row_0.Line_N,row_0.Nat_Line))
                                                                                Moved_NAT_Think.append('line %s = %s' %(row_2.Line_N,row_2.Nat_Line))
                                                                                if row_0.Nat_Line not in Moved_NAT_done:
                                                                                    Moved_NAT.append([row_2.Line_N, row_0.Section, row_0.Line_N, row_0.Nat_Line.replace(') to (',',')])
                                                                                    Moved_NAT_done.append(row_0.Nat_Line)
                                                                                break
                                                    else:
                                                        continue
                        else:
                            print('already position 1')
                            pass

    New_Position_Sec1 = 1
    New_Position_Sec3 = 1
    Moved_NAT_Fix = []
    for t_field in Moved_NAT:
        t_new_item = []
        t_nat_cmd = t_field[3]
        if t_field[1] == 1:
            temp = t_nat_cmd.split()
            if len(temp) > 5:
                t_rest = (' '.join(temp[5:])).strip()
            else:
                t_rest = (' '.join(temp[1:])).strip()
            t_new_item.append('show nat | i %s' %t_rest)
            t_new_item.append('no nat %s ' %t_nat_cmd)
            t_new_item.append('show nat | i %s' %t_rest)
            if t_field[0] == 0:
                t_new_item.append('nat %s %s %s' %(temp[0], New_Position_Sec1, ' '.join(temp[1:])))
                t_new_item.append('show nat | i %s' %t_rest)
                New_Position_Sec1 += 1
            else:
                t_new_item.append('nat %s %s %s' %(temp[0], t_field[0]+1, ' '.join(temp[1:])))
                t_new_item.append('show nat | i %s' %t_rest)
        elif t_field[1] == 2:
            t_new_item.append('Object NAT to be converted:\n%s\n' %row_0.Nat_Line)
        elif t_field[1] == 3:
            temp = t_nat_cmd.split()
            if len(temp) > 5:
                t_rest = (' '.join(temp[5:])).strip()
            else:
                t_rest = (' '.join(temp[1:])).strip()
            t_new_item.append('show nat | i %s' %t_rest)
            t_new_item.append('no nat %s after-auto %s' %(temp[0], ' '.join(temp[1:])) )
            t_new_item.append('show nat | i %s' %t_rest)
            if t_field[0] == 0:
                t_new_item.append('nat %s after-auto %s %s' %(temp[0], New_Position_Sec3, ' '.join(temp[1:])))
                t_new_item.append('show nat | i %s' %t_rest)
                New_Position_Sec3 += 1
            else:
                t_new_item.append('nat %s after-auto %s %s' %(temp[0], t_field[0]+1, ' '.join(temp[1:])))
                t_new_item.append('show nat | i %s' %t_rest)
        else:
            print('How can it be????')
        Moved_NAT_Fix.append(t_new_item)

    #---------------- Most_Triggered_NAT-Watch.html
    Watch_FList = []
    Watch_FList.append('<div class="card-body">\n')
    Watch_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('         <th>%s</th>\n' %'Delta_Tr/Un')
    Watch_FList.append('         <th>%s</th>\n' %'%')
    Watch_FList.append('         <th>%s</th>\n' %'Position')
    Watch_FList.append('         <th>%s</th>\n' %'NAT')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('      <tbody>\n')
    for t_line in Temp_Tr_Nat:
        Watch_FList.append('         <tr>\n')
        Watch_FList.append('            <td>%s</td>\n' %t_line[0])
        Watch_FList.append('            <td>%s</td>\n' %t_line[1])
        Watch_FList.append('            <td>%s</td>\n' %t_line[2])
        Watch_FList.append('            <td class="text-nowrap mr-2">%s</td>\n' %(utils_v2.Color_Line(t_line[3])) )
        Watch_FList.append('         </tr>\n')
    Watch_FList.append('      </tbody>\n')
    Watch_FList.append('   </table>\n')
    Watch_FList.append('</div>\n')

    Watch_FName = FW_log_folder + '/' + hostname___ + '-Most_Triggered_NAT-Watch.html'
    try:
        with open(Watch_FName,mode="w") as html_file:
            html_file.writelines(Watch_FList)
        print('... saved file "%s" '%(Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName))

    #---------------- Most_Triggered_NAT-fIX.html
    Fix_FList=[]
    Fix_FList.append('<div class="card-body">\n')
    Fix_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Fix_FList.append('      <tbody>\n')
    for t_cell in Moved_NAT_Fix:
        Fix_FList.append('         <tr>\n')
        new_block = ''
        for t_line in t_cell:
            new_line = utils_v2.Color_Line(t_line)
            new_block = new_block + new_line + '<br>\n'
        Fix_FList.append('            <td class="text-nowrap mr-2"><br>%s<br></td>\n' %new_block)
        Fix_FList.append('         </tr>\n')
    Fix_FList.append('      </tbody>\n')
    Fix_FList.append('   </table>\n')
    Fix_FList.append('</div>\n')

    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Most_Triggered_NAT-Fix.html'
    try:
        with open(Fix_FName,mode="w") as html_file:
            html_file.writelines(Fix_FList)
        print('... saved file "%s" '%(Fix_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Fix_FName))

    #check for changes in NAT --------------------------

    #check for possible NAT shadowing ------------------

    #------------------------ --------------------------
    print('N_of_NAT_Incremented = %s' %N_of_NAT_Incremented)
    print('N_of_NAT_Resetted = %s' %N_of_NAT_Resetted)
    print('N_of_NAT_Deleted = %s' %N_of_NAT_Deleted)
    print('N_of_NAT_New = %s' %N_of_NAT_New)
    Config_Change.append('\n')
    Config_Change.append('N_of_NAT_Incremented = %s' %N_of_NAT_Incremented)
    Config_Change.append('N_of_NAT_Resetted = %s' %N_of_NAT_Resetted)
    Config_Change.append('N_of_NAT_Deleted = %s' %N_of_NAT_Deleted)
    Config_Change.append('N_of_NAT_New = %s' %N_of_NAT_New)
    Config_Change.append('\n')

    #check for nat against routing -----------------------------
    Printed_Lines = []
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ROUTE_DF"
    ROUTE_DF = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_Crypto_RemoteNet_List"
    Show_Crypto_RemoteNet_List = utils_v2.Shelve_Read_Try(tf_name,'')

    ROUTE_IP_DF = ROUTE_DF.copy()
    for row_index, row in ROUTE_IP_DF.iterrows():
        try:
            ROUTE_IP_DF.at[row_index, 'Network'] = ipaddress.IPv4Network(row.Network)
        except:
            try:
                t_ip_name = row.Network.split('/')[0]
                t_ip = Name_dic[t_ip_name]
                t_sm = row.Network.split('/')[1]
                ROUTE_IP_DF.at[row_index, 'Network'] = ipaddress.IPv4Network(t_ip + '/' + t_sm, strict=False)
            except:
                Moved_NAT_Think.append('ERROR 5433 while converting %s to ipaddress\n' %row.Network)
                print('ERROR 5433 while converting %s to ipaddress\n' %row.Network)
                ROUTE_IP_DF = ROUTE_IP_DF.drop(row_index)
                continue

    Show_Crypto_RemoteNet_IP_List = []
    for n in Show_Crypto_RemoteNet_List:
        Show_Crypto_RemoteNet_IP_List.append(ipaddress.IPv4Network(n))

    for row_index, row in Show_NAT_DB_df.iterrows():
        t_IF_IN = row.IF_IN
        t_SRC_Origin_L = row.SRC_Origin
        t_SRC_Origin_L1 = t_SRC_Origin_L.copy()
        Object_Found = False
        for t_SRC_Origin in t_SRC_Origin_L1:
            try:
                t_SRC_Origin_IP = ipaddress.IPv4Network(t_SRC_Origin, strict=False)
            except:
                try:
                    t_ip_name = t_SRC_Origin.split('/')[0]
                    t_ip = Name_dic[t_ip_name]
                    t_sm = t_SRC_Origin.split('/')[1]
                    t_SRC_Origin_IP = ipaddress.IPv4Network(t_ip + '/' + t_sm, strict=False)
                except:
                    print('can not translate to IP this "%s" @ "%s"' %(t_SRC_Origin, row.Nat_Line))
                    continue

            Bool_check = ('Interface == "%s"') %(t_IF_IN)
            BEST_ROUTE = ''
            WIDE_ROUTE_List = []
            if t_IF_IN == 'any':
                Routing_L = ROUTE_IP_DF['Network'].to_list()
            else:
                Routing_L = ROUTE_IP_DF.query(Bool_check)['Network'].to_list()
            for this_route in Routing_L:
                if t_SRC_Origin_IP.subnet_of(this_route):
                    if BEST_ROUTE == '':
                        BEST_ROUTE = this_route
                    elif this_route.subnet_of(BEST_ROUTE): # swap routes
                        BEST_ROUTE = this_route
            if BEST_ROUTE == '': #no best route found
                if t_SRC_Origin != '0.0.0.0/0':
                    for this_route in Routing_L:
                        if this_route.subnet_of(t_SRC_Origin_IP):
                            WIDE_ROUTE_List.append(str(this_route))
            if WIDE_ROUTE_List != []:
                text_line = ('\n [%s|%s] %s\n' %(row.Section,row.Line_N,row.Nat_Line))
                if text_line not in Printed_Lines:
                    Moved_NAT_Think.append('\n---### NAT Object wider than routing ###---' + text_line)
                    Printed_Lines.append(text_line)
                text_line = (' - Surce_Object is "%s", interface is "%s", routing is:' %(t_SRC_Origin, t_IF_IN))
                if text_line not in Printed_Lines:
                    Moved_NAT_Think.append(text_line)
                    Printed_Lines.append(text_line)
                    for n in WIDE_ROUTE_List:
                        Moved_NAT_Think.append('   %s' %n)
                    Moved_NAT_Think.append('!')

            if BEST_ROUTE == '':
                if WIDE_ROUTE_List == []:
                    if t_SRC_Origin != '0.0.0.0/0':
                        # check if it is in a VPN
                        Route_in_VPN = False
                        for t_vpn_net in Show_Crypto_RemoteNet_IP_List:
                            if t_SRC_Origin_IP.subnet_of(t_vpn_net):
                                Route_in_VPN = True
                                break

                        if Route_in_VPN == False:
                            t0_line = 'Object %s' %(t_SRC_Origin)
                            t1_line = 'does not belong to interface %s' %(t_IF_IN)
                            text_line = ("{:<26} {:<1}".format(t0_line, t1_line))
                            t_SRC_Origin_L.remove(t_SRC_Origin)
                            Moved_NAT_Think.append(text_line)
                            Object_Found = True

        if len(t_SRC_Origin_L) == 0:
            # check if counter is incrementing with wrong routing...
            if (row.Delta_Tr_Hit > 0) or (row.Delta_Un_Hit > 0):
                if BEST_ROUTE == '':
                    if WIDE_ROUTE_List == []:
                        if t_SRC_Origin != '0.0.0.0/0':
                            if Route_in_VPN == False:
                                text_line = ('\n- WARNING!!!! Counter incrementing with missing routing')
                                Moved_NAT_Think.append(text_line)
                                text_line = ('- (%s/%s) [%s|%s] @ %s\n' %(row.Tr_Hit,row.Un_Hit,row.Section,row.Line_N,row.Nat_Line))
                                Moved_NAT_Think.append(text_line)
            # otherwise you can remove the nat...
            text_line = ('All objects found.\n - (%s/%s) [%s|%s] @ %s\n' %(row.Tr_Hit,row.Un_Hit,row.Section,row.Line_N,row.Nat_Line))
            Moved_NAT_Think.append(text_line)
        else:
            if Object_Found == True:
                text_line = ('Remaining objects are:\n - ')
                for n in t_SRC_Origin_L:
                    text_line = text_line+('%s, ' %n)
                text_line = text_line +('\n - (%s/%s) [%s|%s] @ %s\n' %(row.Tr_Hit,row.Un_Hit,row.Section,row.Line_N,row.Nat_Line))
                Moved_NAT_Think.append(text_line)

    if DB_Available:
        Updated_Vals = dict(
                                N_NAT_Lines              = NRows_Show_NAT_DB_df,
                                N_NAT_TrHit_0            = N_Tr_Hit_Zero,
                                N_NAT_UnHit_0            = N_Un_Hit_Zero,
                                N_NAT_Inactive           = t_N_NAT_Inactive,
                                N_NAT_Inactive_toDel     = t_N_NAT_Inactive_toDel,
                                N_NAT_HitCnt_Zero        = t_N_NAT_HitCnt_Zero,
                                N_NAT_HitCnt_Zero_toDel  = t_N_NAT_HitCnt_Zero_toDel,
                                N_NAT_Average_Position   = N_NAT_Average_Position_4db,
                                N_NAT_Incremented        = N_of_NAT_Incremented,
                                N_NAT_Resetted           = N_of_NAT_Resetted,
                                N_NAT_Deleted            = N_of_NAT_Deleted,
                                N_NAT_New                = N_of_NAT_New
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)

    engine.dispose()

    #---------------- Inactive_NAT-Watch.html
    Watch_FList = []
    Watch_FList.append('<div class="card-body">\n')
    Watch_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('         <th>%s</th>\n' %'Days')
    Watch_FList.append('         <th>%s</th>\n' %'Section')
    Watch_FList.append('         <th>%s</th>\n' %'NAT')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('      <tbody>\n')
    for t_line in List_of_NAT_to_Remove:
        Watch_FList.append('         <tr>\n')
        Watch_FList.append('            <td>%s</td>\n' %t_line[0])
        Watch_FList.append('            <td>%s</td>\n' %t_line[3])
        Watch_FList.append('            <td class="text-nowrap mr-2">%s</td>\n' %utils_v2.Color_Line(t_line[4]))
        Watch_FList.append('         </tr>\n')
    Watch_FList.append('      </tbody>\n')
    Watch_FList.append('   </table>\n')
    Watch_FList.append('</div>\n')

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-Inactive_NAT-Watch.html'
    try:
        with open(Watch_FName,mode="w") as html_file:
            html_file.writelines(Watch_FList)
        print('... saved file "%s" '%(Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName))

    #---------------- Inactive_NAT-Watch_2.html
    Watch_FList = []
    Watch_FList.append('<div class="card-body">\n')
    Watch_FList.append('   <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50">\n')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('         <th>%s</th>\n' %'Days')
    Watch_FList.append('         <th>%s</th>\n' %'Section')
    Watch_FList.append('         <th>%s</th>\n' %'NAT')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('      <tbody>\n')
    for t_line in List_of_NAT_aging_to_Remove:
        Watch_FList.append('         <tr>\n')
        Watch_FList.append('            <td>%s</td>\n' %t_line[0])
        Watch_FList.append('            <td>%s</td>\n' %t_line[3])
        Watch_FList.append('            <td class="text-nowrap mr-2">%s</td>\n' %utils_v2.Color_Line(t_line[4]))
        Watch_FList.append('         </tr>\n')
    Watch_FList.append('      </tbody>\n')
    Watch_FList.append('   </table>\n')
    Watch_FList.append('</div>\n')

    Watch_FName_2 = FW_log_folder + '/' + hostname___ + '-Inactive_NAT-Watch_2.html'
    try:
        with open(Watch_FName_2,mode="w") as html_file:
            html_file.writelines(Watch_FList)
        print('... saved file "%s" '%(Watch_FName_2))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName_2))

    #---------------- Inactive_NAT-Fix.html
    t_Fix_FList = []
    for t_row in List_of_NAT_to_Remove:
        t_section = int(t_row[3].strip('[').strip(']').split('|')[0])
        if t_section == 1:
            t_Fix_FList.append('no nat %s\n' %t_row[4].replace(') to (',','))
        elif t_section == 2:
            t_Fix_FList.append('to be implemented --- remove object nat for\n %s\n' %t_row[4])
        elif t_section == 3:
            temp = ('no nat %s\n' %t_row[4].replace(') to (',','))
            t_Fix_FList.append(temp.replace(') ',') after-auto '))

    Fix_FList=[]
    Fix_FList.append('<div class="card-body">\n')
    Fix_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Fix_FList.append('      <tbody>\n')
    for t_line in t_Fix_FList:
        Fix_FList.append('         <tr>\n')
        Fix_FList.append('            <td class="text-nowrap mr-2">%s</td>\n' %utils_v2.Color_Line(t_line))
        Fix_FList.append('         </tr>\n')
    Fix_FList.append('      </tbody>\n')
    Fix_FList.append('   </table>\n')
    Fix_FList.append('</div>\n')

    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Inactive_NAT-Fix.html'
    try:
        with open(Fix_FName,mode="w") as html_file:
            html_file.writelines(Fix_FList)
        print('... saved file "%s" '%(Fix_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Fix_FName))

    #---------------- Deltahitcnt0_NAT-Watch.html
    Watch_FList = []
    Watch_FList.append('<div class="card-body">\n')
    Watch_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('         <th>%s</th>\n' %'Days')
    Watch_FList.append('         <th>%s</th>\n' %'Section')
    Watch_FList.append('         <th>%s</th>\n' %'NAT')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('      <tbody>\n')
    for t_line in List_of_NAT_to_Inactive:
        Watch_FList.append('         <tr>\n')
        Watch_FList.append('            <td>%s</td>\n' %t_line[0])
        Watch_FList.append('            <td>%s</td>\n' %t_line[3])
        Watch_FList.append('            <td class="text-nowrap mr-2">%s</td>\n' %utils_v2.Color_Line(t_line[4]))
        Watch_FList.append('         </tr>\n')
    Watch_FList.append('      </tbody>\n')
    Watch_FList.append('   </table>\n')
    Watch_FList.append('</div>\n')

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_NAT-Watch.html'
    try:
        with open(Watch_FName,mode="w") as html_file:
            html_file.writelines(Watch_FList)
        print('... saved file "%s" '%(Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName))

    #---------------- Deltahitcnt0_NAT-Watch_2.html
    Watch_FList = []
    Watch_FList.append('<div class="card-body">\n')
    Watch_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('         <th>%s</th>\n' %'Days')
    Watch_FList.append('         <th>%s</th>\n' %'Section')
    Watch_FList.append('         <th>%s</th>\n' %'NAT')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('      <tbody>\n')
    for t_line in List_of_NAT_aging_to_Inactive:
        Watch_FList.append('         <tr>\n')
        Watch_FList.append('            <td>%s</td>\n' %t_line[0])
        Watch_FList.append('            <td>%s</td>\n' %t_line[3])
        Watch_FList.append('            <td class="text-nowrap mr-2">%s</td>\n' %utils_v2.Color_Line(t_line[4]))
        Watch_FList.append('         </tr>\n')
    Watch_FList.append('      </tbody>\n')
    Watch_FList.append('   </table>\n')
    Watch_FList.append('</div>\n')

    Watch_FName_2 = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_NAT-Watch_2.html'
    try:
        with open(Watch_FName_2,mode="w") as html_file:
            html_file.writelines(Watch_FList)
        print('... saved file "%s" '%(Watch_FName_2))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName_2))

    #---------------- Deltahitcnt0_NAT-Fix.html
    t_Fix_FList = []
    for t_row in List_of_NAT_to_Inactive:
        t_section = int(t_row[3].strip('[').strip(']').split('|')[0])
        if t_section == 1:
            t_Fix_FList.append('nat %s inactive\n' %t_row[4].replace(') to (',','))
        elif t_section == 2:
            t_Fix_FList.append('to be implemented --- remove object nat for\n %s\n' %t_row[4])
        elif t_section == 3:
            temp = ('nat %s inactive\n' %t_row[4].replace(') to (',','))
            t_Fix_FList.append(temp.replace(') ',') after-auto '))

    Fix_FList=[]
    Fix_FList.append('<div class="card-body">\n')
    Fix_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Fix_FList.append('      <tbody>\n')
    for t_line in t_Fix_FList:
        Fix_FList.append('         <tr>\n')
        Fix_FList.append('            <td class="text-nowrap mr-2">%s</td>\n' %utils_v2.Color_Line(t_line))
        Fix_FList.append('         </tr>\n')
    Fix_FList.append('      </tbody>\n')
    Fix_FList.append('   </table>\n')
    Fix_FList.append('</div>\n')

    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_NAT-Fix.html'
    try:
        with open(Fix_FName,mode="w") as html_file:
            html_file.writelines(Fix_FList)
        print('... saved file "%s" '%(Fix_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Fix_FName))

    Think_FName   = FW_log_folder + '/' + hostname___ + '-Most_Triggered_NAT-Think.html'
    Write_Think_File(Think_FName, Moved_NAT_Think)

    return Config_Change


##===================================================================================================
##  ___  _   _  ____  ___  _  _       ____    __    _  _  ___  ____
## / __)( )_( )( ___)/ __)( )/ )     (  _ \  /__\  ( \( )/ __)( ___)
##( (__  ) _ (  )__)( (__  )  (  ___  )   / /(__)\  )  (( (_-. )__)
## \___)(_) (_)(____)\___)(_)\_)(___)(_)\_)(__)(__)(_)\_)\___/(____)

##Max_Port_Range  = 100
##Max_IPv4_Range  = 20

def Check_Range(t_device, Config_Change, log_folder):

    #html_file_list = []
    t_html_file = []
    t_Config_Change = []

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___
    Err_folder  = log_folder
    html_folder = FW_log_folder

    hostname = t_device
    #config_range_html = hostname___ + '-Config_Range.html'

    text = ('Check_Range @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    t_html_file.append('       <tbody>\n')

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
            WTF_Log    = db.Table('WTF_Log',    db.MetaData(), autoload_with=engine)
            Top_IP_Range    = db.Table('Top_IP_Range',    db.MetaData(), autoload_with=engine)
            Global_Settings = db.Table('Global_Settings', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('=================[ Warning ]==================')
        print('DB not connected, some feature is unavailable\n')
        t_Config_Change.append('=================[ Warning ]==================')
        t_Config_Change.append('DB not connected, some feature is unavailable\n')
        DB_Available = False

    if DB_Available:
        query = db.select(Global_Settings).where(Global_Settings.c.Name=='Global_Settings')
        with engine.connect() as connection:
            Global_Settings_df = pd.DataFrame(connection.execute(query).fetchall())
    else:
        print('@ Check_Range: DB_Available=False')

    Max_IPv4_Range = Global_Settings_df.Max_IPv4_Range[0]
    Max_Port_Range = Global_Settings_df.Max_Port_Range[0]

    # load Obj_Net_Dic for this device
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obj_Net_Dic"
    Obj_Net_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_SVC_Dic"
    OBJ_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_GRP_SVC_Dic"
    OBJ_GRP_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic:
        if len(t_OBJ_GRP_SVC_Dic_key.split()) == 2:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = [t_OBJ_GRP_SVC_Dic_key.split()[1], OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)]
        else:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = ['', OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)]

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines"
    Show_ACL_Lines = utils_v2.Shelve_Read_Try(tf_name,'')

    #remove_tags = re.compile('<.*?>')

    N_Range_IP_Obj = 0
    N_Max_Range_IP = 0
    IP_Ranges_for_DB = {}
    for t_obj_key in Obj_Net_Dic:
        t_value = Obj_Net_Dic[t_obj_key]
        if t_value.startswith('range '):
            IP_1_dec = IPv4_to_DecList(t_value.split()[1], '0.0.0.0')
            IP_2_dec = IPv4_to_DecList(t_value.split()[2], '0.0.0.0')
            N_of_IPs = IP_2_dec[0] - IP_1_dec[0] + 1
            if N_of_IPs > Max_IPv4_Range:
                N_Range_IP_Obj += 1
                if (N_of_IPs > N_Max_Range_IP): N_Max_Range_IP = N_of_IPs
                #text_line = 'object network %s\n  %s\n' %(t_obj_key,t_value)
                t_html_file.append('<tr><td class="text-nowrap"><ul>\n')
                t_html_file.append('<_L1_TEXT_> '+'<br><li>IPs Range: %s</li>\n' %(N_of_IPs))
                t_html_file.append('<_CODE_> '+'object network %s<br>\n &nbsp;&nbsp; %s<br><br>\n' %(t_obj_key,t_value))
                IP_Ranges_for_DB[t_obj_key] = [t_value, N_of_IPs]
                Out = []
                t_Out = Where_Used(t_device, t_obj_key, FW_log_folder, Out)
                if t_Out:
                    for line in t_Out:
                        t_html_file.append(line+'<br>')
                t_html_file.append('</ul></td></tr>\n')

    N_Range_Port_Obj = 0
    N_Max_Range_Port = 0
    for t_obj_key in OBJ_SVC_Dic:
        t_value = OBJ_SVC_Dic[t_obj_key]
        if ' range 'in t_value:
            Port1 = t_value.split('range')[1].split()[0]
            if Port1.isnumeric() == True:
                Port1 = int(Port1)
            else:
                try:
                    Port1 = int(Port_Converter[Port1])
                except:
                    print('port %s not a number and not a string' %(Port1))
            Port2 = t_value.split('range')[1].split()[1]
            if Port2.isnumeric() == True:
                Port2 = int(Port2)
            else:
                try:
                    Port2 = int(Port_Converter[Port2])
                except:
                    print('port %s not a number and not a string' %(Port2))
            N_of_Ports = Port2 - Port1 + 1
            if N_of_Ports > Max_Port_Range:
                N_Range_Port_Obj += 1
                if (N_of_Ports > N_Max_Range_Port): N_Max_Range_Port = N_of_Ports
                #text_line = 'object service %s\n %s\n' %(t_obj_key,t_value)
                t_html_file.append('<tr><td class="text-nowrap"><ul>\n')
                t_html_file.append('<_L1_TEXT_> '+'<br><li>Port Range: %s</li>\n' %(N_of_Ports))
                t_html_file.append('<_CODE_> '+'object service %s<br>\n &nbsp;&nbsp; %s<br><br>\n' %(t_obj_key,t_value))
                Out = []
                t_Out = Where_Used(t_device, t_obj_key, FW_log_folder, Out)
                if t_Out:
                    for line in t_Out:
                        t_html_file.append(line+'<br>')
                t_html_file.append('</ul></td></tr>\n')

    for t_obj_key in OBJ_GRP_SVC_Dic_2:
        t_value = OBJ_GRP_SVC_Dic_2[t_obj_key][1]
        t_proto = OBJ_GRP_SVC_Dic_2[t_obj_key][0]
        for tt_item in t_value:
            if ' range 'in tt_item:
                Port1 = tt_item.split('range')[1].split()[0]
                if Port1.isnumeric() == True:
                    Port1 = int(Port1)
                else:
                    try:
                        Port1 = int(Port_Converter[Port1])
                    except:
                        print('port %s not a number and not a string' %(Port1))

                Port2 = tt_item.split('range')[1].split()[1]
                if Port2.isnumeric() == True:
                    Port2 = int(Port2)
                else:
                    try:
                        Port2 = int(Port_Converter[Port2])
                    except:
                        print('port %s not a number and not a string' %(Port2))
                N_of_Ports = Port2 - Port1 + 1
                if N_of_Ports > Max_Port_Range:
                    N_Range_Port_Obj += 1
                    if (N_of_Ports > N_Max_Range_Port): N_Max_Range_Port = N_of_Ports
                    #text_line = 'object-group service %s %s\n %s\n' %(t_obj_key,t_proto,tt_item)
                    t_html_file.append('<tr><td class="text-nowrap"><ul>\n')
                    t_html_file.append('<_L1_TEXT_> '+'<br><li>Port Range: %s</li>\n' %(N_of_Ports))
                    t_html_file.append('<_CODE_> '+'object-group service %s %s<br>\n &nbsp;&nbsp; %s<br><br>\n' %(t_obj_key,t_proto,tt_item))
                    Out = []
                    t_Out = Where_Used(t_device, t_obj_key, FW_log_folder, Out)
                    if t_Out:
                        for line in t_Out:
                            t_html_file.append(line+'<br>')
                    t_html_file.append('</ul></td></tr>\n')

    for t_item in Show_ACL_Lines:
        if ' range 'in t_item:
            Port1 = t_item.split('range')[1].split()[0]
            if Port1.isnumeric() == True:
                Port1 = int(Port1)
            else:
                try:
                    Port1 = int(Port_Converter[Port1])
                except:
                    print('port "%s" not a number and not a known' %Port1)
            Port2 = t_item.split('range')[1].split()[1]
            if Port2.isnumeric() == True:
                Port2 = int(Port2)
            else:
                try:
                    Port2 = int(Port_Converter[Port2])
                except:
                    print('port2 "%s" not a number and not a known' %Port2)
            N_of_Ports = Port2 - Port1 + 1
            if N_of_Ports > Max_Port_Range:
                N_Range_Port_Obj += 1
                if (N_of_Ports > N_Max_Range_Port): N_Max_Range_Port = N_of_Ports
                #text_line = '\n\n==> spans %s Ports\n%s\n' %(N_of_Ports,t_item)
                t_html_file.append('<tr><td class="text-nowrap"><ul>\n')
                t_html_file.append('<_L1_TEXT_> '+'<br><li>Port Range: %s</li><br>\n' %(N_of_Ports))
                t_html_file.append('<_CODE_> '+'%s\n' %(t_item))
                t_html_file.append('</ul></td></tr>\n')

    t_html_file.append('       </tbody>\n')
    t_html_file.append('   </table>\n')
    t_html_file.append('</div>\n')
    print('Number of IP range objects over %s is: %s' %(Max_IPv4_Range,N_Range_IP_Obj) )
    print('Max IP Range declared is: %s' %(N_Max_Range_IP) )
    print('Number of Port range objects over %s is: %s' %(Max_Port_Range,N_Range_Port_Obj))
    print('Max Port Range declared is: %s' %(N_Max_Range_Port) )

    if DB_Available:
        Updated_Vals = dict(
                            Max_Range_IP   = N_Max_Range_IP,
                            Max_Range_Port = N_Max_Range_Port
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)

        delete_stmt = db.delete(Top_IP_Range).where(Top_IP_Range.c.HostName == hostname___)
        with engine.begin() as connection:
            result = connection.execute(delete_stmt)

        # IP_Ranges_for_DB[t_obj_key] = [t_value, N_of_IPs]
        for t_key in IP_Ranges_for_DB:
            Insert_Vals = dict(
                            HostName = hostname___,
                            Obj_Name = t_key,
                            IP_Range_Length = IP_Ranges_for_DB[t_key][1]
                            )
            insert_stmt = Top_IP_Range.insert().values(**Insert_Vals)
            with engine.begin() as connection:
                results = connection.execute(insert_stmt)

        engine.dispose()

    for i in range(0,len(t_html_file)):
        t_line = t_html_file[i]
        if t_line.split()[0] == '<_CODE_>':
            t_line = ' '.join(t_line.split()[1:])
            t_line = utils_v2.Color_Line(t_line)
            t_html_file[i] = ('%s\n' %t_line)
        elif t_line.split()[0] == '<_L1_TEXT_>':
            t_html_file[i] = ('%s\n' %' '.join(t_line.split()[1:]))
        elif t_line.split()[0] == '<_L2_TEXT_>':
            t_html_file[i] = ('%s\n' %' '.join(t_line.split()[1:]))

    t_html_file.append('</ul><br>\n')
    t_html_file.append('</p>\n')

    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
            raise OSError("Can't create destination directory (%s)!" % (html_folder))

    Watch_FName = f"{html_folder}/{hostname___}-Config_Range.html"
    log_msg = File_Save_Try2(Watch_FName, t_html_file, t_ErrFileFullName, Config_Change)
    if log_msg:
        with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**log_msg))

    for t in t_Config_Change:
        Config_Change.append(t.rstrip())
    return Config_Change

##===================================================================================================
## _    _  _   _  ____  ____  ____       __  __  ___  ____  ____
##( \/\/ )( )_( )( ___)(  _ \( ___)     (  )(  )/ __)( ___)(  _ \
## )    (  ) _ (  )__)  )   / )__)  ___  )(__)( \__ \ )__)  )(_) )
##(__/\__)(_) (_)(____)(_)\_)(____)(___)(______)(___/(____)(____/

# Given a "Firewall" and an "Object" name finds all the occurences of it.
# It looks in access-lists and nat lines.
# It goes recursively on sub-objects found


def Where_Used(t_device, t_Object_Name, log_folder, Out):

    hostname___ = t_device.replace('/','___')
    #log_folder = log_folder + '/' + hostname___
    hostname = t_device

    tf_name = f"{log_folder}/VAR_{hostname___}___Obj_Net_Dic"
    Obj_Net_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{log_folder}/VAR_{hostname___}___OBJ_SVC_Dic"
    OBJ_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{log_folder}/VAR_{hostname___}___OBJ_GRP_NET_Dic"
    OBJ_GRP_NET_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{log_folder}/VAR_{hostname___}___OBJ_GRP_SVC_Dic"
    OBJ_GRP_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic:
        if len(t_OBJ_GRP_SVC_Dic_key.split()) == 2:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)

    tf_name = f"{log_folder}/VAR_{hostname___}___Show_ACL_Lines"
    Show_ACL_Lines = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{log_folder}/VAR_{hostname___}___Show_NAT_DF"
    Show_NAT_DF = utils_v2.Shelve_Read_Try(tf_name,'')

    if  ( (t_Object_Name in Obj_Net_Dic) or
        (t_Object_Name in OBJ_GRP_NET_Dic) or
        (t_Object_Name in OBJ_SVC_Dic) or
        (t_Object_Name in OBJ_GRP_SVC_Dic_2) ):
        # find in access-list
        Printed_Lines = []
        for t_acl_line in Show_ACL_Lines:
            if t_Object_Name in t_acl_line.strip().split():
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> found as object in ACL\n' %t_Object_Name) if not (t_Object_Name in Printed_Lines) else ''
                Out.append('<_CODE_> '+'%s\n' %t_acl_line)
                Printed_Lines.append(t_Object_Name)
        #find in nat
        Printed_Lines = []
        for row in Show_NAT_DF.itertuples():
            if t_Object_Name in row.Nat_Line.strip().split():
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> found as object in NAT\n' %t_Object_Name) if not (t_Object_Name in Printed_Lines) else ''
                Out.append('<_CODE_> '+'%s\n' %row.Nat_Line)
                Printed_Lines.append(t_Object_Name)

    for t_OBJ_GRP_KEY in OBJ_GRP_NET_Dic:
        for t_OBJ_GRP_VALS in OBJ_GRP_NET_Dic[t_OBJ_GRP_KEY]:
            if t_Object_Name in t_OBJ_GRP_VALS.strip().split():
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> nested found as object in <b>"%s"</b>\n' %(t_Object_Name, t_OBJ_GRP_KEY))
                Where_Used(t_device, t_OBJ_GRP_KEY, log_folder, Out)

    for t_OBJ_GRP_KEY in OBJ_GRP_SVC_Dic_2:
        for t_OBJ_GRP_VALS in OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_KEY]:
            if t_Object_Name in t_OBJ_GRP_VALS.strip().split():
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> nested found as object in <b>"%s"</b>\n' %(t_Object_Name, t_OBJ_GRP_KEY))
                Where_Used(t_device, t_OBJ_GRP_KEY, log_folder, Out)

    return Out

##=============================================================================================================================
