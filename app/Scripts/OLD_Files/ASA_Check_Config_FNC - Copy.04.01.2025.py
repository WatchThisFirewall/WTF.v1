
import os, sys
import datetime
import re
from difflib import Differ
import utils_v2
import datetime
from ASA_Check_Config_PARAM import *
from utils_v2 import Write_Think_File, File_Save_Try, File_Save_Try2

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException, BadHostKeyException
from pathlib import Path



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
    t_line = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    Config_Change.append('Timestamp = %s\n' %t_line)
    print(f'Timestamp = %s\n' %t_line)

    import time
    Commands = []
    Commands.append('term page 0')
    Commands.append('show ver')
    Commands.append('show run access-group')
    Commands.append('show nameif')
    #Commands.append('show interface')
    Commands.append('show capture')
    Commands.append('show running-config')
    Commands.append('show route')
    Commands.append('show access-list')
    Commands.append('show nat detail')
    Commands.append('show crypto ipsec sa entry')

    #log_folder = "Output_Log"
    #print('Get_ASA_Commands device = %s' %Device)

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
    while retries <= 3:
        try:
            print('trying to connect to %s...' %(Device_Info["host"]))
            Config_Change.append(f'trying to connect to {Device_Info["host"]}...')
            device_connection = ConnectHandler(**Device_Info)
            if device_connection.is_alive() == False:
                err_line = f'device_connection.is_alive() == False:'
                print(err_line)
                Config_Change.append(err_line)
                return False
            else:
                err_line = f'device_connection.is_alive() == True:'
                print(err_line)
                Config_Change.append(err_line)
                break
        except NetmikoTimeoutException:
            err_line = f'Connection timed out!'
            print(err_line)
            Config_Change.append(err_line)
            retries +=1
        except NetmikoAuthenticationException:
            err_line = f'Authentication failed!'
            print(err_line)
            Config_Change.append(err_line)
            retries +=1
        except BadHostKeyException:
            err_line = f'The host key is not recognized. Possible man-in-the-middle attack!'
            print(err_line)
            Config_Change.append(err_line)
            retries +=1
        except SSHException:
            err_line = f'SSH connection failed!'
            print(err_line)
            Config_Change.append(err_line)
            retries +=1
        except Exception as e:
            err_line = f'An unexpected error occurred: {e}'
            print(err_line)
            Config_Change.append(err_line)
            retries +=1

    if retries >= 3:
        err_line = f'_________________________________________________________'
        print(err_line)
        Config_Change.append(err_line)
        err_line = f'FAILED TO CONNECT TO {Device[4]}@{Device[0]}")'
        print(err_line)
        Config_Change.append(err_line)
        return False

    if Device_Info['device_type'] == 'cisco_ftd':
        device_connection.send_command('system support diagnostic-cli',max_loops=50000,delay_factor=1)
        device_connection.send_command('enable\n',max_loops=50000,delay_factor=1)
##        device_connection.send_command('system support diagnostic-cli')
##        device_connection.send_command('enable')

    hostname = device_connection.find_prompt()[:-1]
    #print(hostname)
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
        #time.sleep(2)
        while retries <5:
            try:
                output.append("%s\n\n%s\n\n" %(t_Command, device_connection.send_command(t_Command,max_loops=50000,delay_factor=3,read_timeout=600*retries)))
                #output.append("%s\n\n%s\n\n" %(t_Command, device_connection.send_command(t_Command,max_loops=50000,delay_factor=1)))
                break
            except Exception as e:
                print(f"Error while executing command: {e}")
                retries +=1
                time.sleep(retries*2)
        if retries == 4:
            Log_Message = (f"UNABLE TO RUN COMMAND {t_Command} on {hostname}"); print(Log_Message)
            Config_Change.append(Log_Message)
            return False

    device_connection.disconnect()

    FW_log_folder = log_folder + '/' + hostname___
    if not os.path.exists(FW_log_folder):
        try:
            os.mkdir(FW_log_folder)
        except:
             raise OSError("Can't create destination directory (%s)!" % (FW_log_folder))

    try:
        with open("%s/%s.txt"%(FW_log_folder,hostname___),"w+") as f:
            for n in output:
                f.write('\n\n!_________________________________________________________\n\n')
                f.write(n)
                f.write('\n\n')
        print('... saved file "%s/%s.txt" '%(FW_log_folder,hostname___))
        Config_Change.append('... saved file "%s/%s.txt" '%(FW_log_folder,hostname___))
        return True
    except:
        print("Can't write to destination file (%s/%s.txt)!" % (FW_log_folder,hostname___))
        Config_Change.append("Can't write to destination file (%s/%s.txt)!" % (FW_log_folder,hostname___))
        return False



##=============================================================================================================================
## ___  ____  __    ____  ____      ___  _   _  _____  _    _       ____  __  __  _  _
##/ __)(  _ \(  )  (_  _)(_  _)    / __)( )_( )(  _  )( \/\/ )     (  _ \(  )(  )( \( )
##\__ \ )___/ )(__  _)(_   )(  ___ \__ \ ) _ (  )(_)(  )    (  ___  )   / )(__)(  )  (
##(___/(__)  (____)(____) (__)(___)(___/(_) (_)(_____)(__/\__)(___)(_)\_)(______)(_)\_)

def Split_Show_run(Device, Config_Change, Show_Line, log_folder):
    hostname___ = Device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___

    # read previusly collected output
    try:
        with open("%s/%s.txt"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            l = f.readlines()
    except:
        print('file %s/%s.txt not found!' %(FW_log_folder,hostname___))
        Config_Change_Dic.append(f'file {FW_log_folder}/{hostname___}.txt not found!')

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
##    try:
##        with open("%s/%s___%s.txt"%(FW_log_folder,hostname___,Show_Line.title().strip().replace(' ','_')),"w") as f:
##            for n in temp:
##                f.write(n)
##    except:
##        print("Can't open file %s/%s___%s.txt for writing" %(FW_log_folder,hostname___,Show_Line.title().strip().replace(' ','_')))

    t_DestFileFullName = ("%s/%s___%s.txt"%(FW_log_folder,hostname___,Show_Line.title().strip().replace(' ','_')))
    #retries = File_Save_Try(tf_name,temp)
    File_Save_Try2(t_DestFileFullName, temp, t_ErrFileFullName, Config_Change)



##=============================================================================================================================
##  ___  _____  _  _  ____  ____  ___    ____  ____  ____  ____
## / __)(  _  )( \( )( ___)(_  _)/ __)  (  _ \(_  _)( ___)( ___)
##( (__  )(_)(  )  (  )__)  _)(_( (_-.   )(_) )_)(_  )__)  )__)
## \___)(_____)(_)\_)(__)  (____)\___/  (____/(____)(__)  (__)

def Config_Diff(Device, Config_Change, log_folder):

    import sqlalchemy as db
    import pandas as pd
    import shelve
    from tabulate import tabulate

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

    hostname___ = Device.replace('/','___')
    Err_folder = log_folder
    FW_log_folder = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    #log_folder = hostname___
    global WTF_Error_FName

    text = ('Config Diff @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    T_0_ShowRun_file   = FW_log_folder + '/' + hostname___ + '.CFG.t-0.txt'
    T_1_ShowRun_file   = FW_log_folder + '/' + hostname___ + '.CFG.t-1.txt'
    Delta_ShowRun_file = FW_log_folder + '/' + hostname___ + '.CFG.Delta.txt'
    Delta_ShowRun_html = hostname___ + '.CFG.Delta.html'
##    confdiff_MASTER    =  '../../app/templates/confdiff_MASTER.html'
##    confdiff_html      =  '../../app/templates/confdiff.html'
    #html_folder        = '../../app/templates/Log_FW/' + FW_log_folder
    html_folder = FW_log_folder

##if T_0_ShowRun_file does not exist:
##    T_0_ShowRun_file = show_run
##    T_1_ShowRun_file = show_run
##    html_file = ''
##else:
##    T_0_ShowRun_file = show_run
##    Delta_file = T_0_ShowRun_file - T_1_ShowRun_file
##    Append Delta_file to old one
##    make html

    if os.path.isfile(T_0_ShowRun_file):
        os.path.exists(T_1_ShowRun_file) and os.remove(T_1_ShowRun_file)
        os.rename(T_0_ShowRun_file, T_1_ShowRun_file)
        try:
            with open("%s/%s"%(html_folder,Delta_ShowRun_html),mode="w") as html_file:
                html_file.write('\n')
            print('... saved file "%s/%s" '%(html_folder,Delta_ShowRun_html))
        except:
            raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Delta_ShowRun_html))

    try:
        with open("%s/%s___Show_Running-Config.txt" %(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            new_file = f.readlines()
        with open(T_0_ShowRun_file,"w") as f:
            for n in new_file:
                f.write(n)
    except:
        print('new file "%s___Show_Running-Config.txt" for compare missing' %hostname___)

    Delta_File = []
    try:
        with open(T_1_ShowRun_file, mode='r', encoding='utf-8', errors='replace') as f:
            old_file = f.readlines()

            differ = Differ()
            Line_Number = 0
            for line in differ.compare(old_file, new_file):
                Delta_File.append([Line_Number, line.strip()])
                Line_Number += 1
    except:
        print('old file "%s" for compare missing' %T_1_ShowRun_file)
        old_file = ''


    Num_Added_Lines = 0
    Num_Remvd_Lines = 0
    Diff_Only = []
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

    #Config_Change.append('Added Lines = %s' %str(Num_Added_Lines))
    #Config_Change.append('Remvd Lines = %s' %str(Num_Remvd_Lines))
    if DB_Available:
        Updated_Vals = dict(
                            Config_Diff_Added_Lines = Num_Added_Lines,
                            Config_Diff_Remvd_Lines = Num_Remvd_Lines,
                            Config_Total_Lines = len(new_file)
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)
        #print(f"{results.rowcount} row(s) updated.")
        engine.dispose()



    t_now = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')

    OLD_Diff_File_Exists = False
    try:
        tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Diff_Only_DF')
        with shelve.open(tf_name) as shelve_obj: OLD_Diff_Only_DF = shelve_obj['0']
        OLD_Diff_File_Exists = True
    except:
        pass
    # if date file older than X, delete old log
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    t_today = datetime.date(int(today.split('-')[0]),int(today.split('-')[1]),int(today.split('-')[2]))

    if OLD_Diff_File_Exists == True:
        # reset column 'NEW'
        OLD_Diff_Only_DF['New'] = ''
        # delete too old lines
        for row in OLD_Diff_Only_DF[::-1].itertuples():
            temp = row.Date.split('-')[0]
            t_read_date = datetime.date(int(temp.split('.')[0]),int(temp.split('.')[1]),int(temp.split('.')[2]))
            if (t_today-t_read_date).days >= Max_Diff_Log_Age:
                OLD_Diff_Only_DF=OLD_Diff_Only_DF.drop(row.Index)

    if len(Diff_Only) > 0:
        col_names = ['Line_N','Line']
        NEW_Diff_Only_DF = pd.DataFrame(Diff_Only, columns = col_names)
        NEW_Diff_Only_DF.insert(0,'Date',t_now)
        NEW_Diff_Only_DF.insert(2,'New','NEW')
        if OLD_Diff_File_Exists:
            Diff_Only_DF = pd.concat([NEW_Diff_Only_DF, OLD_Diff_Only_DF], ignore_index=True)
        else:
            Diff_Only_DF = NEW_Diff_Only_DF

        Config_Change.append(tabulate(Diff_Only_DF,Diff_Only_DF,tablefmt='psql',showindex=False))
        #print(tabulate(Diff_Only_DF,Diff_Only_DF,tablefmt='psql',showindex=False))

        tf_name = "%s/VAR_%s___%s"%(FW_log_folder, hostname___, 'Diff_Only_DF')
        retries = utils_v2.Shelve_Write_Try(tf_name, Diff_Only_DF)
        if retries == 3:
            with open("%s/%s"%(Err_folder, WTF_Error_FName),"a+") as f:
                f.write('Cannot write file %s/VAR_%s___%s! @ Config_Diff\n' %(FW_log_folder, hostname___, 'Diff_Only_DF'))

        with open(Delta_ShowRun_file, mode="w") as txt_file:
            txt_file.write(tabulate(Diff_Only_DF,Diff_Only_DF,tablefmt='psql',showindex=False))
    else:
        #first run or no diff... different handling?
        tf_name = "%s/VAR_%s___%s"%(FW_log_folder, hostname___, 'Diff_Only_DF')
        file_path = Path(tf_name)
        if file_path.exists():
            Diff_Only_DF = utils_v2.Shelve_Read_Try(tf_name, Diff_Only_DF)
            if not Diff_Only_DF.empty:
                if Diff_Only_DF.shape[0] > 0:
                    Diff_Only_DF['New'] = ''
        else:
            Diff_Only_DF = pd.DataFrame()

    # OUTPUT HTML FILE
    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
             raise OSError("Can't create destination directory (%s)!" % (html_folder))

    t_html_file = []
    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('''
       <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-order='[[ 0, "desc" ]]' data-page-length="50" >\n
       ''')
    my_index = 0
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
                    t_html_file.append('           <td>%s</td>\n' %new_line)
                elif t_col_index == 0:
                    t_html_file.append('           <td>%s</td>\n' %Diff_Only_DF.iloc[row.Index][t_col_index])
                else :
                    t_html_file.append('           <td class="text-center">%s</td>\n' %Diff_Only_DF.iloc[row.Index][t_col_index])
            t_html_file.append('       </tr>\n')
        t_html_file.append('       </tbody>\n')
        t_html_file.append('   </table>\n')
        t_html_file.append('</div>\n')
    else:
        t_html_file.append('\n')

    try:
        with open("%s/%s"%(html_folder,Delta_ShowRun_html),mode="w") as html_file:
            html_file.writelines(t_html_file)
        print('... saved file "%s/%s" '%(html_folder,Delta_ShowRun_html))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Delta_ShowRun_html))


    # ============================================
    # ========= config length line chart =========
    # ============================================
    from utils_v2 import timedelta_in_months
    from utils_v2 import File_Save_Try
    ConfLenHist_FList = []
    ConfLenHist_FName = ('%s/%s-ConfLenHist.txt' %(FW_log_folder,hostname___))
    t_year_Nbr  = int(datetime.datetime.now().strftime('%Y'))
    t_month_Nbr = int(datetime.datetime.now().strftime('%m'))
    t_month_Str = datetime.datetime.now().strftime('%b')

    ConfLenHist_Exists = False
    if len(new_file) > 0:
        try:
    ##  if ConfLenHist.txt exist:
            with open(ConfLenHist_FName,'r', encoding='utf-8', errors='replace') as f:
                ConfLenHist = f.readlines()
            ConfLenHist_Exists = True
    ##      if last_month_Nbr == t_month_Nbr:
            File_Last_Year  = int(ConfLenHist[-1].split()[0].split('-')[0])
            File_Last_Month = int(ConfLenHist[-1].split()[0].split('-')[1])

            start_date = datetime.datetime(File_Last_Year, File_Last_Month, 1)
            end_date   = datetime.datetime(t_year_Nbr, t_month_Nbr, 1)
            Delta_Months = timedelta_in_months(start_date, end_date)

    ##        create x axis series and update value
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
            with open(ConfLenHist_FName, "w") as f:
                f.write(text)
                print('... saved file "%s"' %ConfLenHist_FName)

    if ConfLenHist_Exists == True:
        if Delta_Months == 0:
            ConfLenHist[-1] = ConfLenHist[-1].split()[0]+ ' ' + str(len(new_file)) + '\n'
            text = ''.join(i for i in ConfLenHist)
        elif Delta_Months == 1:
##          left_shift the array for delta values
            ConfLenHist = ConfLenHist[Delta_Months:] + ConfLenHist[:Delta_Months]
            ConfLenHist[-1] = '%s-%s %s\n' %(t_year_Nbr,t_month_Nbr,len(new_file))
            text = ''.join(i for i in ConfLenHist)
        elif Delta_Months <= 24:
##          left_shift the array for delta values
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
##            rebuild from scratch
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

        with open(ConfLenHist_FName, "w") as f:
            f.write(text)
            print('... saved file "%s"' %ConfLenHist_FName)

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

    t_fname = ("%s/chart-area1.js"%(html_folder))
    File_Save_Try(t_fname,l)

    return Config_Change


##=============================================================================================================================
##   __    ___  __      _  _  ___    ____  _  _  ____  ____  ____  ____  ____  __    ___  ____
##  /__\  / __)(  )    ( \/ )/ __)  (_  _)( \( )( ___)(_  _)( ___)(  _ \( ___)/__\  / __)( ___)
## /(__)\( (__  )(__    \  / \__ \   _)(_  )  (  )__)   )(   )__)  )   / )__)/(__)\( (__  )__)
##(__)(__)\___)(____)    \/  (___/  (____)(_)\_)(____) (__) (____)(_)\_)(__)(__)(__)\___)(____)

def ACL_VS_Interface(t_device, Config_Change, log_folder):
    import time
    from utils_v2 import Write_Think_File

    hostname___ = t_device.replace('/','___')
    Err_folder  = log_folder
    FW_log_folder  = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    #html_folder = '../../app/templates/Log_FW/' + FW_log_folder
    global WTF_Error_FName
    Watch_FList = []
    Watch_FName = FW_log_folder + '/' + hostname___ + '-Unprotected_IF-Watch.html'
    Think_FList = []
    Think_FName = FW_log_folder + '/' + hostname___ + '-Unprotected_IF-Think.html'
    Fix_FList   = []
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Unprotected_IF-Fix.html'
    #Merge_Flist = []
    #Merge_FName = FW_log_folder + '/' + hostname___ + '-Unprotected_IF-Merge.txt'
    #Merge_Flist.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    #Merge_Flist.append('!')

    #text = ('Unprotected IF @ %s' %hostname___)
    #utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    #utils_v2.Text_in_Frame (text, Merge_Flist)

    if not os.path.exists(html_folder):
        try:
            os.mkdir(html_folder)
        except:
             raise OSError("Can't create destination directory (%s)!" % (html_folder))

    text = ('Acl Vs Ineterface @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    import shelve
    import sqlalchemy as db
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

    try:
        with open("%s/%s___Show_Nameif.txt"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            l = f.readlines()
    except:
        print('ERROR!!! file %s/%s___Show_Nameif.txt not found!' %(FW_log_folder,hostname___))
    #tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    #with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_if')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_if = shelve_obj['0']

    Nameif_Dic = {}
    for n in range(1,len(l)):
        if re.match(r'^\s*$', l[n]):
            continue
        elif ('Interface' in l[n]) and ('Name' in l[n]):
            continue
        else:
            Nameif_Dic[l[n].split()[1]] = l[n].split()[0]

##    try:
##        with open("%s/%s___Show_Run_Access-Group.txt"%(FW_log_folder,hostname___),"r") as f:
##            l = f.readlines()
##    except:
##        print('ERROR!!! file %s/%s___Show_Run_Access-Group.txt not found!' %(FW_log_folder,hostname___))
##
##    Accessgroup_Dic_by_if = {}
##    for n in range(1,len(l)):
##        if l[n].startswith('access-group'):
##            if l[n].split()[-1] != 'global' :
##                Accessgroup_Dic_by_if[l[n].split()[4]] = l[n].split()[1]
##
##    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_if')
##    utils_v2.Shelve_Write_Try(tf_name,Accessgroup_Dic_by_if)

    t_N_Interfaces_NoACL = 0
    t_N_Interfaces = len(Nameif_Dic.keys())
    Done_Flag = False
    for n in Nameif_Dic.keys():
        if n not in Accessgroup_Dic_by_if.keys():
            if not Done_Flag:
                #Watch_FList.append('The Following Interfaces have not ACLs applied:<br>')
                text_line = ('The following Interfaces have not ACLs applied:')
                Done_Flag = True
##            print('Warning... No access-list configured on Interface "%s"' %n)
##            Config_Change.append('Warning... No access-list configured on Interface "%s"' %n)
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

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
    Root_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict.keys())
    #Vals_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF_light(ACL_List_Dict.values())
    for t_item in Accessgroup_Dic_by_if.keys():
        Root_ACL_Lines_DF_Slice = Root_ACL_Lines_DF.loc[Root_ACL_Lines_DF['Name'] == Accessgroup_Dic_by_if[t_item]]
        Root_ACL_Lines_DF_Slice.reset_index(inplace=True, drop=True)
        #Vals_ACL_Lines_DF_Slice = Vals_ACL_Lines_DF.loc[Vals_ACL_Lines_DF['Name'] == Accessgroup_Dic_by_if[t_item]]
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
            #print(f"{results.rowcount} row(s) updated.")



##    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List')
##    with shelve.open(tf_name) as shelve_obj: ACL_List = shelve_obj['0']
##    for t_item in ACL_List:
##        if t_item not in Accessgroup_Dic_by_if.values():
##            query = db.insert(ACL_Summary).values(  HostName=t_device,
##                                                    ACL_Name=t_item)
##            ResultProxy = connection.execute(query)

    #query = db.delete(ACL_Summary).where(db.and_(Active_Capture.columns.HostName==row.HostName, Active_Capture.columns.Name==row.Name))

    retries = 0
    if len(Watch_FList) >= 1:
        while retries < 3:
            try:
                with open(Watch_FName, "w+") as f:
                    f.write('<p class="text-secondary" >\n')
                    f.write('%s<br>\n' %text_line)
                    f.write('<ul>\n')
                    for item in Watch_FList:
                        f.write('<li>%s</li>\n' %item)
                        #f.write('<li>\n' + '<li>\n '.join(Watch_FList))
                    f.write('</ul>\n')
                    f.write('</p>\n')
                    print('... saved file "%s"' %Watch_FName)
                    break
            except:
                retries +=1
                time.sleep(retries*2)
        if retries == 3:
            print('ERROR!!! Cannot write to file %s' %Watch_FName)

        Write_Think_File(Think_FName, Think_FList)
        Write_Think_File(Fix_FName, Fix_FList)

##        Merge_Flist.append('\n!=================[ Watch ]==================\n!\n')
##        for n in Watch_FList: Merge_Flist.append(n)
##        Merge_Flist.append('\n!=================[ Think ]==================\n!\n')
##        for n in Think_FList: Merge_Flist.append(n)
##        Merge_Flist.append('\n!==================[ Fix ]===================\n!\n')
##        for n in Fix_FList: Merge_Flist.append(n)
##        Merge_Flist.append('!')
    else:   # means empty file
        Write_Think_File(Watch_FName, ['\n'])
        Write_Think_File(Think_FName, Think_FList)
        Write_Think_File(Fix_FName, ['\n'])

##    t_Merge_Flist = []
##    for n in Merge_Flist:
##        t_Merge_Flist.append(n.replace('<br>','\n'))
##    with open(Merge_FName, "w") as f:
##        f.write('\n'.join(t_Merge_Flist))


    if DB_Available:
        engine.dispose()

    return Config_Change


##=============================================================================================================================
## _  _  _____    __    _____  ___    ____  _____  ____      __    ___  __
##( \( )(  _  )  (  )  (  _  )/ __)  ( ___)(  _  )(  _ \    /__\  / __)(  )
## )  (  )(_)(    )(__  )(_)(( (_-.   )__)  )(_)(  )   /   /(__)\( (__  )(__
##(_)\_)(_____)  (____)(_____)\___/  (__)  (_____)(_)\_)  (__)(__)\___)(____)

#def NO_Log_For_ACL(logging_monitor_line, Config_Change, Show_run_ACL_NoLog_Lst):
def NO_Log_For_ACL(t_device, Config_Change, log_folder):
    import shelve
    import time
    import sqlalchemy as db
    from utils_v2 import File_Save_Try

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

    Show_run_ACL_NoLog_Lst = []

    FW_log_folder = log_folder + '/' + hostname___
    nologacl_htm_FName = FW_log_folder + '/' + hostname___ + '.nologacl_Fix.html'
    #nologacl_txt_FList = []
    #nologacl_txt_FName = FW_log_folder + '/' + hostname___ + '.nologacl_Fix.txt'
    #nologacl_txt_FList.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    #nologacl_txt_FList.append('!\n')
    logdisabledacl_htm_FName = FW_log_folder + '/' + hostname___ + '.logdisabledacl_Fix.html'
    #logdisabledacl_txt_FName = FW_log_folder + '/' + hostname___ + '.logdisabledacl_Fix.txt'
    Show_run_ACL_LogDis_Lst = []
    #logdisabledacl_txt_Lst = []
    #logdisabledacl_txt_Lst.append(datetime.datetime.now().strftime('\n%Y-%m-%d_%H-%M-%S\n'))
    #logdisabledacl_txt_Lst.append('!\n')

    text = ('No Log For Acl @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    #utils_v2.Text_in_Frame (text, nologacl_txt_FList)
    #nologacl_txt_FList.append('\n')

    inactiveacl_htm_FName = FW_log_folder + '/' + hostname___ + '.inactiveacl_Fix.html'
    inactiveacl_txt_FList = []
    inactiveacl_txt_FName = FW_log_folder + '/' + hostname___ + '.inactiveacl_Fix.txt'
    inactiveacl_txt_FList.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    inactiveacl_txt_FList.append('!\n')

    text = ('Inactive Acl @ %s' %hostname___)
    #utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    utils_v2.Text_in_Frame (text, inactiveacl_txt_FList)
    inactiveacl_txt_FList.append('\n')

    re9 = re.compile(r'(hitcnt=.*)')


    try:
        with open("%s/%s___Show_Running-Config.txt"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            l = f.readlines()
    except:
        print('ERROR!!! file %s/%s___Show_Running-Config.txt not found!' %(FW_log_folder,hostname___))
        exit(0)
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_if')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_if = shelve_obj['0']

    for n in range(1,len(l)):
        if re.match(r'^\s*$', l[n]):
            continue
        elif l[n].startswith('logging monitor '):
            logging_monitor_line = l[n]
        elif l[n].startswith('access-list '):
            ACL_NAME = l[n].split()[1]
            if ACL_NAME in list(Accessgroup_Dic_by_if.values()): #sto facendo i controlli solo sulle ACL applicate ad interfacce
                if ' remark ' not in l[n]:
                    if (' standard ') not in l[n]:
                        N_Lines_ACL = N_Lines_ACL +1
                        if ' inactive' not in l[n]:
                            N_Lines_ACL_active += 1
                            if (' log disable' in l[n]):
                                temp = l[n].rstrip().replace(' log disable', ' log')
                                Show_run_ACL_LogDis_Lst.append(temp)
                                N_Lines_ACL_LogDis = N_Lines_ACL_LogDis +1
                            elif (' log ' not in l[n]):
                                Show_run_ACL_NoLog_Lst.append(l[n].strip() + ' log')
                                N_Lines_ACL_NoLog = N_Lines_ACL_NoLog +1
                        else:
                            N_Lines_ACL_inactive +=1
                            #Show_run_ACL_Inactive_Lst.append('no ' + l[n].strip())
                else:
                    N_Lines_ACL_Remarks +=1


    if logging_monitor_line != '':
        Config_Change.append('! logging monitor level configured is: "%s"' %logging_monitor_line.strip())
    if logging_monitor_line != '':
        if logging_monitor_line.strip().split()[2] != 'notifications':
            Config_Change.append('Suggestion!!! Consider changing the monitor logging level to "notifications"')
    else:
        Config_Change.append('Suggestion!!! no explicit logging monitor level configured')

    #L2_Vlan_Name = row['L2_VLAN_Name'] if not row.isnull()['L2_VLAN_Name'] else ''
    percent = round(N_Lines_ACL_NoLog/N_Lines_ACL_active*100,2) if N_Lines_ACL_active else 0
##    Config_Change.append('--- %s over %s "no log" entries (%s%%)' %(N_Lines_ACL_NoLog,N_Lines_ACL_active,percent))
    percent = round(N_Lines_ACL_LogDis/N_Lines_ACL_active*100,2) if N_Lines_ACL_active else 0
##    Config_Change.append('--- %s over %s "disabled log" entries (%s%%)' %(N_Lines_ACL_LogDis,N_Lines_ACL_active,percent))
##    Config_Change.append('--- %s access-list lines ' %(N_Lines_ACL))
##    Config_Change.append('--- %s access-list active lines ' %(N_Lines_ACL_active))
##    Config_Change.append('--- %s access-list inactive lines ' %(N_Lines_ACL_inactive))
##    Config_Change.append('--- %s access-list remarks lines ' %(N_Lines_ACL_Remarks))
##    for n in Show_run_ACL_NoLog_Lst:
##        Config_Change.append('%s' %n)
##    Config_Change .append('\n!The following lines were having log disabled')
##    for n in Show_run_ACL_LogDis_Lst:
##        logdisabledacl_txt_Lst.append('%s\n' %n)

    #File_Save_Try(logdisabledacl_txt_FName,logdisabledacl_txt_Lst)

    Write_Think_File(nologacl_htm_FName, Show_run_ACL_NoLog_Lst)
    Write_Think_File(logdisabledacl_htm_FName, Show_run_ACL_LogDis_Lst)

##    with open(nologacl_txt_FName, "w") as f:
##        f.write('\n'.join(nologacl_txt_FList))
##        f.write('\n'.join(Show_run_ACL_NoLog_Lst))

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
        #print(f"{results.rowcount} row(s) updated.")
        engine.dispose()

    return Config_Change


##=============================================================================================================================
## __  __  _  _  __  __  ___  ____  ____       __    ___  __
##(  )(  )( \( )(  )(  )/ __)( ___)(  _ \     /__\  / __)(  )
## )(__)(  )  (  )(__)( \__ \ )__)  )(_) )   /(__)\( (__  )(__
##(______)(_)\_)(______)(___/(____)(____/   (__)(__)\___)(____)

def Unused_ACL(t_device, Config_Change, log_folder):
    import shelve
    import time
    import sqlalchemy as db

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
    FW_log_folder = log_folder + '/' + hostname___
    Watch_FList = [' ']
    Watch_Heading_Text = ('The Following ACLs are not applied:')
    Watch_FName = FW_log_folder + '/' + hostname___ + '-Unused_ACL-Watch.html'
    Think_FList = [' ']
    Think_FName = FW_log_folder + '/' + hostname___ + '-Unused_ACL-Think.html'
    Fix_FList   = [' ']
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-Unused_ACL-Fix.html'
##    Merge_Flist = []
##    Merge_FName = FW_log_folder + '/' + hostname___ + '-Unused_ACL-Merge.txt'
##    Merge_Flist.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
##    Merge_Flist.append('!')

##    text = ('Unused Acl @ %s' %hostname___)
##    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
##    utils_v2.Text_in_Frame (text, Merge_Flist)

    # find unused acl for service-policy
    Used_ACL_ServPol = []
    ServicePolicy_Lst = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ServicePolicy_Lst')
    ServicePolicy_Lst = utils_v2.Shelve_Read_Try(tf_name,ServicePolicy_Lst)
    #with shelve.open(tf_name) as shelve_obj: ServicePolicy_Lst = shelve_obj['0']

    PolicyMap_Dct = {}
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'PolicyMap_Dct')
    PolicyMap_Dct = utils_v2.Shelve_Read_Try(tf_name,PolicyMap_Dct)
    #with shelve.open(tf_name) as shelve_obj: PolicyMap_Dct = shelve_obj['0']

    ClassMap_Dct = {}
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ClassMap_Dct')
    ClassMap_Dct = utils_v2.Shelve_Read_Try(tf_name,ClassMap_Dct)
    #with shelve.open(tf_name) as shelve_obj: ClassMap_Dct = shelve_obj['0']

    for n in ServicePolicy_Lst:
        t_cm = PolicyMap_Dct[n]
        for m in t_cm:
            try:
                Used_ACL_ServPol.append(ClassMap_Dct[m])
            except:
                print('WARNING... class %s in policy-map %s not used' %(m,n))

    Unused_ACL_List = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']

    with open("%s/%s___Show_Capture.txt"%(FW_log_folder,hostname___),"r") as f:
        l = f.readlines()
    ACL_Capture_List = []
    for n in range(0,len(l)):
        if 'access-list' in l[n]:
            ACL_Capture_List.append(l[n].split('access-list')[1].split()[0])

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Global_ACL_Dic')
    with shelve.open(tf_name) as shelve_obj: Global_ACL_Dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List')
    with shelve.open(tf_name) as shelve_obj: ACL_List = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_SplitTunnel_List')
    with shelve.open(tf_name) as shelve_obj: ACL_SplitTunnel_List = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Crypto_MAP_ACL_List')
    with shelve.open(tf_name) as shelve_obj: Crypto_MAP_ACL_List = shelve_obj['0']

    for n in ACL_List:
        #if n not in Accessgroup_Dic_by_if.values():
        if n not in Accessgroup_Dic_by_ACL.keys():
            if n not in ACL_Capture_List:
                if n not in Used_ACL_ServPol:
                    if n not in ACL_SplitTunnel_List:
                        if n not in Global_ACL_Dic.values():
                            if n not in Crypto_MAP_ACL_List:
                                #print('Notify...  access-list "%s" is not applied to any interface or capture' %n) if (DEBUG_LEVEL == 1) else ''
##                                Config_Change.append('Notify...  access-list "%s" is not applied' %n)
                                Watch_FList.append('%s' %n)
                                Unused_ACL_List.append(n)
##    Config_Change.append('!')
    try:
        percent = round(len(Unused_ACL_List)/len(ACL_List)*100,2) if len(ACL_List) else 0
    except:
        print('ERROR! Divide by zero @ %s, %s' %(hostname___, ACL_List))
        exit(123456)
##    Config_Change.append('--- %s ACL over %s are not used (%s%%)\n'%(len(Unused_ACL_List), len(ACL_List), percent))

    if DB_Available:
        Updated_Vals = dict(
                            Unused_ACL=len(Unused_ACL_List),
                            Declared_ACL=len(ACL_List),
                            Percent_Unused_ACL=percent
                            )
        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(**Updated_Vals)
        with engine.begin() as connection:
            results = connection.execute(query)
        #print(f"{results.rowcount} row(s) updated.")
        engine.dispose()

    for n in Unused_ACL_List:
##        Config_Change.append('show run | i %s ' %n)
        Think_FList.append('show run | i %s ' %n)

##    Config_Change.append('!')
    if (len(Unused_ACL_List) > 0):
##        Config_Change.append('! conf t')
        for n in Unused_ACL_List:
##            Config_Change.append('clear configure access-list %s' %n)
            Fix_FList.append('clear configure access-list %s' %n)

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Unused_ACL_List')
    with shelve.open(tf_name, "c") as shelve_obj: shelve_obj['0'] = Unused_ACL_List

    FirstRun = True
##    Config_Change.append('!')
    for n in ClassMap_Dct.values():
        if n not in Used_ACL_ServPol:
            for t_key, t_value in ClassMap_Dct.items():
                if t_value == n:
                    if FirstRun == True:
                        Watch_FList.append('!')
                    #print('Notify... class-map "%s" not used' %t_value) if (DEBUG_LEVEL == 0) else ''
##                    Config_Change.append('Notify... class-map "%s" not used' %t_key)
                    Watch_FList.append('class-map "%s" not used' %t_key)
##                    Config_Change.append('show run | i %s ' %t_key)
                    Think_FList.append('show run | i %s ' %t_key)
##                    Config_Change.append('no class-map %s' %t_key)
                    Fix_FList.append('no class-map %s' %t_key)
                    FirstRun = False

    FirstRun = True
    for n in PolicyMap_Dct.keys():
        if n not in ServicePolicy_Lst:
            if FirstRun == True:
                Watch_FList.append('!')
            #print('Notify... policy-map "%s" not used' %n) if (DEBUG_LEVEL == 0) else ''
##            Config_Change.append('Notify... policy-map "%s" not used' %n)
            Watch_FList.append('policy-map "%s" not used' %n)
##            Config_Change.append('show run | i %s ' %n)
            Think_FList.append('show run | i %s ' %n)
##            Config_Change.append('no policy-map %s' %n)
            Fix_FList.append('no policy-map %s' %n)
            FirstRun = False

# aggiungere timestamp


    retries = 0
    if len(Watch_FList) >= 1:
        while retries < 3:
            try:
                with open(Watch_FName, "w+") as f:
                    f.write('<p class="text-secondary" >\n')
                    f.write('%s<br>\n' %Watch_Heading_Text)
                    f.write('<ul>\n')
                    for item in Watch_FList:
                        f.write('<li>%s</li>\n' %item)
                        #f.write('<li>\n' + '<li>\n '.join(Watch_FList))
                    f.write('</ul>\n')
                    f.write('</p>\n')
                    print('... saved file "%s"' %Watch_FName)
                    break
            except:
                retries +=1
                time.sleep(retries*2)
        if retries == 3:
            print('ERROR!!! Cannot write to file %s' %Watch_FName)

    Write_Think_File(Think_FName, Think_FList)
    Write_Think_File(Fix_FName, Fix_FList)

##    Merge_Flist.append('\n!=================[ Watch ]==================\n!\n')
##    for n in Watch_FList: Merge_Flist.append(n)
##    Merge_Flist.append('\n!=================[ Think ]==================\n!\n')
##    for n in Think_FList: Merge_Flist.append(n)
##    Merge_Flist.append('\n!==================[ Fix ]===================\n!\n')
##    for n in Fix_FList: Merge_Flist.append(n)
##    Merge_Flist.append('!')
##    with open(Merge_FName, "w") as f:
##        f.write('\n'.join(Merge_Flist))

    return Config_Change

##=============================================================================================================================
## __  __  _  _  __  __  ___  ____  ____     _____  ____   ____  ____  ___  ____
##(  )(  )( \( )(  )(  )/ __)( ___)(  _ \   (  _  )(  _ \ (_  _)( ___)/ __)(_  _)
## )(__)(  )  (  )(__)( \__ \ )__)  )(_) )   )(_)(  ) _ <.-_)(   )__)( (__   )(
##(______)(_)\_)(______)(___/(____)(____/   (_____)(____/\____) (____)\___) (__)

def Unused_Object(t_device, Config_Change, log_folder):
    import shelve
    import time
    import sqlalchemy as db
    from utils_v2 import File_Save_Try

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

    text = ('Unused Object @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    Used_Object_List = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Used_Object_List')
    Used_Object_List = utils_v2.Shelve_Read_Try(tf_name,Used_Object_List)

    Declared_OBJ_NET = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Declared_OBJ_NET')
    Declared_OBJ_NET = utils_v2.Shelve_Read_Try(tf_name,Declared_OBJ_NET)

    Declared_OBJ_GRP_NET = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Declared_OBJ_GRP_NET')
    Declared_OBJ_GRP_NET = utils_v2.Shelve_Read_Try(tf_name,Declared_OBJ_GRP_NET)

    Declared_Object_service = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Declared_Object_service')
    Declared_Object_service = utils_v2.Shelve_Read_Try(tf_name,Declared_Object_service)

    OBJ_GRP_SVC_Dic = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_SVC_Dic')
    OBJ_GRP_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,OBJ_GRP_SVC_Dic)

    OBJ_GRP_PRT_Dic = []
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_PRT_Dic')
    OBJ_GRP_PRT_Dic = utils_v2.Shelve_Read_Try(tf_name,OBJ_GRP_PRT_Dic)

    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic.keys():
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
    percent = round(Count_Obj_Not_Applied/len(Declared_OBJ_NET)*100,2) if len(Declared_OBJ_NET) else 0
##    Config_Change.append('\n--- %s over %s "object network" not applied (%s%%)' %(Count_Obj_Not_Applied,len(Declared_OBJ_NET),percent))
##    for n in Unused_Obj_Net:
##        Config_Change.append('%s' %n)


    Unused_ObjGrp_Net = []
    Count_ObjGrp_Not_Applied = 0
    for n in Declared_OBJ_GRP_NET:
        if n not in Used_Object_List:
            Count_ObjGrp_Not_Applied += 1
            Unused_ObjGrp_Net.append(n)
    percent = round(Count_ObjGrp_Not_Applied/len(Declared_OBJ_GRP_NET)*100,2) if len(Declared_OBJ_GRP_NET) else 0
##    Config_Change.append('\n--- %s over %s "object-group  network" not applied (%s%%)' %(Count_ObjGrp_Not_Applied,len(Declared_OBJ_GRP_NET),percent))
##    for n in Unused_ObjGrp_Net:
##        Config_Change.append('%s' %n)

    Unused_Obj_Service = []
    Count_ObjSrv_Not_Applied = 0
    for n in Declared_Object_service:
        if n not in Used_Object_List:
            Count_ObjSrv_Not_Applied += 1
            Unused_Obj_Service.append(n)
    percent = round(Count_ObjSrv_Not_Applied/len(Declared_Object_service)*100,2) if len(Declared_Object_service) else 0
##    Config_Change.append('\n--- %s over %s "object service" not applied (%s%%)' %(Count_ObjSrv_Not_Applied,len(Declared_Object_service),percent))
##    for n in Unused_Obj_Service:
##        Config_Change.append('%s' %n)

    Unused_ObjGrp_Service = []
    Count_ObjGrpSrv_Not_Applied = 0
    # find in services
    for n in OBJ_GRP_SVC_Dic_2.keys():
        if n not in Used_Object_List:
            Count_ObjGrpSrv_Not_Applied += 1
            Unused_ObjGrp_Service.append(n)
    # find in protocols
    for n in OBJ_GRP_PRT_Dic.keys():
        if n not in Used_Object_List:
            Count_ObjGrpSrv_Not_Applied += 1
            Unused_ObjGrp_Service.append(n)
    LEN_OBJ_SVC = len(OBJ_GRP_SVC_Dic_2.keys()) + len(OBJ_GRP_PRT_Dic.keys())
    percent = round(Count_ObjGrpSrv_Not_Applied/LEN_OBJ_SVC*100,2) if LEN_OBJ_SVC else 0
##    Config_Change.append('\n--- %s over %s "object-group service" not applied (%s%%)' %(Count_ObjGrpSrv_Not_Applied,LEN_OBJ_SVC,percent))
##    for n in Unused_ObjGrp_Service:
##        Config_Change.append('%s' %n)

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
            if item in OBJ_GRP_SVC_Dic_2.keys():
                Fix_FList.append('no object-group service %s' %item)
            elif item in OBJ_GRP_PRT_Dic.keys():
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

    import shelve
    hostname___ = t_device.replace('/','___')

    text = ('object-group network with one entry @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    FW_log_folder = log_folder + '/' + hostname___
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_NET_Dic')
    with shelve.open(tf_name) as shelve_obj: OBJ_GRP_NET_Dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obj_Net_Dic')
    with shelve.open(tf_name) as shelve_obj: Obj_Net_Dic = shelve_obj['0']
    Declared_OBJ_GRP_NET_Dic = len(OBJ_GRP_NET_Dic)

    OBJ_GRP_NET_ONE = []
    Old_to_New = {}
    TEMP_Config_Change = []

    for t_key in OBJ_GRP_NET_Dic.keys():
        if len(OBJ_GRP_NET_Dic[t_key]) == 1:
    ##        OBJ_GRP_NET_ONE.append(t_key)
            TEMP_Config_Change.append('\n!object-group network %s' %(t_key))
            TEMP_Config_Change.append('!%s' %(OBJ_GRP_NET_Dic[t_key][0]))

            this_item = OBJ_GRP_NET_Dic[t_key][0]

            if ' host ' in this_item:
                OBJ_GRP_NET_ONE.append(t_key)
                Old_Name = t_key
                New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('H_')) else ('H_%s' %t_key.replace('-','_').upper())
    ##            if t_key.replace('-','_').upper().startswith('H_'):
    ##                New_Name = '%s' %t_key.replace('-','_').upper()
    ##            else:
    ##                 New_Name = 'H_%s' %t_key.replace('-','_').upper()
                Old_to_New[Old_Name] = New_Name
                TEMP_Config_Change.append('object network %s' %New_Name)
                TEMP_Config_Change.append(' %s' %(OBJ_GRP_NET_Dic[t_key][0].replace('network-object','')))
            elif 'network-object object' in this_item:
                OBJ_GRP_NET_ONE.append(t_key)
                Old_Name = t_key
                if 'host ' in Obj_Net_Dic[this_item.split()[2]]:
                    New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('H_')) else ('H_%s' %t_key.replace('-','_').upper())
    ##                New_Name = 'H_%s' %t_key.replace('-','_').upper()
                elif 'subnet ' in Obj_Net_Dic[this_item.split()[2]]:
                    New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('N_')) else ('N_%s' %t_key.replace('-','_').upper())
    ##                New_Name = 'N_%s' %t_key.replace('-','_').upper()
                elif 'range ' in Obj_Net_Dic[this_item.split()[2]]:
                    New_Name = ('%s' %t_key.replace('-','_').upper()) if (t_key.replace('-','_').upper().startswith('R_')) else ('R_%s' %t_key.replace('-','_').upper())
    ##                New_Name = 'R_%s' %t_key.replace('-','_').upper()
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
    ##            if t_key.replace('-','_').upper().startswith('N_'):
    ##                New_Name = '%s' %t_key.replace('-','_').upper()
    ##            else:
    ##                New_Name = 'N_%s' %t_key.replace('-','_').upper()
                Old_to_New[Old_Name] = New_Name
                TEMP_Config_Change.append('object network %s' %New_Name)
                TEMP_Config_Change.append('%s' %(this_item.replace('network-object','subnet')))
            #print('object-group network %s' %(t_key))

    Declared_OBJ_GRP_NET_ONE = len(OBJ_GRP_NET_ONE)
    TEMP_Config_Change.append('')
    for t_key in OBJ_GRP_NET_Dic:
        for t_item in OBJ_GRP_NET_Dic[t_key]:
            for tt_key in Old_to_New.keys():
                if 'group-object ' in t_item:
                    if tt_key == t_item.split()[1]:
                        TEMP_Config_Change.append('object-group network %s' %t_key)
                        TEMP_Config_Change.append(' network-object object %s' %Old_to_New[tt_key])
                        TEMP_Config_Change.append(' no group-object %s\n' %tt_key)
    ##            elif ' network-object ' in t_item:
    ##                if tt_key == t_item.split()[1]:
    ##                TEMP_Config_Change.append('object-group network %s' %t_key)
    ##                TEMP_Config_Change.append('object %s' %Old_to_New[tt_key])
    ##                TEMP_Config_Change.append('no group-object %s' %tt_key)

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines')
    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines = shelve_obj['0']

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
    #TEMP2_Config_Change.append('Declared object-group network   = %s' %Declared_OBJ_GRP_NET_Dic)
    #TEMP2_Config_Change.append('Declared object-group network 1 = %s' %Declared_OBJ_GRP_NET_ONE)
    percent = round(Declared_OBJ_GRP_NET_ONE/Declared_OBJ_GRP_NET_Dic*100,2) if Declared_OBJ_GRP_NET_Dic else 0
    TEMP2_Config_Change.append('--- %s over %s "object-group network" entries (%s%%)' %(Declared_OBJ_GRP_NET_ONE,Declared_OBJ_GRP_NET_Dic,percent))

    for n in TEMP_Config_Change:
        TEMP2_Config_Change.append(n)
    #for n in TEMP2_Config_Change:
    #    Config_Change.append(n)

    Fix_FName   = FW_log_folder + '/' + hostname___ + '-ObjGrpNet_1Entry-Watch.html'
    Write_Think_File(Fix_FName, TEMP2_Config_Change)

    return Config_Change


##=============================================================================================================================
## ____  __  __  ____  __    ____  ___    __   ____  ____  ____     _____  ____   ____  ____  ___  ____  ___
##(  _ \(  )(  )(  _ \(  )  (_  _)/ __)  /__\ (_  _)( ___)(  _ \   (  _  )(  _ \ (_  _)( ___)/ __)(_  _)/ __)
## )(_) ))(__)(  )___/ )(__  _)(_( (__  /(__)\  )(   )__)  )(_) )   )(_)(  ) _ <.-_)(   )__)( (__   )(  \__ \
##(____/(______)(__)  (____)(____)\___)(__)(__)(__) (____)(____/   (_____)(____/\____) (____)\___) (__) (___/

def Duplicated_Objects(t_device, Config_Change, log_folder):

    import shelve
    import time
    import sqlalchemy as db

    hostname___ = t_device.replace('/','___')
    FW_log_folder  = log_folder + '/' + hostname___
    html_folder = FW_log_folder
    hostname = t_device

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

    text = ('Duplicated Objects @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Undeclared_NetObj_List')
    with shelve.open(tf_name) as shelve_obj: Undeclared_NetObj_List = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_NET_Dic')
    with shelve.open(tf_name) as shelve_obj: OBJ_GRP_NET_Dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obejct_by_value_Dict')
    with shelve.open(tf_name) as shelve_obj: Obejct_by_value_Dict = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Declared_OBJ_NET')
    with shelve.open(tf_name) as shelve_obj: Declared_OBJ_NET = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obj_Net_Dic')
    with shelve.open(tf_name) as shelve_obj: Obj_Net_Dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_SVC_Dic')
    with shelve.open(tf_name) as shelve_obj: OBJ_GRP_SVC_Dic = shelve_obj['0']


##    (=================================================)
##    (==      Search_For_Duplicated_Obj_Network      ==)
##    (=================================================)
    Dup_OBJ_NET_List = []
    N_of_Duplicated_OBJ_NET = 0
    N_of_unique_Duplicated_OBJ_NET = 0
    for t_key in Obejct_by_value_Dict.keys():
        if len(Obejct_by_value_Dict[t_key]) > 1:
            N_of_Duplicated_OBJ_NET += 1
            N_of_unique_Duplicated_OBJ_NET += len(Obejct_by_value_Dict[t_key])
            Dup_OBJ_NET_List.append([t_key, Obejct_by_value_Dict[t_key]])

    Prcnt_N_of_unique_Dup_OBJ_NET = round(100*N_of_unique_Duplicated_OBJ_NET/len(Declared_OBJ_NET),1) if (len(Declared_OBJ_NET)!=0) else 0
##    Watch_Heading_Text = ('%s Network Objects over %s (%s%%) are duplicated:' %(N_of_unique_Duplicated_OBJ_NET, len(Declared_OBJ_NET), Prcnt_N_of_unique_Dup_OBJ_NET))

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

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-ObjNet_Duplicated-Watch.html'
    try:
        with open(Watch_FName,mode="w") as html_file:
            #html_file.writelines(line for line in Watch_Flist)
            html_file.writelines(Watch_Flist)
        print('... saved file "%s" '%(Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName))

##    (=================================================)
##    (==    Search_For_Duplicated_Obj-Grp_Network    ==)
##    (=================================================)
    # apri OBJ_GRP_NET_Dic ed esplode ricorsivamente tutte le entry per ottenere solo ip
    # controlla se ci sono duplicati

    OBJ_GRP_NET_Dic_explode = {}
    for t_key in OBJ_GRP_NET_Dic.keys():
        t_vals = []
        for t_item in OBJ_GRP_NET_Dic[t_key]:
            if 'network-object host ' in t_item:
                t_vals.append(t_item.split()[-1])
            elif 'network-object object ' in t_item:
                temp = Obj_Net_Dic[t_item.split()[-1]]
                temp = temp.replace('host ','')
                temp = temp.replace('range ','')
                temp = temp.replace('subnet ','')
                temp = temp.replace('fqdn ','')
                t_vals.append(temp)
            elif 'group-object ' in t_item:
                tt_key = t_item.split()[-1]
                for tt_item in OBJ_GRP_NET_Dic[tt_key]:
                    if 'network-object host ' in tt_item:
                        t_vals.append(tt_item.split()[-1])
                    elif 'network-object object ' in tt_item:
                        temp = Obj_Net_Dic[tt_item.split()[-1]]
                        temp = temp.replace('host ','')
                        temp = temp.replace('range ','')
                        temp = temp.replace('subnet ','')
                        temp = temp.replace('fqdn ','')
                        t_vals.append(temp)
                    elif 'group-object ' in tt_item:
                        ttt_key = tt_item.split()[-1]
                        for ttt_item in OBJ_GRP_NET_Dic[ttt_key]:
                            if 'network-object host ' in ttt_item:
                                t_vals.append(ttt_item.split()[-1])
                            elif 'network-object object ' in ttt_item:
                                temp = Obj_Net_Dic[ttt_item.split()[-1]]
                                temp = temp.replace('host ','')
                                temp = temp.replace('range ','')
                                temp = temp.replace('subnet ','')
                                temp = temp.replace('fqdn ','')
                                t_vals.append(temp)
                            elif 'group-object ' in ttt_item:
                                ttt_key = ttt_item.split()[-1]
                            else:
                                # network-object 10.10.100.0 255.255.254.0
                                t_vals.append(ttt_item.replace('network-object ',''))
                    else:
                        # network-object 10.10.100.0 255.255.254.0
                        t_vals.append(tt_item.replace('network-object ',''))

            else:
                # network-object 10.10.100.0 255.255.254.0
                t_vals.append(t_item.replace('network-object ',''))
        OBJ_GRP_NET_Dic_explode[t_key] = t_vals

    Dup_OBJGRP_NET_List = []
    Found_keys = []
    t_key_List = list(OBJ_GRP_NET_Dic_explode.keys())
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

##    for n in range(0,len(Dup_OBJGRP_NET_List)):
##        t_group = Dup_OBJGRP_NET_List[n]
##        print('\n\n--- object group composed by: ---')
##        for t_obj in OBJ_GRP_NET_Dic_explode[t_group[0]]:
##            print(t_obj)
##        for m in range (0,len(t_group)):
##            t_key = t_group[m]
##            Out = []
##            t_Out = Where_Used(t_device, t_key, FW_log_folder, Out)
##            if t_Out:
##                print('OBJ GRP %s' %t_key)
##                for line in t_Out:
##                    print(line)

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
    Watch_Flist.append('</div>\n')

    Watch_FName   = FW_log_folder + '/' + hostname___ + '-ObjGrpNet_Duplicated-Watch.html'
    try:
        with open(Watch_FName,mode="w") as html_file:
            #html_file.writelines(line for line in Watch_Flist)
            html_file.writelines(Watch_Flist)
        print('... saved file "%s" '%(Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName))


##    (=================================================)
##    (==     Search_For_Duplicated_Obj_Service_      ==)
##    (=================================================)
    N_of_Duplicated_OBJ_SVC = 0
    Duplicated_OBJ_SVC = {}
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_SVC_Dic')
    with shelve.open(tf_name) as shelve_obj: OBJ_SVC_Dic = shelve_obj['0']
    for m in range(0,len(OBJ_SVC_Dic.keys())):
        tm_key = list(OBJ_SVC_Dic.keys())[m]
        tm_item = OBJ_SVC_Dic[tm_key]
        for mm in range(m+1,len(OBJ_SVC_Dic.keys())):
            tmm_key = list(OBJ_SVC_Dic.keys())[mm]
            tmm_item = OBJ_SVC_Dic[tmm_key]
            if tmm_item == tm_item:
                Duplicated_OBJ_SVC[tm_item] = [tm_key]
                if tmm_key not in Duplicated_OBJ_SVC[tm_item]:
                    Duplicated_OBJ_SVC[tm_item].append(tmm_key)
    if len(Duplicated_OBJ_SVC)>0:
        for t_key in Duplicated_OBJ_SVC.keys():
            temp = '|'.join(Duplicated_OBJ_SVC[t_key])
##            Config_Change.append('- object service "%s" declared in "%s"' %(t_key,temp))
    N_of_Duplicated_OBJ_SVC = sum(len(sublist) for sublist in list(Duplicated_OBJ_SVC.values()))
    Prcnt_N_of_Duplicated_OBJ_SVC = round(100*N_of_Duplicated_OBJ_SVC/len(OBJ_SVC_Dic.keys()),1) if (len(OBJ_SVC_Dic.keys())!=0) else 0

    Watch_Flist = []
    Watch_Flist.append('<div class="card-body">\n')
    Watch_Flist.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_Flist.append('       <thead><tr>\n')
    Watch_Flist.append('           <th class="px-2">Service</th>\n')
    Watch_Flist.append('           <th class="px-2">Service Name</th>\n')
    Watch_Flist.append('       </tr></thead>\n')
    Watch_Flist.append('       <tbody>\n')
    for t_key in Duplicated_OBJ_SVC.keys():
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
    try:
        with open(Watch_FName,mode="w") as html_file:
            #html_file.writelines(line for line in Watch_Flist)
            html_file.writelines(Watch_Flist)
        print('... saved file "%s" '%(Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName))

    Think_Flist = []
    Think_Flist.append('<div class="card-body">\n')
    Think_Flist.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Think_Flist.append('       <thead><tr>\n')
    Think_Flist.append('           <th>Object Service</th>\n')
    Think_Flist.append('       </tr></thead>\n')
    Think_Flist.append('       <tbody>\n')
    for t_key in Duplicated_OBJ_SVC.keys():
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
##                        t_Config_Change.append(remove_tags.sub('', line.strip())+'\n')

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
            Think_Flist[i] = ('%s\n' %t_line)
        elif t_line.split()[0] == '<_L1_TEXT_>':
            Think_Flist[i] = ('%s\n' %' '.join(t_line.split()[1:]))
        elif t_line.split()[0] == '<_L2_TEXT_>':
            Think_Flist[i] = ('%s\n' %' '.join(t_line.split()[1:]))

    Think_FName   = FW_log_folder + '/' + hostname___ + '-ObjSvc_Duplicated-Think.html'
    try:
        with open(Think_FName,mode="w") as html_file:
            #html_file.writelines(line for line in Think_Flist)
            html_file.writelines(Think_Flist)
        print('... saved file "%s" '%(Think_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Think_FName))


##    (=================================================)
##    (==    Search_For_Duplicated_Obj-Grp_Service    ==)
##    (=================================================)
    # apri OBJ_GRP_SVC_Dic ed esplode ricorsivamente tutte le entry per ottenere solo ip
    # controlla se ci sono duplicati

##FW-M-PE-01/act/pri(config)# object-group service ttt
##  description     Specify description text
##  group-object    Configure an object group as an object
##  help            Help for service object-group configuration commands
##  no              Remove an object or description from object-group
##  service-object  Configure a service object
##
##FW-M-PE-01/act/pri(config)# object-group service tttt tcp
##  description   Specify description text
##  group-object  Configure an object group as an object
##  help          Help for service object-group configuration commands
##  no            Remove an object or description from object-group
##  port-object   Configure a port object

    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic.keys():
        if len(t_OBJ_GRP_SVC_Dic_key.split()) == 2:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)

    OBJ_GRP_SVC_Dic_explode = {}
    for t_key in OBJ_GRP_SVC_Dic_2.keys():
        t_vals = []
        for t_item in OBJ_GRP_SVC_Dic_2[t_key]:
            if 'port-object ' in t_item:
                t_vals.append(t_item.strip().replace('port-object ',''))
            elif 'service-object ' in t_item:
                t_vals.append(t_item.strip().replace('service-object ',''))
            elif 'group-object ' in t_item:
                tt_key = t_item.strip().replace('group-object ','')
                for tt_item in OBJ_GRP_SVC_Dic_2[tt_key]:
                    if 'port-object ' in tt_item:
                        t_vals.append(tt_item.strip().replace('port-object ',''))
                    elif 'service-object ' in tt_item:
                        t_vals.append(tt_item.strip().replace('service-object ',''))
                    elif 'group-object ' in tt_item:
                        ttt_key = tt_item.strip().replace('group-object ','')
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
                        print('... there is some problem here')

            else:
                print('... there is some problem here')
        OBJ_GRP_SVC_Dic_explode[t_key] = t_vals

    Dup_OBJGRP_SVC_List = []
    Found_keys = []
    t_key_List = list(OBJ_GRP_SVC_Dic_explode.keys())
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

##    for n in range(0,len(Dup_OBJGRP_SVC_List)):
##        t_group = Dup_OBJGRP_SVC_List[n]
##        print('\n\n--- object group composed by: ---')
##        for t_obj in OBJ_GRP_NET_Dic_explode[t_group[0]]:
##            print(t_obj)
##        for m in range (0,len(t_group)):
##            t_key = t_group[m]
##            Out = []
##            t_Out = Where_Used(t_device, t_key, FW_log_folder, Out)
##            if t_Out:
##                print('OBJ GRP %s' %t_key)
##                for line in t_Out:
##                    print(line)

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
    try:
        with open(Watch_FName,mode="w") as html_file:
            #html_file.writelines(line for line in Watch_Flist)
            html_file.writelines(Watch_Flist)
        print('... saved file "%s" '%(Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Watch_FName))







    netobjusedList = []
    Undeclared_NetObj_Used_List = []
    for n in Undeclared_NetObj_List:
##        if n not in Obejct_by_value_Dict.keys():
##            print ('Notify...  object %s declared as "network-object"' %n) if (DEBUG_LEVEL == 0) else ''
        if n in Obejct_by_value_Dict.keys():
##            print('Notify...  object %s declared as "network-object" but "object network" %s exists' %(n,Obejct_by_value_Dict[n]))
            #Config_Change.append('Notify...  object %s declared as network-object but object network %s exists' %(n,Obejct_by_value_Dict[n]))
            netobjusedList.append('object <b>%s</b> declared as network-object but object network %s exists' %(n,Obejct_by_value_Dict[n]))
            Undeclared_NetObj_Used_List.append(n)


    #Config_Change.append('\n\nNumber of undeclared "network-object" = %s' %len(Undeclared_NetObj_List))
    #Config_Change.append('Number of equivalent "object network" = %s' %len(Undeclared_NetObj_Used_List))
    netobjusedList.append('\n\nNumber of undeclared "network-object" = %s' %len(Undeclared_NetObj_List))
    netobjusedList.append('Number of equivalent "object network" = %s' %len(Undeclared_NetObj_Used_List))
    Fix_FName   = FW_log_folder + '/' + hostname___ + '-netobjused-Watch.html'
    Write_Think_File(Fix_FName, netobjusedList)

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Undeclared_NetObj_Used_List')
    with shelve.open(tf_name, "c") as shelve_obj: shelve_obj['0'] = Undeclared_NetObj_Used_List

    #Config_Change.append('')
    for t_key in OBJ_GRP_NET_Dic.keys():
        Printed_Header = False
        for t_item in OBJ_GRP_NET_Dic[t_key]:
            if t_item.startswith(' network-object host '):
                temp = t_item.split()[2]
                if temp in Obejct_by_value_Dict.keys():
                    if Printed_Header == False:
                        Config_Change.append('!\nobject-group network %s' %t_key)
                        Printed_Header = True
                    Config_Change.append(' network-object object %s' %Obejct_by_value_Dict[temp][0])
                    Config_Change.append(' no network-object host %s' %temp)
            elif t_item.startswith(' network-object '):
                if len(t_item.replace(' ','.').split('.')) == 10:
                    temp = t_item.split()[1] + ' ' + t_item.split()[2]
                    if temp in Obejct_by_value_Dict.keys():
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
        #print(f"{results.rowcount} row(s) updated.")
        engine.dispose()

    return Config_Change

##=============================================================================================================================
##   __    ___  __      ___  _____  __  __  ____   ___  ____    _  _  ___    ____  _____  __  __  ____  ____  _  _  ___    ____   __    ____  __    ____
##  /__\  / __)(  )    / __)(  _  )(  )(  )(  _ \ / __)( ___)  ( \/ )/ __)  (  _ \(  _  )(  )(  )(_  _)(_  _)( \( )/ __)  (_  _) /__\  (  _ \(  )  ( ___)
## /(__)\( (__  )(__   \__ \ )(_)(  )(__)(  )   /( (__  )__)    \  / \__ \   )   / )(_)(  )(__)(   )(   _)(_  )  (( (_-.    )(  /(__)\  ) _ < )(__  )__)
##(__)(__)\___)(____)  (___/(_____)(______)(_)\_) \___)(____)    \/  (___/  (_)\_)(_____)(______) (__) (____)(_)\_)\___/   (__)(__)(__)(____/(____)(____)

def ACL_Source_Vs_Routing_Table(t_device, Config_Change, log_folder):

    from Network_Calc import Sub_Mask_2
    from tabulate import tabulate
    import shelve
    import ipaddress
    import pandas as pd
    import sqlalchemy as db

    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    FW_log_folder = log_folder + '/' + hostname___
    html_folder = FW_log_folder

    FW_log_folder = log_folder + '/' + hostname___
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

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ROUTE_DF')
    with shelve.open(tf_name) as shelve_obj: ROUTE_DF = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Name_dic')
    with shelve.open(tf_name) as shelve_obj: Name_dic = shelve_obj['0']

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_NET_Dic')
    with shelve.open(tf_name) as shelve_obj: OBJ_GRP_NET_Dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obj_Net_Dic')
    with shelve.open(tf_name) as shelve_obj: Obj_Net_Dic = shelve_obj['0']

    Printed_Lines = []
    NoActive_NoRoute_Root_ACL = []
    SiActive_NoRoute_Root_ACL = []
    NoActive_NoRoute_Child_ACL = []
    SiActive_NoRoute_Child_ACL = []
    NoActive_Noroute_Hash_ACL_Dic = {}
    SiActive_Noroute_Hash_ACL_Dic = {}

    Double_NO_Active_Hash = []
    Double_SI_Active_Hash = []
    Totally_Wrong_Routing_Active_ACL = []
    Partlly_Wrong_Routing_Active_ACL = []
    Partlly_Wrong_Routing_Active_ACL_Dic = {}
    Totally_Wrong_Routing_Active_ACL_Counting = []

    text = ('Check Acl Source Vs Routing Table @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    Config_Change.append('Check if URPF (Unicast Reverse Path Forwarding) is enabled\n')

    ROUTE_IP_DF = ROUTE_DF.copy()
    for row in ROUTE_IP_DF.itertuples():
        try:
            ROUTE_IP_DF.at[row.Index, 'Network'] = ipaddress.IPv4Network(row.Network)
        except:
            Config_Change.append('ERROR 1106 while converting %s to ipaddress\n' %row.Network)
            print('ERROR 1106 while converting %s to ipaddress\n' %row.Network)
            ROUTE_IP_DF = ROUTE_IP_DF.drop(row.Index)
            row = { 'TimeStamp' : datetime.datetime.now().astimezone(),
                    'Level'     : 'WARNING',
                    'Message'   : (f'Error While Converting "{row.Network}" to ipaddress in {t_device}')}
            with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
            continue

    ACL_WiderThanRouting = {}
    BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List_Dict.keys())
    for t_key in list(ACL_List_Dict.keys()):
        t_Root__Hash = t_key.split()[-1]
        t_Child_Hash = []

        LOOP_INDEX = LOOP_INDEX + 1
        if LOOP_INDEX > (ITEMS/STEPS)*BINS:
            print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1

        t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_key])
        t_ACL_Name = t_ACL_Lines_DF.Name[0]
        t_If_Name = ''
        try:
            t_If_Name = Accessgroup_Dic_by_ACL[t_ACL_Name]
        except:
            continue

        for row in t_ACL_Lines_DF.itertuples():
            temp1 = [row.ACL, row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, row.Hitcnt, row.Hash]
            #print('DBG:' + ' '.join(row)) if (DBG == 1) else ''
            this_Src_Obj = utils_v2.ASA_ACL_Obj_to_Net(row.Source)
            if this_Src_Obj == []: #da gestire ipv6
                continue
            for t_this_Src_Obj in this_Src_Obj:
                temp = t_this_Src_Obj.split()
                try:
                    t_this_Src_Obj = temp[0] + Sub_Mask_2[temp[1]]
                except:
                    text_line = ('>>>   ERROR... non conventional subnet mask for "%s"' %t_this_Src_Obj)
                    if text_line not in Printed_Lines:
                        #print(text_line)
                        Config_Change.append(text_line)
                        Printed_Lines.append(text_line)
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

                Bool_check = ('Interface == "%s"') %(t_If_Name)
                #Wider_Object_Found = False
                BEST_ROUTE = ''
                WIDE_ROUTE_List = []
                for this_route in ROUTE_IP_DF.query(Bool_check)['Network'].to_list():
                #for this_route in Routing_Table:
                    try:
                        if this_Src_Obj_IP.subnet_of(this_route):
                            if BEST_ROUTE == '':
                                BEST_ROUTE = this_route
                            elif this_route.subnet_of(BEST_ROUTE): # swap routes
                                BEST_ROUTE = this_route
                    except:
                        Config_Change.append('ERROR... this_route not in the right format %s' %this_route)
                        continue

                if BEST_ROUTE == '': #no best route found
                    if t_this_Src_Obj != '0.0.0.0/0':
                        for this_route in ROUTE_IP_DF.query(Bool_check)['Network'].to_list():
                            try:
                                if this_route.subnet_of(this_Src_Obj_IP):
                                    WIDE_ROUTE_List.append(str(this_route))
                            except:
                                print('Error at line 1702:')
                                print('this_route = %s' %this_route)
                                print('this_Src_Obj_IP = %s' %this_Src_Obj_IP)
                                exit()
                if WIDE_ROUTE_List != []:
                    text_line = ('\n@ %s' %t_key)
                    ACL_WiderThanRouting[t_key] = []
##                    if text_line not in Printed_Lines:
##                        Config_Change.append('\n---### ACL wider than routing ###---\n')
##                        Config_Change.append(text_line)
##                        Printed_Lines.append(text_line)
##                        ACL_WiderThanRouting[t_key] = []
                    text_line = (' - Surce_Object is <b>%s</b>, interface is <b>%s</b>, routing is:' %(t_this_Src_Obj, t_If_Name))
##                    if text_line not in Printed_Lines:
##                        Config_Change.append(text_line)
##                        Printed_Lines.append(text_line)
##                        ACL_WiderThanRouting[t_key].append(text_line)
##                        temp = []
##                        for n in WIDE_ROUTE_List:
##                            Config_Change.append('   %s' %n)
##                            temp.append(n)
##                        Config_Change.append('!')
##                        ACL_WiderThanRouting[t_key].append(temp)

##                    Config_Change.append(text_line)
##                    Printed_Lines.append(text_line)
                    ACL_WiderThanRouting[t_key].append(text_line)
                    temp = []
                    for n in WIDE_ROUTE_List:
##                        Config_Change.append('   %s' %n)
                        temp.append(n)
##                    Config_Change.append('!')
                    ACL_WiderThanRouting[t_key].append(temp)

                if BEST_ROUTE == '':
                    if WIDE_ROUTE_List == []:
                        if t_this_Src_Obj != '0.0.0.0/0':
                            text_line = ('Object %s\t\tdoes not belong to interface %s  @  %s|%s' %(row.Source,t_If_Name,row.Name,row.Line))
##                            if DEBUG_LEVEL == 0:
##                                if text_line not in Printed_Lines:
##                                    print (text_line)
##                                    Config_Change.append(text_line)
##                                    Printed_Lines.append(text_line)
                            if 'inactive' in row.Inactive:
                                if t_key not in NoActive_NoRoute_Root_ACL:
                                    NoActive_NoRoute_Root_ACL.append(t_key)
                                NoActive_NoRoute_Child_ACL.append(re_space.sub(' ',' '.join(temp1)))
                                if row.Hash not in t_Child_Hash:
                                    t_Child_Hash.append(row.Hash)
                                else:
                                    if 'range' not in row.Source:
##                                        print('>>> Hash Duplicato @ %s' %(' '.join(row))) if (DEBUG_LEVEL == 0) else ''
                                        Double_NO_Active_Hash.append(re_space.sub(' ',' '.join(temp1)))
                                NoActive_Noroute_Hash_ACL_Dic[t_Root__Hash] = t_Child_Hash
                            else:
                                if t_key not in SiActive_NoRoute_Root_ACL:
                                    SiActive_NoRoute_Root_ACL.append(t_key)
                                SiActive_NoRoute_Child_ACL.append(re_space.sub(' ',' '.join(temp1)))
                                if row.Hash not in t_Child_Hash:
                                    t_Child_Hash.append(row.Hash)
                                else:
                                    if 'range' not in row.Source:
##                                        print('>>> Hash Duplicato @ %s' %(' '.join(row))) if (DEBUG_LEVEL == 0) else ''
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
        #ACL_GROSS_df.columns = ['ID','HostName','First_Seen','Name','Line','Type','Action','Service','Source','S_Port','Dest','D_Port','Rest','Inactive','Hitcnt','Hash','Delta_HitCnt']
        if ACL_GROSS_df.shape[0] > 0:
            ACL_GROSS_df = ACL_GROSS_df.drop(labels='ID', axis=1)

    re_space = re.compile(r'  +') # two or more spaces
    ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict.keys())
    for t_key in list(SiActive_Noroute_Hash_ACL_Dic.keys()):
        Bool_check = ('Hash == "%s"') %(t_key)
        for row in ACL_Lines_DF.query(Bool_check).itertuples(): # un solo elemento
            ACL_Lines_DF.loc[row.Index, 'Hitcnt'] = "(hitcnt=%s)" %row.Hitcnt
            temp1 = [row.ACL, row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, '(hitcnt='+row.Hitcnt+')', row.Hash]
            t_Root_key = re_space.sub(' ',' '.join(temp1))
            t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_Root_key])
            t_ACL_Lines_DF_check = t_ACL_Lines_DF.copy()
            for t_row in t_ACL_Lines_DF.itertuples():
                for t_hash in SiActive_Noroute_Hash_ACL_Dic[t_key]:
                    if t_row.Hash == t_hash:
                        t_ACL_Lines_DF_check = t_ACL_Lines_DF_check.drop(t_row.Index)
            if len(t_ACL_Lines_DF_check) == 0:
                #print('Totally Wrong Routing for ACL @ %s' %t_Root_key)
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
                    else:
                        Totally_Wrong_Routing_Active_ACL_Counting.append([t_Delta_HitCnt.item(),t_Root_key])

                        #print('Totally Wrong Routing and incrementing for ACL\n @ %s' %(t_Root_key))
##                    if t_Delta_HitCnt.item() > 0:
##                        Totally_Wrong_Routing_Active_ACL_Counting.append([t_Delta_HitCnt.item(),t_Root_key])
##                        #print('Totally Wrong Routing and incrementing for ACL\n @ %s' %(t_Root_key))

            else:
                temp = []
                for t_row in t_ACL_Lines_DF.itertuples():
                    if t_row.Hash in SiActive_Noroute_Hash_ACL_Dic[t_key]:
                        temp1 = [t_row.ACL, t_row.Name, t_row.Line, t_row.Type, t_row.Action, t_row.Service, t_row.Source, t_row.S_Port, t_row.Dest, t_row.D_Port, t_row.Rest, t_row.Inactive, '(hitcnt='+t_row.Hitcnt+')', t_row.Hash]
                        #print('Partially Wrong Routing for ACL @ %s' %' '.join(t_row))
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
##    print(text_line)
##    Config_Change.append(text_line)
##    for n in Totally_Wrong_Routing_Active_ACL_Counting:
##        print ("{0:<8}==> {1}".format(n[0], n[1]))
##        Config_Change.append("{0:<8}==> {1}".format(n[0], n[1]))
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
    Watch_FName = hostname___ + '-WR4ACLCounting-Watch.html'
    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

    # OUTPUT HTML FILE for ACL_WiderThanRouting -------------------------------------------------------------------------
    t_html_file = []
    if len(ACL_WiderThanRouting) > 0:
        t_html_file.append('<ul>')
        for t_key in ACL_WiderThanRouting.keys():
            t_html_file.append('<li> %s<br>' %utils_v2.Color_Line(t_key))
            t_html_file.append('%s' %ACL_WiderThanRouting[t_key][0])
            t_html_file.append('<p class="text-dark small">')
            for t_route in ACL_WiderThanRouting[t_key][1]:
                t_html_file.append('&nbsp;' + t_route +'<br>')

            t_html_file.append('</p></li>')
        t_html_file.append('</ul>')
    else:
        t_html_file.append('nothing to show\n')
    Watch_FName = hostname___ + '-ACL_WiderThanRouting-Watch.html'
    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

    # OUTPUT HTML FILE for Totally_Wrong_Routing_Active_ACL -------------------------------------------------------------------------
    t_html_file = []
    if len(Totally_Wrong_Routing_Active_ACL) > 0:
        Totally_Wrong_Routing_Active_ACL.reverse()
        for n in Totally_Wrong_Routing_Active_ACL:
            t_html_file.append('%s<br>' %utils_v2.Color_Line(n))
    else:
        t_html_file.append('nothing to show\n')
    Watch_FName = hostname___ + '-TotWrongRouteACL-Watch.html'
    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))





    # OUTPUT HTML FILE for Partlly_Wrong_Routing_Active_ACL_Dic -------------------------------------------------------------------------
    PartlyWrongRouteACL = {}
    text_line = '\n--- Partially Wrong Routing for ACL ---'
    print(text_line)
    Config_Change.append(text_line)
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines_DF')
    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']
    Processed_line = []
    Processed_ACL_line = []
    for t_key in Partlly_Wrong_Routing_Active_ACL_Dic.keys():
        #Config_Change.append('\n @ ' + t_key)
##        print('\n @ ' + t_key)
        #for m in Partlly_Wrong_Routing_Active_ACL_Dic[t_key]:
        #dropped_ACL = Partlly_Wrong_Routing_Active_ACL_Dic[t_key]
        Root_ACL_df  = utils_v2.ASA_ACL_to_DF_light([t_key])
        check_point = Root_ACL_df['Name'][0] + ' ' + Root_ACL_df['Source'][0]
        if check_point not in Processed_ACL_line:
##            Config_Change.append('\n @ ' + t_key)
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
            #if t_Where_OBJ_Src_df['Name'].is_unique:
            #oggetto usato solo come souorce in questa ACL (una o più volte)
                #---- controllare anche i NAT ----
##                Config_Change.append('Object "%s" used as source in this ACL only' %t_OBJ_Src)
                PartlyWrongRouteACL[t_key].append('Object "%s" used as source in this ACL only' %t_OBJ_Src)
                if len(t_Where_OBJ_Dst_df) == 0:
##                    Config_Change.append('Object "%s" not used as destination' %t_OBJ_Src)
                    PartlyWrongRouteACL[t_key].append('Object "%s" not used as destination' %t_OBJ_Src)
                    #oggetto mai usato come Dest
                    #print('Object can be removed...')

                    if  (t_OBJ_Src.split()[0]) == 'object':
                        this_src_OBJ = t_OBJ_Src.split()[1]
                        print(".. object... WTF???? Dovrebbe essere un totally wrong routing.... ")
                        print('t_OBJ_Src = %s' %t_OBJ_Src)
                        print('t_key = %s' %t_key)
                        print('row = %s' %row)
                    elif(t_OBJ_Src.split()[0]) == 'object-group':
                        this_src_OBJ = t_OBJ_Src.split()[1]
                        #Config_Change.append('show run | i %s' %this_src_OBJ)
##                        Config_Change.append('object-group network %s' %this_src_OBJ)
                        PartlyWrongRouteACL[t_key].append('object-group network %s' %this_src_OBJ)

                        this_Obj_Grp = OBJ_GRP_NET_Dic[this_src_OBJ]

                        for row in Child_ACL_Df.itertuples():
                            src_to_find = row.Source
##                            Config_Change.append('!no routing for %s' %src_to_find)
                            PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)

                            if 'host ' in src_to_find:
                                src_to_find = src_to_find.split()[1]
                                for item in this_Obj_Grp:
                                    if 'network-object host' in item:
                                        if item.split()[2] == src_to_find:
##                                            Config_Change.append('no %s' %item)
                                            PartlyWrongRouteACL[t_key].append('no %s' %item)
                                    elif 'network-object object' in item:
                                        objnet_2_find = item.split()[2]
                                        objnet_item = Obj_Net_Dic[objnet_2_find]
                                        if src_to_find in objnet_item:
##                                            Config_Change.append('no %s' %item)
                                            PartlyWrongRouteACL[t_key].append('no %s' %item)
                                    elif 'group-object' in item:
                                        # ----- nested host, recursive lookup to be done -----
                                        continue
                                    elif 'network-object ' in item:
                                        if src_to_find in item:
##                                            Config_Change.append('no network-object %s' %item)
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
                                        # questo caso dovrebbe ricadere nella parte superiore dell "if"
                                        continue
                                    elif 'network-object object' in item:
                                        objnet_2_find = item.split()[2]
                                        objnet_item = Obj_Net_Dic[objnet_2_find]
                                        if src_to_find in objnet_item:
##                                            Config_Change.append('no %s' %item)
                                            PartlyWrongRouteACL[t_key].append('no %s' %item)
                                        item_Found = True
                                    elif 'group-object' in item:
                                        # ----- nested host, recursive lookup to be done -----
                                        item_Found = True
                                        continue
                                    elif 'network-object ' in item:
                                        if src_to_find in item:
##                                            Config_Change.append('no network-object %s' %item)
                                            PartlyWrongRouteACL[t_key].append('no network-object %s' %item)
                                        item_Found = True
                                if item_Found == False:
                                    print('eccezione da gestire!!!!!')
                                    print('src_to_find = %s' %src_to_find)
                                    print('item = %s' %item)
                                    print('t_key = %s' %t_key)
                                    print('row = %s' %row)
                                    exit(67890)

                    elif(t_OBJ_Src.split()[0]) == 'host':
                        this_src_OBJ = t_OBJ_Src.split()[1]
                        print(".. host... WTF???? Dovrebbe essere un totally wrong routing.... ")
                    elif('.' in t_OBJ_Src.split()[0]):
                        try:
                            t_this_Src_ip = t_OBJ_Src.split()[0] + Sub_Mask_2[t_OBJ_Src.split()[1]]
                            ipaddress.IPv4Network(t_this_Src_ip, strict=False)
##                            Config_Change.append('no %s' %t_OBJ_Src)
                            PartlyWrongRouteACL[t_key].append('no %s' %t_OBJ_Src)
                        except:
                            print('check what is passed @%s' %t_this_Src_ip)
                            exit('0000')
                else:
##                    Config_Change.append('Object "%s" used as destination in other ACL' %t_OBJ_Src)
                    PartlyWrongRouteACL[t_key].append('Object "%s" used as destination in other ACL' %t_OBJ_Src)
##                    Config_Change.append(tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False))
                    temp = tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False).split('\n')
                    for line in temp:
                        PartlyWrongRouteACL[t_key].append(line.replace(' ','&nbsp;'))
                    #PartlyWrongRouteACL[t_key].append(tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False).replace('\n','<br>').replace(' ','&nbsp;'))
                    for row in Child_ACL_Df.itertuples():
                        src_to_find = row.Source
##                        Config_Change.append('!no routing for %s' %src_to_find)
                        PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)
            else:
                check_line = '%s in %s' %(t_OBJ_Src, ', '. join(list(t_Where_OBJ_Src_df['Name'].unique())))
                if check_line not in Processed_line:
                    Processed_line.append(check_line)
##                    Config_Change.append('Object "%s" used as source in other ACL @ %s' %(t_OBJ_Src, ', '. join(list(t_Where_OBJ_Src_df['Name'].unique()))))
                    PartlyWrongRouteACL[t_key].append('Object "%s" used as source in other ACL' %(t_OBJ_Src))
##                    Config_Change.append(tabulate(t_Where_OBJ_Src_df,t_Where_OBJ_Src_df,tablefmt='psql',showindex=False))
                    temp = tabulate(t_Where_OBJ_Src_df,t_Where_OBJ_Src_df,tablefmt='psql',showindex=False).split('\n')
                    for line in temp:
                        PartlyWrongRouteACL[t_key].append(line.replace(' ','&nbsp;'))
                    #PartlyWrongRouteACL[t_key].append(tabulate(t_Where_OBJ_Src_df,t_Where_OBJ_Src_df,tablefmt='psql',showindex=False).replace('\n','<br>').replace(' ','&nbsp;'))
                    for row in Child_ACL_Df.itertuples():
                        src_to_find = row.Source
##                        Config_Change.append('!no routing for %s' %src_to_find)
                        PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)
                    #more than one ACL woth this SRC_OBJ
                    if len(t_Where_OBJ_Dst_df) == 0:
##                        Config_Change.append('Object "%s" not used as destination' %t_OBJ_Src)
                        PartlyWrongRouteACL[t_key].append('Object "%s" not used as destination' %t_OBJ_Src)
##                        Config_Change.append(tabulate(t_Where_OBJ_Src_df,t_Where_OBJ_Src_df,tablefmt='psql',showindex=False))
##                        PartlyWrongRouteACL[t_key].append(tabulate(t_Where_OBJ_Src_df,t_Where_OBJ_Src_df,tablefmt='psql',showindex=False).replace('\n','<br>').replace(' ','&nbsp;'))
                        for row in t_Where_OBJ_Src_df.itertuples():
                            line_Check = '%s %s' %(row.Name, row.Source)
                            if line_Check not in Processed_line:
                                Processed_line.append(line_Check)
                    else:
##                        Config_Change.append('Object "%s" used as destination in other ACL' %t_OBJ_Src)
                        PartlyWrongRouteACL[t_key].append('Object "%s" used as destination in other ACL' %t_OBJ_Src)
##                        Config_Change.append(tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False))
                        temp = tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False).split('\n')
                        for line in temp:
                            PartlyWrongRouteACL[t_key].append(line.replace(' ','&nbsp;'))
                        #PartlyWrongRouteACL[t_key].append(tabulate(t_Where_OBJ_Dst_df,t_Where_OBJ_Dst_df,tablefmt='psql',showindex=False).replace('\n','<br>').replace(' ','&nbsp;'))
                        for row in Child_ACL_Df.itertuples():
                            src_to_find = row.Source
##                            Config_Change.append('!no routing for %s' %src_to_find)
                            PartlyWrongRouteACL[t_key].append('!no routing for %s' %src_to_find)
                        continue
                else:
##                    Config_Change.append('%s already processed' %t_OBJ_Src)
                    PartlyWrongRouteACL[t_key].append('%s already processed' %t_OBJ_Src)

### da gestire IPv6 in "utils_v2.ASA_ACL_Obj_to_Net(row.Source)"
    t_html_file = []
    if len(PartlyWrongRouteACL) > 0:
        t_html_file.append('<ul>')
        for t_key in PartlyWrongRouteACL.keys():
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
    Watch_FName = hostname___ + '-PtlyWrongRouteACL-Watch.html'
    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

    return Config_Change


##=============================================================================================================================
##   __    ___  __      ____   ___  ____    _  _  ___    ____  _____  __  __  ____  ____  _  _  ___    ____   __    ____  __    ____
##  /__\  / __)(  )    (  _ \ / __)(_  _)  ( \/ )/ __)  (  _ \(  _  )(  )(  )(_  _)(_  _)( \( )/ __)  (_  _) /__\  (  _ \(  )  ( ___)
## /(__)\( (__  )(__    )(_) )\__ \  )(     \  / \__ \   )   / )(_)(  )(__)(   )(   _)(_  )  (( (_-.    )(  /(__)\  ) _ < )(__  )__)
##(__)(__)\___)(____)  (____/ (___/ (__)     \/  (___/  (_)\_)(_____)(______) (__) (____)(_)\_)\___/   (__)(__)(__)(____/(____)(____)

# per ogni riga ACL expanded:
    # controlla roting DEST => interfaccia di uscita
    # riorganizza la ACL suddividendo per SRC_IF VS DST_IF

def ACL_Dest_Vs_Routing_Table(t_device, Config_Change, log_folder):

    from Network_Calc import Sub_Mask_2,Sub_Mask_1,IPv4_to_DecList,Is_Dec_Overlapping,Port_Converter
    from tabulate import tabulate
    import shelve
    import ipaddress
    import pandas as pd
    import sqlalchemy as db
    from utils_v2 import File_Save_Try

    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    FW_log_folder = log_folder + '/' + hostname___
    html_folder = FW_log_folder

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

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ROUTE_DF')
    with shelve.open(tf_name) as shelve_obj: ROUTE_DF = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Name_dic')
    with shelve.open(tf_name) as shelve_obj: Name_dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Nameif_List')
    with shelve.open(tf_name) as shelve_obj: Nameif_List = shelve_obj['0']

    Printed_Lines = []
    NoActive_NoRoute_Root_ACL = []
    SiActive_NoRoute_Root_ACL = []
    NoActive_NoRoute_Child_ACL = []
    SiActive_NoRoute_Child_ACL = []
    NoActive_Noroute_Hash_ACL_Dic = {}
    SiActive_Noroute_Hash_ACL_Dic = {}

    Double_NO_Active_Hash = []
    Double_SI_Active_Hash = []
    Totally_Wrong_Routing_Active_ACL = []
    Partlly_Wrong_Routing_Active_ACL = []
    Partlly_Wrong_Routing_Active_ACL_Dic = {}

    Redundant_Routes = []
    Redundant_Routes_Warnign = []

    text = ('Check Acl Destination Vs Routing Table @ %s' %hostname___)
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
    ROUTE_IP_DF = ROUTE_DF.copy()
    ROUTE_IP_DF['IPv4_Network'] = ''

    t_N_Total_Routes = ROUTE_IP_DF.shape[0]
    t_N_Redun_Routes = 0
    for row in ROUTE_IP_DF.itertuples():
        try:
            ROUTE_IP_DF.at[row.Index, 'IPv4_Network'] = ipaddress.IPv4Network(row.Network)
        except:
            try:
                t_routename = row.Network.split('/')[0]
                t_routeip = Name_dic[t_routename] +'/'+ row.Network.split('/')[1]
                ROUTE_IP_DF.at[row.Index, 'IPv4_Network'] = ipaddress.IPv4Network(t_routeip)
            except:
                Config_Change.append('ERROR 1105 while converting %s to ipaddress\n' %row.Network)
                print('ERROR 1105 while converting %s to ipaddress\n' %row.Network)
                ROUTE_IP_DF = ROUTE_IP_DF.drop(row.Index)
                continue
    ROUTE_IP_DF_copy = ROUTE_IP_DF.copy()

##    start = datetime.datetime.now()
    Routing_Space_IN = {}
    for t_IN_ifName in list(ROUTE_IP_DF.Interface.unique()):
        Routing_Space_IN[t_IN_ifName] = 0
    for t_IN_ifName in Nameif_List:
        if t_IN_ifName not in Routing_Space_IN.keys():
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
                if row1.Interface != row2.Interface:
                    Routing_Space_IN[row2.Interface] -= row1.IPv4_Network.num_addresses
            if row2.Network == '0.0.0.0/0':
                continue
            if (row1.IPv4_Network).subnet_of(row2.IPv4_Network):
                if BEST_ROUTE == []:
                    BEST_ROUTE = [row2.IPv4_Network, row2.Interface, row2.NextHop]
                elif row2.IPv4_Network.subnet_of(BEST_ROUTE[0]): # swap routes
                    if row1.NextHop == row2.NextHop:
                        BEST_ROUTE = [row2.IPv4_Network, row2.Interface, row2.NextHop]
                    else:
                        #print('Best route %s to different NextHop %s @ interface %s' %(row2.IPv4_Network, row2.NextHop, row2.Interface))
                        Redundant_Routes_Warnign.append('\n')
                        Redundant_Routes_Warnign.append('route %s %s %s\n' %(row2.Interface, row2.IPv4_Network, row2.NextHop))
                        Redundant_Routes_Warnign.append('route %s %s %s\n' %(row1.Interface, row1.IPv4_Network, row1.NextHop))
                        #Redundant_Routes.append('Best route %s to different NextHop %s @ interface %s' %(row2.IPv4_Network, row2.NextHop, row2.Interface))
                        #print('\n')
                        #print('route %s %s %s' %(row2.Interface, row2.IPv4_Network, row2.NextHop))
                        #print('route %s %s %s' %(row1.Interface, row1.IPv4_Network, row1.NextHop))
                        #print('Best route %s to different NextHop %s @ interface %s' %(row2.IPv4_Network, row2.NextHop, row2.Interface))

        if BEST_ROUTE != []:
            if Interface1 == BEST_ROUTE[1]:
                if row1.Type == 'C':
                    #print('CONNECTED!!!')
                    Redundant_Routes.append('\n CONNECTED!!!')
                    Redundant_Routes.append('! %s @ %s ==> %s' %(row1.IPv4_Network, row1.Interface, BEST_ROUTE[0]))
                #print('\nredundant route found: %s @ %s ==> %s' %(row1.IPv4_Network, row1.Interface, BEST_ROUTE[0]))
                #print('no route %s %s %s %s ' %((row1.Interface), str(row1.IPv4_Network.network_address), str(row1.IPv4_Network.netmask), row1.NextHop))
                else:
                    Redundant_Routes.append('\n! %s @ %s ==> %s' %(row1.IPv4_Network, row1.Interface, BEST_ROUTE[0]))
                    Redundant_Routes.append('no route %s %s %s %s ' %((row1.Interface), str(row1.IPv4_Network.network_address), str(row1.IPv4_Network.netmask), row1.NextHop))
                #print('Dropping %s' %ROUTE_IP_DF.iloc[row1.Index])
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

    for t_key1 in Routing_Space_IN.keys():
        sum_delta = 0
        for t_key2 in Routing_Space_IN.keys():
            if t_key1 != t_key2:
                sum_delta += Routing_Space_IN[t_key2]
        Routing_Space_OUT[t_key1] = Routing_Space_IN[t_key1]*sum_delta
    #print('routing check done!') --------------------------------------------------------------------------------

    t_html_file = ['<ul>']
    Founded_Routes = {}
    acl_too_open = []
    BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List_Dict.keys())
    for t_key in list(ACL_List_Dict.keys()):
##        t_Root__Hash = t_key.split()[-1]
##        t_Child_Hash = []

        LOOP_INDEX = LOOP_INDEX + 1
        if LOOP_INDEX > (ITEMS/STEPS)*BINS:
            print ('....%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1

        t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_key])
        t_ACL_Name = t_ACL_Lines_DF.Name[0]
        t_If_Name = ''
        try:
            t_If_Name = Accessgroup_Dic_by_ACL[t_ACL_Name]
        except:
            continue #silently skip acl not applied to any interface

        for row in t_ACL_Lines_DF.itertuples():
            ACL_text = row.ACL+' '+row.Name+' '+row.Line+' '+row.Type+' '+row.Action+' '+row.Service+' '+row.Source+' '+row.S_Port+' '+row.Dest+' '+row.D_Port+' '+row.Rest+' '+row.Hitcnt+' '+row.Hash
            #print('DBG:' + ' '.join(row)) if (DBG == 1) else ''
            this_Dst_Obj = utils_v2.ASA_ACL_Obj_to_Net(row.Dest)
            if this_Dst_Obj == []: #da gestire ipv6
                continue
            if 'inactive' in row.Inactive:
                continue

            if utils_v2.ASA_ACL_Obj_to_IP(row.Source)[0] == -1: #ipv6
                continue
            elif utils_v2.ASA_ACL_Obj_to_IP(row.Source)[0] == ipaddress.IPv4Network('0.0.0.0/0'):
                SRC = Routing_Space_IN[t_If_Name]
            else:
                SRC = utils_v2.ASA_ACL_Obj_to_IP(row.Source)[0].num_addresses
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
                #print(f"{round(ACL_Openess,2):<6} - {ACL_text:>8}")
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

            if this_Dst_Obj[0] in list(Founded_Routes.keys()):
                if this_Dst_Obj[0] != '0.0.0.0 0.0.0.0':
                    Out_Interface = Founded_Routes[this_Dst_Obj[0]]
                    ACL_OUT_IF_COUNTER_dic[(t_If_Name,Out_Interface)] += 1
                    #ACL_OUT_IF_ACLs_dic[(t_If_Name,Out_Interface)].append(' '.join(row))
                    ACL_OUT_IF_ACLs_dic[(t_If_Name,Out_Interface)].append(ACL_text)
                    continue

            for t_this_Dst_Obj in this_Dst_Obj:
                temp = t_this_Dst_Obj.split()
                try:
                    t_this_Dst_Obj = temp[0] + Sub_Mask_2[temp[1]]
                except:
                    text_line = ('>>>   ERROR... non conventional subnet mask for "%s"' %t_this_Dst_Obj)
                    if text_line not in Printed_Lines:
                        #print(text_line)
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

                # find all routes related to this t_this_Dst_Obj
                # if best route and others to single next hop =>
                # else => wide_route to other interfaces


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
                        if this_Dst_Obj[0] not in list(Founded_Routes.keys()):
                            Founded_Routes[this_Dst_Obj[0]] = Out_Interface

                        #print('BEST_ROUTE = %s' %BEST_ROUTE)
                        ROUTE_IP_DF_bis = ROUTE_IP_DF_copy.copy()
                        ROUTE_IP_DF_bis = ROUTE_IP_DF_bis.loc[ROUTE_IP_DF_bis['Type']!='V']
                        Best_Route_Index = ROUTE_IP_DF_copy.index[ROUTE_IP_DF_copy['IPv4_Network'] == BEST_ROUTE].to_list()[0]
                        ROUTE_IP_DF_bis = ROUTE_IP_DF_bis.drop(Best_Route_Index)
                        #df.loc[df['column_name'] == some_value]

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
                        #print('Dst == any => all interfaces to be triggered if PERMIT')
                        #print(' '.join(row))

                if WIDE_ROUTE_List != []:
                    #print('WIDE_ROUTE_List = %s' %WIDE_ROUTE_List)
                    text_line = ('<li> %s' %t_key)
                    #print('\n---### ACL wider than routing ###---')
                    #print (text_line)
                    #Config_Change.append(text_line)
                    t_html_file.append(text_line)
                    t_this_Dst_Obj = this_Dst_Obj[0].split()
                    try:
                        text_line = (' - Dest_Object is "%s%s", interface IN is "%s"\n' %(t_this_Dst_Obj[0], Sub_Mask_2[t_this_Dst_Obj[1]], t_If_Name))
                    except:
                        text_line = (' - Dest_Object is "%s", interface IN is "%s"\n' %(this_Dst_Obj[0], t_If_Name))
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
                    #print (text_line)
                    #Config_Change.append(text_line)
                    t_html_file.append(text_line)
                    t_html_file.append('<p class="text-dark small">')
                    for n in WIDE_ROUTE_List:
                        temp = (f"{n[0]:<20} {n[1]:<5}")
                        t_html_file.append(temp.replace(' ','&nbsp;'))
                    t_html_file.append('</p></li>')


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
        for t_key in ACL_Space_ICMP.keys():
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

##            print('ACL_Space_ICMP for: \t\t%s = %s' %(t_key, ACL_Space_ICMP_Percent))
##            print('ACL_Space_UDP  for: \t\t%s = %s' %(t_key, ACL_Space_UDP_Percent))
##            print('ACL_Space_TCP  for: \t\t%s = %s' %(t_key, ACL_Space_TCP_Percent))
##            print('!')

            if t_key in list(Accessgroup_Dic_by_ACL.values()):
                Updated_Vals = dict(
                                    ACL_Space_ICMP = ACL_Space_ICMP_Percent,
                                    ACL_Space_TCP  = ACL_Space_TCP_Percent,
                                    ACL_Space_UDP  = ACL_Space_UDP_Percent
                                    )
                query = db.update(ACL_Summary).where(db.and_(ACL_Summary.c.HostName==hostname___, ACL_Summary.c.Nameif==t_key)).values(**Updated_Vals)
                with engine.begin() as connection:
                    results = connection.execute(query)
                #print(f"{results.rowcount} row(s) updated.")

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
            #print(f"{results.rowcount} row(s) updated.")
    else:
        print('ERROR in ACL_Dest_Vs_Routing_Table: DB NOT Available!')

    ACL_OUT_IF_COUNTER_list = []
    for t_key in ACL_OUT_IF_COUNTER_dic.keys():
        if ACL_OUT_IF_COUNTER_dic[t_key] != 0:
            ACL_OUT_IF_COUNTER_list.append([t_key[0], t_key[1], ACL_OUT_IF_COUNTER_dic[t_key]])
    ACL_OUT_IF_COUNTER_df = pd.DataFrame(ACL_OUT_IF_COUNTER_list, columns = ['IF_in' , 'IF_Out', 'Count'])
    #Config_Change.append(tabulate(ACL_OUT_IF_COUNTER_df,ACL_OUT_IF_COUNTER_df,tablefmt='psql',showindex=False))

##    for t_key in ACL_OUT_IF_ACLs_dic.keys():
##        if len(ACL_OUT_IF_ACLs_dic[t_key]) != 0:
##            Config_Change.append('----- ' + t_key[0]+' to '+t_key[1]+' -----')
##            for n in ACL_OUT_IF_ACLs_dic[t_key]:
##                Config_Change.append(n)

    # OUTPUT HTML FILE 'acl_too_open-Watch.html' ------------------------------------------
    Watch_FName = hostname___ + '-acl_too_open-Watch.html'
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
        t_html_file.append('    <th>%s</th>\n' %t_item[0])
        new_line = utils_v2.Color_Line(' '.join(t_item[1].split()[:-2]))
        t_html_file.append('    <th>%s</th>\n' %new_line)
        t_html_file.append('    <th>%s</th>\n' %utils_v2.Color_Line(t_item[1].split()[-2]))
        t_html_file.append('    <th>%s</th>\n' %t_item[1].split()[-1])
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

    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

    # OUTPUT HTML FILE 'drill_down_acls-Watch.html' ---------------------------------------------------
    Watch_FName = hostname___ + '-drill_down_acls-Watch.html'
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
    # collect all input interfaces
    #t_html_file.append('    <th><input type="text" class="form-control form-control-sm" placeholder="Filter IF_IN"></th>\n')
    t_html_file.append('  <th>\n')
    t_html_file.append('    <select class="form-control form-control-sm">\n')
    t_html_file.append('      <option value="">Filter IF_IN</option>\n')
    done_if = []
    for t_key in ACL_OUT_IF_ACLs_dic.keys():
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
    for t_key in ACL_OUT_IF_ACLs_dic.keys():
        if len(ACL_OUT_IF_ACLs_dic[t_key]) != 0:
            #Config_Change.append('----- ' + t_key[0]+' to '+t_key[1]+' -----')
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

    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

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
                #['inside','M_OOB_FE_',124],
        elif "_HEIGHT_GOES_HERE_" in l[n]:
            if len(ACL_OUT_IF_COUNTER_dic.keys()) < 600:
                CONST_Height_Scale_Factor = round(600 / len(ACL_OUT_IF_COUNTER_dic.keys()))
                if_number = len(ACL_OUT_IF_COUNTER_dic.keys())*CONST_Height_Scale_Factor
            else:
                if_number = len(ACL_OUT_IF_COUNTER_dic.keys())
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

    import sqlalchemy as db
    import pandas as pd
    from tabulate import tabulate
    import re
    import shelve
    import ipaddress

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
        #print('hostname = %s' %hostname)
        query = db.select(Active_Capture).where(Active_Capture.c.HostName==hostname___)
        with engine.connect() as connection:
            Capture_db = pd.DataFrame(connection.execute(query).fetchall())
            #ResultSet = connection.execute(query)
        #Capture_db = pd.DataFrame(ResultSet)

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

    # organizzo i dati letti come il db
    FW_log_folder = log_folder + '/' + hostname___
    with open("%s/%s___Show_Capture.txt"%(FW_log_folder,hostname___),"r") as f:
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
        Capture_db.columns = ['ID','HostName','Name','First_Seen','Content']
        Capture_db = Capture_db.drop('ID',axis=1)
        #check if capture is new
        for row in Capture_df.itertuples():
            t_name = row.Name
            query = db.select(Active_Capture).where(db.and_(Active_Capture.columns.HostName==hostname___, Active_Capture.columns.Name==t_name))
            #t_Capture_db = pd.DataFrame(connection.execute(query).fetchall())
            with engine.connect() as connection:
                t_Capture_db = pd.DataFrame(connection.execute(query).fetchall())
            if len(t_Capture_db) == 0: #capture is new
                #print('inserting new capture @ %s : %s in DB' %(row.HostName, row.Name))
                Config_Change.append(f'inserting new capture @ {row.HostName} : {row.Name} in DB')
                #query = db.insert(Active_Capture).values(HostName=row.HostName, Name=row.Name, First_Seen=row.First_Seen, Content=row.Content)
                #ResultProxy = connection.execute(query)
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
                    #query = db.insert(Active_Capture).values(HostName=row.HostName, Name=row.Name, First_Seen=row.First_Seen, Content=row.Content)
                    #ResultProxy = connection.execute(query)
                    delete_stmt = db.delete(Active_Capture).where(db.and_(Active_Capture.columns.HostName==row.HostName, Active_Capture.columns.Name==row.Name))
                    with engine.begin() as connection:
                        result = connection.execute(delete_stmt)
                    #deleted_rows = result.rowcount
                    #print(f"{result.rowcount} row(s) deleted.")
                    #print('modified new capture @ %s : %s in DB' %(row.HostName, row.Name))
                    Config_Change.append(f'{result.rowcount} row(s) deleted.')
                    Config_Change.append(f'modified new capture @ {row.HostName} : {row.Name} in DB')
                    insert_stmt = Active_Capture.insert().values(HostName=row.HostName, Name=row.Name, First_Seen=row.First_Seen, Content=row.Content)
                    with engine.begin() as connection:
                        connection.execute(insert_stmt)
                    Capture_df.iloc[row.Index].First_Seen = 0
        # rimuovo dal db le capture che sono già state cancellate
        if len(Capture_df) > 0:
            for row in Capture_db.itertuples():
                Bool_check = ('HostName == "%s" & Name == "%s"') %(row.HostName,row.Name)
                t_Capture_df = Capture_df.query(Bool_check)
                if len(t_Capture_df) == 0:
                    #print('deleting capture @ %s : %s from DB' %(row.HostName,row.Name))
                    Config_Change.append(f'deleting capture @ {row.HostName} : {row.Name} from DB')
                    delete_stmt = db.delete(Active_Capture).where(db.and_(Active_Capture.columns.HostName==row.HostName, Active_Capture.columns.Name==row.Name))
                    with engine.begin() as connection:
                        result = connection.execute(delete_stmt)
                    #print(f"{result.rowcount} row(s) deleted.")
                    Config_Change.append(f"{result.rowcount} row(s) deleted.")
        else:
            # rimuovo tutte le capture dal DB
            delete_stmt = db.delete(Active_Capture).where(Active_Capture.columns.HostName==hostname___)
            with engine.begin() as connection:
                result = connection.execute(delete_stmt)
            #print(f'{result.rowcount} row(s) deleted.')
            Config_Change.append(f'{result.rowcount} row(s) deleted.')
    else:
        #capture is new
        #print('new device, inserting %s captures for %s in DB' %(len(Capture_df),hostname))
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
##    Merge_FName = FW_log_folder + '/' + hostname___ + '-Capture-Merge.txt'
    Watch_Flist = []
    Merge_Flist = []
    Merge_Flist.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    Merge_Flist.append('!')

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
            #print('row.Index = %s' %row.Index)
            #print('t_col_index = %s' %t_col_index)
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

    Capture_df_Print = pd.DataFrame(Capture_df[['First_Seen','Content']])
    for row in Capture_df_Print.itertuples():
        Merge_Flist.append('%s Days ---------- ' %(row.First_Seen))
        for n in range(0,len(row.Content)):
            Merge_Flist.append('%s' %(row.Content[n].strip()))

    Merge_Flist.append('!')
    for n in Clear_Capture: Merge_Flist.append(n)
    Merge_Flist.append('!')
##    with open(Merge_FName, "w") as f:
##        f.write('\n'.join(Merge_Flist))

##    Config_Change.append('!')
##    for n in Clear_Capture:
##        Config_Change.append('%s' %n)

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

##        Updated_Vals = dict(
##                                N_Capture = t_N_Capture,
##                                N_Capture_CircBuff = t_N_Capture_CircBuff,
##                                N_Capture_Active = t_N_Capture_Active,
##                                N_Capture_Old = t_N_Capture_Old
##                            )
##        query = db.update(My_Devices).where(My_Devices.c.HostName==hostname___).values(Updated_Vals)
##        results = connection.execute(query)

    engine.dispose()
    return Config_Change


##=============================================================================================================================
## __  __  ___  ____    ____  ____  ___  __      __    ____  ____  ____     _____  ____   ____  ____  ___  ____  ___
##(  )(  )/ __)( ___)  (  _ \( ___)/ __)(  )    /__\  (  _ \( ___)(  _ \   (  _  )(  _ \ (_  _)( ___)/ __)(_  _)/ __)
## )(__)( \__ \ )__)    )(_) ))__)( (__  )(__  /(__)\  )   / )__)  )(_) )   )(_)(  ) _ <.-_)(   )__)( (__   )(  \__ \
##(______)(___/(____)  (____/(____)\___)(____)(__)(__)(_)\_)(____)(____/   (_____)(____/\____) (____)\___) (__) (___/

def Use_Declared_Objects(t_device, Config_Change, log_folder):
#    from Network_Calc import Sub_Mask_2
    import shelve
#    import ipaddress

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Undeclared_NetObj_Used_List')
    with shelve.open(tf_name) as shelve_obj: Undeclared_NetObj_Used_List = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obejct_by_value_Dict')
    with shelve.open(tf_name) as shelve_obj: Obejct_by_value_Dict = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_NET_Dic')
    with shelve.open(tf_name) as shelve_obj: OBJ_GRP_NET_Dic = shelve_obj['0']

    Watch_Flist = []
    text = ('Use Declared Object @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    with open("%s/%s___Show_Running-Config.txt"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
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
                    #print('convert this to " object network ..."')
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
    from tabulate import tabulate
#    from Network_Calc import Sub_Mask_2
    import shelve
#    import ipaddress

    hostname___ = t_device.replace('/','___')

    text = ('Explicit Deny Ip Any Any @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    FW_log_folder = log_folder + '/' + hostname___
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines_DF')
    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Unused_ACL_List')
    with shelve.open(tf_name) as shelve_obj: Unused_ACL_List = shelve_obj['0']

    Bool_check = ('Action == "deny" & Service == "ip" & "%s" in Source & "%s" in Dest' %('any','any'))
    temp = Show_ACL_Lines_DF.query(Bool_check)

    # check it only for ACL in "access-group"
    for n in range(0,len(Accessgroup_Dic_by_ACL.keys())):
        t_ACL = list(Accessgroup_Dic_by_ACL.keys())[n]
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

##    Bool_check = ('Action == "deny" & "%s" in Dest' %('any'))
##    temp = Show_ACL_Lines_DF.query(Bool_check)
##    Config_Change.append(tabulate(temp,temp,tablefmt='psql',showindex=False))

    return Config_Change

##=============================================================================================================================
## ____  ____  ____  __  __  ____  ____                __    _  _  _  _
##(  _ \( ___)(  _ \(  \/  )(_  _)(_  _)  \|/  \|/    /__\  ( \( )( \/ )
## )___/ )__)  )   / )    (  _)(_   )(    /|\  /|\   /(__)\  )  (  \  /
##(__)  (____)(_)\_)(_/\/\_)(____) (__)             (__)(__)(_)\_) (__)

def Permit_X_X_Any(t_device, Config_Change, log_folder):
    from tabulate import tabulate
    from Network_Calc import Sub_Mask_2
    import shelve
    import pandas as pd
#    import ipaddress

    hostname___ = t_device.replace('/','___')
    re_space = re.compile(r'  +') # two or more spaces

    LARGER_PREFIX = 20

    text = ('Permit * * Any @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    Permit_to_Any = []
    Not_Applied_ACL = []
    Inactive_ACL = []
    Larger_ACL = []
    inactive_Larger_ACL = []
    DF_Filter_1 = ('Action == "permit" & "%s" in Dest' %('any'))
    DF_Filter_2 = ('Action == "permit" & "%s" in Dest' %('any4'))
#    DF_Filter_1 = ('"%s" in Dest' %('any'))
#    DF_Filter_2 = ('"%s" in Dest' %('any4'))

    FW_log_folder = log_folder + '/' + hostname___
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']

    BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List_Dict.keys())
    for t_key in list(ACL_List_Dict.keys()):

        LOOP_INDEX = LOOP_INDEX + 1
        if LOOP_INDEX > (ITEMS/STEPS)*BINS:
            print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1

        t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_key])
        temp1 = t_ACL_Lines_DF.query(DF_Filter_1)
        if len(temp1) > 0:
            Permit_to_Any.append(t_key)
        temp2 = t_ACL_Lines_DF.query(DF_Filter_2)
        if len(temp2) > 0:
            Permit_to_Any.append(t_key)

        for row in t_ACL_Lines_DF.itertuples():
            Dest_Item = row.Dest
            if 'host' not in Dest_Item:
                if 'range' not in Dest_Item:
                    if 'any' not in Dest_Item:
                        try:
                            Dest_SubMask = Sub_Mask_2[Dest_Item.split()[1]].replace('/','')
                            if int(Dest_SubMask) <= LARGER_PREFIX:
                                if 'inactive' in row.Rest:
                                    if t_key not in inactive_Larger_ACL:
                                        inactive_Larger_ACL.append(t_key)
                                elif t_key not in Larger_ACL:
                                    Larger_ACL.append(t_key)
                        except:
                            temp1 = [row.ACL, row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, row.Hitcnt, row.Hash]
                            t_line = ' '.join(temp1)
                            print('WARNING!!! non conventional subnet mask @ "%s"' %t_line)
                            Config_Change.append('WARNING!!! non conventional subnet mask @ %s' %t_line)

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Unused_ACL_List')
    with shelve.open(tf_name) as shelve_obj: Unused_ACL_List = shelve_obj['0']

    Permit_to_Any_DF = utils_v2.ASA_ACL_to_DF(Permit_to_Any)
    for row in Permit_to_Any_DF.itertuples():
        temp1 = [row.ACL, row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, row.Hitcnt, row.Hash]
        if row.Name in Unused_ACL_List:
            #Not_Applied_ACL.append(' '.join(row))
            Not_Applied_ACL.append(temp1)
            Permit_to_Any_DF = Permit_to_Any_DF.drop(row.Index)
        elif 'inactive' in row.Inactive:
            #Inactive_ACL.append(' '.join(row))
            Inactive_ACL.append(temp1)
            Permit_to_Any_DF = Permit_to_Any_DF.drop(row.Index)

    col_names = ['ACL', 'Name', 'Line', 'Type', 'Action', 'Service', 'Source', 'S_Port','Dest','D_Port','Rest','Inactive','Hitcnt','Hash']
    Config_Change.append(tabulate(Permit_to_Any_DF,Permit_to_Any_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n Dangerous inactive ACL\n')
    #Inactive_ACL_DF = utils_v2.ASA_ACL_to_DF(Inactive_ACL)
    Inactive_ACL_DF = pd.DataFrame(Inactive_ACL, columns = col_names)
    Config_Change.append(tabulate(Inactive_ACL_DF,Inactive_ACL_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n Dangerous not applied ACL\n')
    #Not_Applied_ACL_DF = utils_v2.ASA_ACL_to_DF(Not_Applied_ACL)
    Not_Applied_ACL_DF = pd.DataFrame(Not_Applied_ACL, columns = col_names)
    Config_Change.append(tabulate(Not_Applied_ACL_DF,Not_Applied_ACL_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n ACL with Destination Larger than \\%s\n' %LARGER_PREFIX)
    Larger_ACL_DF = utils_v2.ASA_ACL_to_DF(Larger_ACL)
    Config_Change.append(tabulate(Larger_ACL_DF,Larger_ACL_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n Dangerous Inactive ACL with Destination Larger than \\%s\n' %LARGER_PREFIX)
    inactive_Larger_ACL_DF = utils_v2.ASA_ACL_to_DF(inactive_Larger_ACL)
    Config_Change.append(tabulate(inactive_Larger_ACL_DF,inactive_Larger_ACL_DF,tablefmt='psql',showindex=False))

    return Config_Change


##=============================================================================================================================
## ____  ____  ____  __  __  ____  ____    ___  ____   ___      __    _  _  _  _
##(  _ \( ___)(  _ \(  \/  )(_  _)(_  _)  / __)(  _ \ / __)    /__\  ( \( )( \/ )
## )___/ )__)  )   / )    (  _)(_   )(    \__ \ )   /( (__    /(__)\  )  (  \  /
##(__)  (____)(_)\_)(_/\/\_)(____) (__)   (___/(_)\_) \___)  (__)(__)(_)\_) (__)

def Permit_Src_Any(t_device, Config_Change, log_folder):
    from tabulate import tabulate
    from Network_Calc import Sub_Mask_2
    import shelve
    import pandas as pd
#    import ipaddress


    LARGER_PREFIX = 20

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']

    text = ('Permit|Deny * Any * @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    Permit_to_Any = []
    Not_Applied_ACL = []
    Inactive_ACL = []
    Larger_ACL = []
    inactive_Larger_ACL = []
##    DF_Filter_1 = ('Action == "permit" & "%s" in Dest' %('any'))
##    DF_Filter_2 = ('Action == "permit" & "%s" in Dest' %('any4'))
    DF_Filter_1 = ('"%s" in Source' %('any'))
    DF_Filter_2 = ('"%s" in Source' %('any4'))

    BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List_Dict.keys())
    for t_key in list(ACL_List_Dict.keys()):

        LOOP_INDEX = LOOP_INDEX + 1
        if LOOP_INDEX > (ITEMS/STEPS)*BINS:
            print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1

        t_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(ACL_List_Dict[t_key])
        temp1 = t_ACL_Lines_DF.query(DF_Filter_1)
        if len(temp1) > 0:
            Permit_to_Any.append(t_key)
        temp2 = t_ACL_Lines_DF.query(DF_Filter_2)
        if len(temp2) > 0:
            Permit_to_Any.append(t_key)

        for row_index, row in t_ACL_Lines_DF.iterrows():
            Dest_Item = row.Source
            if 'host' not in Dest_Item:
                if 'range' not in Dest_Item:
                    if 'any' not in Dest_Item:
                        try:
                            Dest_SubMask = Sub_Mask_2[Dest_Item.split()[1]].replace('/','')
                        except:
                            continue
                        if int(Dest_SubMask) <= LARGER_PREFIX:
                            if 'inactive' in row.Inactive:
                                if t_key not in inactive_Larger_ACL:
                                    inactive_Larger_ACL.append(t_key)
                            elif t_key not in Larger_ACL:
                                Larger_ACL.append(t_key)

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Unused_ACL_List')
    with shelve.open(tf_name) as shelve_obj: Unused_ACL_List = shelve_obj['0']
    Permit_to_Any_DF = utils_v2.ASA_ACL_to_DF(Permit_to_Any)
    for row_index, row in Permit_to_Any_DF.iterrows():
        if row.Name in Unused_ACL_List:
            #Not_Applied_ACL.append(' '.join(row))
            Not_Applied_ACL.append(row)
            Permit_to_Any_DF = Permit_to_Any_DF.drop(row_index)
        elif 'inactive' in row.Inactive:
            #Inactive_ACL.append(' '.join(row))
            Inactive_ACL.append(row)
            Permit_to_Any_DF = Permit_to_Any_DF.drop(row_index)

    col_names = ['ACL', 'Name', 'Line', 'Type', 'Action', 'Service', 'Source', 'S_Port','Dest','D_Port','Rest','Inactive','Hitcnt','Hash']
    Config_Change.append(tabulate(Permit_to_Any_DF,Permit_to_Any_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n Dangerous inactive ACL\n')
    #Inactive_ACL_DF = utils_v2.ASA_ACL_to_DF(Inactive_ACL)
    Inactive_ACL_DF = pd.DataFrame(Inactive_ACL, columns = col_names)
    Config_Change.append(tabulate(Inactive_ACL_DF,Inactive_ACL_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n Dangerous not applied ACL\n')
    #Not_Applied_ACL_DF = utils_v2.ASA_ACL_to_DF(Not_Applied_ACL)
    Not_Applied_ACL_DF = pd.DataFrame(Not_Applied_ACL, columns = col_names)
    Config_Change.append(tabulate(Not_Applied_ACL_DF,Not_Applied_ACL_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n ACL with Source Larger than \\%s\n' %LARGER_PREFIX)
    Larger_ACL_DF = utils_v2.ASA_ACL_to_DF(Larger_ACL)
    Config_Change.append(tabulate(Larger_ACL_DF,Larger_ACL_DF,tablefmt='psql',showindex=False))
    Config_Change.append('\n Dangerous Inactive ACL with Source Larger than \\%s\n' %LARGER_PREFIX)
    inactive_Larger_ACL_DF = utils_v2.ASA_ACL_to_DF(inactive_Larger_ACL)
    Config_Change.append(tabulate(inactive_Larger_ACL_DF,inactive_Larger_ACL_DF,tablefmt='psql',showindex=False))

    return Config_Change


##=============================================================================================================================
## ____  ____    ____  _____  ____      __    ___  __
##(  _ \(  _ \  ( ___)(  _  )(  _ \    /__\  / __)(  )
## )(_) )) _ <   )__)  )(_)(  )   /   /(__)\( (__  )(__
##(____/(____/  (__)  (_____)(_)\_)  (__)(__)\___)(____)

def DB_For_ACL(t_device, Config_Change, log_folder):
    from tabulate import tabulate
    #from Network_Calc import Sub_Mask_2
    import shelve
    import time
    import re
    import pandas as pd
    import sqlalchemy as db

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices      = db.Table('My_Devices',      db.MetaData(), autoload_with=engine)
            ACL_GROSS       = db.Table('ACL_GROSS',       db.MetaData(), autoload_with=engine)
            Global_Settings = db.Table('Global_Settings', db.MetaData(), autoload_with=engine)
            WTF_Log         = db.Table('WTF_Log',         db.MetaData(), autoload_with=engine)
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

##    Max_ACL_HitCnt0_Age  = 180 #days
##    Max_ACL_Inactive_Age = 180 #days
##    Min_Hitcnt_Threshold = 20  #sotto questo numero la ACL è in dubbio
##    N_ACL_Most_Triggered = 10  #numero di regole a maggiore hit che vengono visualizzate
##    Max_ACL_Expand_Ratio = 100

    if DB_Available:
        query = db.select(Global_Settings).where(Global_Settings.c.Name=='Global_Settings')
        with engine.connect() as connection:
            Global_Settings_df = pd.DataFrame(connection.execute(query).fetchall())
        query = db.select(My_Devices).where(My_Devices.c.HostName=="%s" %hostname___)
        with engine.connect() as connection:
            Device_to_Check_df = pd.DataFrame(connection.execute(query).fetchall())
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

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_remark_Lines')
    with shelve.open(tf_name) as shelve_obj: ACL_remark_Lines = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_if')
    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_if = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines_DF')
    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']

##    --------- this section has been moved to ASA_CHECK_CONFIG_VAR.PY ---------
##    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_List_Dict')
##    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
##    # ---------- Check for too large Expanded ACLs ---------- #
##    #Expanded_ACL_List = [['X_Lines', 'ACL']]
##    Expanded_ACL_List = []
##    for t_key in ACL_List_Dict.keys():
##        if len(ACL_List_Dict[t_key]) >= Max_ACL_Expand_Ratio:
##            Expanded_ACL_List.append([len(ACL_List_Dict[t_key]), t_key])
##    Expanded_ACL_df = pd.DataFrame(Expanded_ACL_List, columns = ['X_Lines' , 'ACL'])
##    Expanded_ACL_df = Expanded_ACL_df.sort_values('X_Lines', ascending = (False))
##    Config_Change.append('--- The Following ACL lines expanded greater than %s ---' %Max_ACL_Expand_Ratio)
##    Config_Change.append(tabulate(Expanded_ACL_df,Expanded_ACL_df,tablefmt='psql',showindex=False))


    ACL_Lines_DF = Show_ACL_Lines_DF
    for row in ACL_Lines_DF.itertuples(): #sto facendo i controlli solo sulle ACL applicate ad interfacce
        if row.Name not in list(Accessgroup_Dic_by_if.values()):
            ACL_Lines_DF = ACL_Lines_DF.drop(row.Index)

    today = datetime.datetime.now().strftime('%Y-%m-%d')
    if DB_Available:
        query = db.select(ACL_GROSS).where(ACL_GROSS.columns.HostName=="%s" %hostname___)
        with engine.connect() as connection:
            ACL_GROSS_db = pd.DataFrame(connection.execute(query).fetchall())

    if len(ACL_GROSS_db) == 0: # New Device
        print('Device not in DB... writing %s lines' %len(ACL_Lines_DF))
        Config_Change.append('Device not in DB... writing %s lines' %len(ACL_Lines_DF))
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
            with engine.begin() as connection:
                result = connection.execute(insert_stmt)
            #print(f"{result.rowcount} row(s) inserted.")

        # make empty report files:
        Watch_FName   = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Watch.html'
        Watch_FName_2 = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Watch_2.html'
        Fix_FName     = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Fix.html'
        #Merge_FName   = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Merge.txt'
        Write_Think_File(Watch_FName,   ['\n'])
        Write_Think_File(Watch_FName_2, ['\n'])
        Write_Think_File(Fix_FName,     ['\n'])
        #Write_Think_File(Merge_FName,   ['\n'])

        Watch_FName   = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Watch.html'
        Watch_FName_2 = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Watch_2.html'
        Fix_FName     = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Fix.html'
        #Merge_FName   = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Merge.txt'
        Write_Think_File(Watch_FName,   ['\n'])
        Write_Think_File(Watch_FName_2, ['\n'])
        Write_Think_File(Fix_FName,     ['\n'])
        #Write_Think_File(Merge_FName,   ['\n'])

    else:
        #ACL_GROSS_db.columns = ['ID','HostName','First_Seen','Name','Line','Type','Action','Service','Source','S_Port','Dest','D_Port','Rest','Inactive','Hitcnt','Hash','Delta_HitCnt']
        ACL_GROSS_db = ACL_GROSS_db.drop(labels='ID', axis=1)
        t_today = datetime.date(int(today.split('-')[0]),int(today.split('-')[1]),int(today.split('-')[2]))

        #print('line 3886')
        #print(datetime.datetime.now())
        N_ACL_Lines = ACL_Lines_DF.shape[0]
        BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = N_ACL_Lines
        for row in ACL_Lines_DF.itertuples():
##            if '0x0c5aaf87' in row.Hash:
##                print('stop')
            LOOP_INDEX = LOOP_INDEX + 1
            if LOOP_INDEX > (ITEMS/STEPS)*BINS:
                print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1
            t_hash = row.Hash
            #Bool_check = ('Hash == "%s"' %(t_hash))
            Bool_check = (('Name=="%s" & Action=="%s" & Service=="%s"& Source=="%s" & Dest=="%s" & D_Port=="%s" & Hash=="%s"') %(row.Name, row.Action, row.Service, row.Source, row.Dest, row.D_Port, row.Hash))
            t_ACL_GROSS_db = (ACL_GROSS_db.query(Bool_check))

            # there can not be two identical ACL lines
            if len(t_ACL_GROSS_db) > 1:
                Log_Message = (f'@ ACL_GROSS for {hostname} has to be cleaned'); print(Log_Message); Config_Change.append(Log_Message)
                row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
                with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
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
                with engine.begin() as connection:
                    result = connection.execute(insert_stmt)
                #print(f"{result.rowcount} row(s) inserted.")

            else:
                # controllo se Hitcnt si è incrementato
                try:
                    if int(row.Hitcnt) > int(t_ACL_GROSS_db.Hitcnt):
                        pass
                except:
                    print('ERROR Triggered in DB_For_ACL ...int(t_ACL_GROSS_db.Hitcnt)... ----------------------------------------------------------------------------')
                    for n in t_ACL_GROSS_db:
                        print(n)

                if int(row.Hitcnt) > int(t_ACL_GROSS_db.Hitcnt):
                    if int(row.Hitcnt)-int(t_ACL_GROSS_db.Hitcnt) <= Min_Hitcnt_Threshold:
                        temp_few_hitcnt.append('\n%s Hitcount in %s days' %(int(row.Hitcnt)-int(t_ACL_GROSS_db.Hitcnt), (t_today-t_ACL_GROSS_db.First_Seen.item()).days))
                        t_line = 'access-list %s %s %s %s %s %s %s %s %s %s %s' %(row.Name, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Hitcnt, row.Hash)
                        t_line = re_space.sub(' ',t_line)
                        temp_few_hitcnt.append(t_line)

                    N_of_ACL_Incremented += 1
                    #print('ACL con Hitcount incrementato, aggiorno DB')
                    # aggiorno i dati sul DB
                    Delta = int(row.Hitcnt) - int(t_ACL_GROSS_db.Hitcnt)
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
                    with engine.begin() as connection:
                        results = connection.execute(query)
                    #print(f"{results.rowcount} row(s) updated.")

                elif int(row.Hitcnt) == int(t_ACL_GROSS_db.Hitcnt):
                    t_Days = (t_today-t_ACL_GROSS_db.First_Seen.item()).days
                    t_line = 'access-list %s %s %s %s %s %s %s %s %s %s %s (hitcnt=%s) %s' %(row.Name, row.Line, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest, row.Inactive, row.Hitcnt, row.Hash)
                    t_line = re_space.sub(' ',t_line)
                    t_line_clean = 'access-list %s %s %s %s %s %s %s %s %s inactive' %(row.Name, row.Type, row.Action, row.Service, row.Source, row.S_Port, row.Dest, row.D_Port, row.Rest)
                    t_line_clean = re_space.sub(' ',t_line_clean)

                    if 'inactive' in row.Inactive:
                        # check if to be deleted
                        if t_Days >= Max_ACL_Inactive_Age:
                            # --- Max_ACL_Inactive_Age expired => delete it ---
                            # Check line before if is a remark
                            tmp_line = 'access-list %s line %s remark ' %(row.Name, str(int(row.Line.split()[1])-1))
                            for t_ACL_remark_Lines in ACL_remark_Lines:
                                if t_ACL_remark_Lines.startswith(tmp_line):
                                    temp_no_inactive.append(['',t_ACL_remark_Lines])
                                    Fix_FList_Inactive.append('no %s' %(t_ACL_remark_Lines))
                            temp_no_inactive.append([t_Days, t_line])
                            Fix_FList_Inactive.append('no %s' %(t_line_clean))
                            N_temp_no_inactive += 1
                        else:
                            # Max_ACL_Inactive_Age not expired => Report it
                            #temp_inactive_below.append(['%s' %(t_Days), '%s' %(t_line)])
                            temp_inactive_below.append([t_Days, t_line])
                            N_temp_inactive_below += 1
                    else:
                        # check if to make inactive
                        if row.Action.lower() == 'deny':
                            continue
                        elif t_Days >= Max_ACL_HitCnt0_Age:
                            # Max_ACL_HitCnt0_Age expired => turn it to inactive
                            #temp_yo_inactive.append(['%s' %(t_Days), '%s (hitcnt=%s)' %(t_line.replace(' inactive',''), t_ACL_GROSS_db.Hitcnt.item())])
                            temp_yo_inactive.append([t_Days, '%s' %(t_line)])
                            Fix_FList_DeltaHit0.append(t_line_clean)
                            N_temp_yo_inactive += 1
                        else:
                            # Max_ACL_HitCnt0_Age not expired => Report it
                            t_line = t_line.replace(' inactive', '')
                            #temp_yo_inactive_below.append(['%s' %(t_Days), '%s' %(t_line)])
                            temp_yo_inactive_below.append([t_Days, t_line])
                            N_temp_yo_inactive_below += 1

                    # aggiorno DB
                    Delta = 0
##                    Updated_Vals = dict(
##                                        Line        = row.Line,
##                                        Inactive    = row.Inactive,
##                                        Delta_HitCnt= Delta,
##                                        Rest        = row.Rest
##                                        )
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
                    with engine.begin() as connection:
                        results = connection.execute(query)
                    #print(f"{results.rowcount} row(s) updated.")
                else:
                    # contatori resettati, aggiorno db
                    N_of_ACL_Resetted += 1
                    t_line = ['access-list',row.Name,row.Line,row.Type,row.Action,row.Service,row.Source,row.S_Port,row.Dest,row.D_Port,row.Rest,row.Inactive,row.Hitcnt,row.Hash]
                    t_line = ' '.join(t_line)
                    t_line = re_space.sub(' ',t_line)
                    Config_Change.append(t_line)
                    Config_Change.append('Hitcount resetted for ACL, updating DB...')
                    # aggiorno la data sul DB
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
                    with engine.begin() as connection:
                        results = connection.execute(query)
                    #print(f"{results.rowcount} row(s) updated.")

        #print('line 4002')
        #print(datetime.datetime.now())
        N_ACL_Inactive = N_temp_no_inactive + N_temp_inactive_below
        N_active_ACL_Lines = N_ACL_Lines - N_ACL_Inactive
        Watch_FList = []
        Watch_FName   = hostname___ + '-Inactive_ACL-Watch.html'
        Watch_FName_2 = hostname___ + '-Inactive_ACL-Watch_2.html'
        Fix_FName   = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Fix.html'
        #Merge_Flist = []
        #Merge_FName = FW_log_folder + '/' + hostname___ + '-Inactive_ACL-Merge.txt'
        #Merge_Flist.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        #Merge_Flist.append('!')

        #if len(temp_no_inactive) > 0:   # inactive lines to be deleted
        percent = round(len(temp_no_inactive)/N_ACL_Lines*100,2) if N_ACL_Lines else 0
        t_line = ('--- %s ACL over %s can be removed (%s%%) ---' %(N_temp_no_inactive, N_ACL_Lines, percent))
        temp_no_inactive_DF = pd.DataFrame(temp_no_inactive, columns = ['Days', 'Line'])
        Watch_FList.append(tabulate(temp_no_inactive_DF,temp_no_inactive_DF,tablefmt='psql',showindex=False))

        if not os.path.exists(html_folder):
            try:
                os.mkdir(html_folder)
            except:
                Config_Change.append("Can't create destination directory (%s)!" % (html_folder))
                raise OSError("Can't create destination directory (%s)!" % (html_folder))

        try:
            with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
                html_file.write('<div class="card-body">\n')
                html_file.write('''
                   <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n
                   ''')
                my_index = 0
                N_Cols = temp_no_inactive_DF.shape[1]
                html_file.write('       <thead><tr>\n')
                for t_col_index in range(0,N_Cols):
                    html_file.write('           <th>%s</th>\n' %temp_no_inactive_DF.columns[t_col_index])
                html_file.write('       </tr></thead>\n')
                html_file.write('       <tbody>\n')
                for row in temp_no_inactive_DF.itertuples():
                    html_file.write('       <tr>\n')
                    for t_col_index in range(0,N_Cols):
                        #print('row.Index = %s' %row.Index)
                        #print('t_col_index = %s' %t_col_index)
                        t_line = temp_no_inactive_DF.iloc[row.Index][t_col_index]
                        if t_col_index == N_Cols-1:
                            t_line = utils_v2.Color_Line(t_line)
                            html_file.write('           <td>%s</td>\n' %t_line)
                        else:
                            html_file.write('           <td>%s</td>\n' %t_col_index)
                    html_file.write('       </tr>\n')
                html_file.write('       </tbody>\n')
                html_file.write('   </table>\n')
                html_file.write('</div>\n')

            print('... saved file "%s/%s" '%(html_folder,Watch_FName))
        except:
            raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

        Write_Think_File(Fix_FName, Fix_FList_Inactive)
##        for n in Watch_FList: Merge_Flist.append(n)
##        Merge_Flist.append('!')
##        for n in Fix_FList_Inactive: Merge_Flist.append(n)
##        Merge_Flist.append('!')
##        with open(Merge_FName, "w") as f:
##            f.write('\n'.join(Merge_Flist))


        #if len(temp_inactive_below) > 0:
        percent = round(len(temp_inactive_below)/N_ACL_Lines*100,2) if N_ACL_Lines else 0
        t_line = ('--- %s ACL over %s Still aging (%s%%) ---' %(len(temp_inactive_below), N_ACL_Lines, percent))
        temp_inactive_below_DF = pd.DataFrame(temp_inactive_below, columns = ['Days', 'Line'])

        try:
            with open("%s/%s"%(html_folder,Watch_FName_2),mode="w") as html_file:
                html_file.write('<div class="card-body">\n')
                html_file.write('''
                   <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n
                   ''')
                my_index = 0
                N_Cols = temp_inactive_below_DF.shape[1]
                html_file.write('       <thead><tr>\n')
                for t_col_index in range(0,N_Cols):
                    html_file.write('           <th>%s</th>\n' %temp_inactive_below_DF.columns[t_col_index])
                html_file.write('       </tr></thead>\n')
                html_file.write('       <tbody>\n')
                for row in temp_inactive_below_DF.itertuples():
                    html_file.write('       <tr>\n')
                    for t_col_index in range(0,N_Cols):
                        #print('row.Index = %s' %row.Index)
                        #print('t_col_index = %s' %t_col_index)
                        t_line = temp_inactive_below_DF.iloc[row.Index][t_col_index]
                        if t_col_index == N_Cols-1:
                            t_line = utils_v2.Color_Line(t_line)
                            html_file.write('           <td>%s</td>\n' %t_line)
                        else:
                            html_file.write('           <td>%s</td>\n' %t_line)
                    html_file.write('       </tr>\n')
                html_file.write('       </tbody>\n')
                html_file.write('   </table>\n')
                html_file.write('</div>\n')

            print('... saved file "%s/%s" '%(html_folder,Watch_FName_2))
        except:
            raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName_2))

        Watch_FList = []
        Watch_FName   = hostname___ + '-Deltahitcnt0_ACL-Watch.html'
        Watch_FName_2 = hostname___ + '-Deltahitcnt0_ACL-Watch_2.html'
        Fix_FName   = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Fix.html'
##        Merge_Flist = []
##        Merge_FName = FW_log_folder + '/' + hostname___ + '-Deltahitcnt0_ACL-Merge.txt'
##        Merge_Flist.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
##        Merge_Flist.append('!')

        #if len(temp_yo_inactive) > 0:
        percent = round(len(temp_yo_inactive)/N_active_ACL_Lines*100,2) if N_active_ACL_Lines else 0
        temp_yo_inactive_DF = pd.DataFrame(temp_yo_inactive, columns = ['Days', 'Line'])
        Watch_FList.append(tabulate(temp_yo_inactive_DF,temp_yo_inactive_DF,tablefmt='psql',showindex=False))

        if not os.path.exists(html_folder):
            try:
                os.mkdir(html_folder)
            except:
                Config_Change.append("Can't create destination directory (%s)!" % (html_folder))
                raise OSError("Can't create destination directory (%s)!" % (html_folder))

        try:
            with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
                html_file.write('<div class="card-body">\n')
                html_file.write('''
                   <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n
                   ''')
                my_index = 0
                N_Cols = temp_yo_inactive_DF.shape[1]
                html_file.write('       <thead><tr>\n')
                for t_col_index in range(0,N_Cols):
                    html_file.write('           <th>%s</th>\n' %temp_yo_inactive_DF.columns[t_col_index])
                html_file.write('       </tr></thead>\n')
                html_file.write('       <tbody>\n')
                for row in temp_yo_inactive_DF.itertuples():
                    html_file.write('       <tr>\n')
                    for t_col_index in range(0,N_Cols):
                        #print('row.Index = %s' %row.Index)
                        #print('t_col_index = %s' %t_col_index)
                        t_line = temp_yo_inactive_DF.iloc[row.Index][t_col_index]
                        if t_col_index == N_Cols-1:
                            t_line = utils_v2.Color_Line(t_line)
                            html_file.write('           <td>%s</td>\n' %t_line)
                        else:
                            html_file.write('           <td>%s</td>\n' %t_line)
                    html_file.write('       </tr>\n')
                html_file.write('       </tbody>\n')
                html_file.write('   </table>\n')
                html_file.write('</div>\n')

            print('... saved file "%s/%s" '%(html_folder,Watch_FName))
        except:
            raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

        Write_Think_File(Fix_FName, Fix_FList_DeltaHit0)
##        for n in Watch_FList: Merge_Flist.append(n)
##        Merge_Flist.append('!')
##        for n in Fix_FList_DeltaHit0: Merge_Flist.append(n)
##        Merge_Flist.append('!')
##        with open(Merge_FName, "w") as f:
##            f.write('\n'.join(Merge_Flist))

        #if len(temp_yo_inactive_below) > 0:
        percent = round(len(temp_yo_inactive_below)/N_active_ACL_Lines*100,2) if N_active_ACL_Lines else 0
        temp_yo_inactive_below_DF = pd.DataFrame(temp_yo_inactive_below, columns = ['Days', 'Line'])

        try:
            with open("%s/%s"%(html_folder,Watch_FName_2),mode="w") as html_file:
                html_file.write('<div class="card-body">\n')
                html_file.write('''
                   <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n
                   ''')
                my_index = 0
                N_Cols = temp_yo_inactive_below_DF.shape[1]
                html_file.write('       <thead><tr>\n')
                for t_col_index in range(0,N_Cols):
                    html_file.write('           <th>%s</th>\n' %temp_yo_inactive_below_DF.columns[t_col_index])
                html_file.write('       </tr></thead>\n')
                html_file.write('       <tbody>\n')
                for row in temp_yo_inactive_below_DF.itertuples():
                    html_file.write('       <tr>\n')
                    for t_col_index in range(0,N_Cols):
                        #print('row.Index = %s' %row.Index)
                        #print('t_col_index = %s' %t_col_index)
                        t_line = temp_yo_inactive_below_DF.iloc[row.Index][t_col_index]
                        if t_col_index == N_Cols-1:
                            t_line = utils_v2.Color_Line(t_line)
                            html_file.write('           <td>%s</td>\n' %t_line)
                        else:
                            html_file.write('           <td>%s</td>\n' %t_line)
                    html_file.write('       </tr>\n')
                html_file.write('       </tbody>\n')
                html_file.write('   </table>\n')
                html_file.write('</div>\n')

            print('... saved file "%s/%s" '%(html_folder,Watch_FName_2))
        except:
            raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName_2))



        if len(temp_few_hitcnt) > 0:
            Config_Change.append('\n\n!--- Too Few Hitcount for the following ACL (threshold at %s) ---' %Min_Hitcnt_Threshold)
            for n in temp_few_hitcnt:
                Config_Change.append(n)

        # remove ldeleted ines from DB -------------------------------
        Header_Printed = False
        for row in ACL_GROSS_db.itertuples():
            t_hash = row.Hash
            #Bool_check = ('Hash == "%s"' %(t_hash))
            Bool_check = (('Name=="%s" & Action=="%s" & Service=="%s"& Source=="%s" & Dest=="%s" & D_Port=="%s" & Hash=="%s"') %(row.Name, row.Action, row.Service, row.Source, row.Dest, row.D_Port, row.Hash))
            t_ACL_Lines_DF = ACL_Lines_DF.query(Bool_check)
            if len(t_ACL_Lines_DF) == 0: # ACL LINE is no longer in config
                N_of_ACL_Deleted += 1
                if Header_Printed == False:
                    Config_Change.append('\n!--- ACL removed from DB ---')
                    print('\n!--- ACL removed from DB ---')
                    Header_Printed = True
                #delete_stmt = db.delete(ACL_GROSS).where(db.and_(ACL_GROSS.c.HostName==hostname___, ACL_GROSS.c.Hash==row.Hash))
                delete_stmt = db.delete(ACL_GROSS).where(db.and_(ACL_GROSS.c.HostName==hostname___,
                                                                 ACL_GROSS.c.Name==row.Name,
                                                                 ACL_GROSS.c.Action==row.Action,
                                                                 ACL_GROSS.c.Service==row.Service,
                                                                 ACL_GROSS.c.Source==row.Source,
                                                                 ACL_GROSS.c.Dest==row.Dest,
                                                                 ACL_GROSS.c.D_Port==row.D_Port,
                                                                 ACL_GROSS.c.Hash==row.Hash))
                with engine.begin() as connection:
                    result = connection.execute(delete_stmt)
                print(f"{result.rowcount} row(s) deleted.")
                t_line = ['access-list',row.Name,row.Line,row.Type,row.Action,row.Service,row.Source,row.S_Port,row.Dest,row.D_Port,row.Rest,row.Inactive,row.Hitcnt,row.Hash]
                ACL_Deleted_List.append(' '.join(t_line))
                #Config_Change.append(' '.join(t_line))
                #print(' '.join(t_line))

    # canellare unmatched entry da db

        #Bool_check = ('Action == "deny" & "%s" in Source & "%s" in Dest' %('any','any'))
        #temp = Show_ACL_Lines_DF.query(Bool_check)

##    if hostname not in ACL_GROSS_df[1].unique():
##        pass

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
        #print(f"{results.rowcount} row(s) updated.")

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
    #ACL_GROSS_db.columns = ['ID','HostName','First_Seen','Name','Line','Type','Action','Service','Source','S_Port','Dest','D_Port','Rest','Inactive','Hitcnt','Hash','Delta_HitCnt']

    Deny_ACL_Triggering_TooMuch = []
    if ACL_GROSS_db.shape[0] > 0:
        ACL_GROSS_db = ACL_GROSS_db.drop(labels='ID', axis=1)
        ACL_Names = list(ACL_GROSS_db.Name.unique())
        #print('line5')
        #print(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
        ACL_Names.sort()
        #print('line6')
        #print(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    ##    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_if')
    ##    with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_if = shelve_obj['0']

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

    ##        temp_df['#'] = temp_df['Line'].apply(lambda x: int(x.split()[1]))
            ttt = temp_df.sort_values('#')
            temp_df = ttt.reset_index()
            temp_df.drop(labels='index', axis=1)
            temp_df = temp_df.sort_values('Delta_HitCnt',ascending=False)

            #Config_Change.append('\n --- access-list %s has %s rows---' %(t_ACL,temp_df_NRows))
            Most_Hitted_ACL[t_ACL,temp_df_NRows] = []

            t_Processed_ACLs = 0
            Incremental_Line = 1

            for row in temp_df.itertuples():
                if t_Processed_ACLs == N_ACL_Most_Triggered:
                    break

                if row.Delta_HitCnt > 0:
                    #print("{:>10}".format("TEST"))
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
                        #Config_Change.append("{:<25}| {:>6} | {:<10}".format(t0_line, t1_line, t2_line))
                        temp_item_4_MHACL.append(row.Delta_HitCnt)
                        temp_item_4_MHACL.append(percent)
                        temp_item_4_MHACL.append(t2_line)
                        ##Most_Hitted_ACL[t_ACL,temp_df_NRows].append([row.Delta_HitCnt, percent, t2_line])
                        #print("{:<25}| {:>6} | {:<10}".format(t0_line, t1_line, t2_line))
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
                                ##Most_Hitted_ACL[t_ACL,temp_df_NRows].append('Line can not be moved...')
                            else:
                                Temp_Config_Change.append('can be moved up to line %s' %max(Incremental_Line,(Move_to_Line+1)))
                                temp_item_4_MHACL.append('Move to line %s' %max(Incremental_Line,(Move_to_Line+1)))
                                ##Most_Hitted_ACL[t_ACL,temp_df_NRows].append('can be moved up to line %s' %max(Incremental_Line,(Move_to_Line+1)))
                            if (Incremental_Line >= Move_to_Line+1):
                                Incremental_Line += 1
                        Temp_Shadow_List = []
                        for n in out_fnc:
                            Temp_Config_Change.append(n)
                            Temp_Shadow_List.append(n)
                        temp_item_4_MHACL.append(Temp_Shadow_List)
                        ##Most_Hitted_ACL[t_ACL,temp_df_NRows].append(Temp_Shadow_List)
                        Most_Hitted_ACL[t_ACL,temp_df_NRows].append(temp_item_4_MHACL)

    ##                        if True:
    ##                            [Move_to_Line, out_fnc] = Check_Dec_Shadowing(t_device, t2_line, FW_log_folder)
    ##                            Temp_Config_Change.append('\n---'  + t2_line)
    ##                            for n in out_fnc:
    ##                                Temp_Config_Change.append(n)
    ##                            if Move_to_Line != -1:
    ##                                Temp_Config_Change.append('can be moved up to line %s' %(Move_to_Line+1))
    ##                        else:
    ##                            Move_to_Line = (Check_Shadowing(t_device, t2_line, FW_log_folder))[0]
    ##                            Temp_Config_Change.append('---'  + t2_line)
    ##                            for n in (Check_Shadowing(t_device, t2_line, FW_log_folder))[1]:
    ##                                Temp_Config_Change.append(n)
    ##                            Temp_Config_Change.append('can be moved up to line %s' %(Move_to_Line+1))

                        #print('can be moved up to line %s' %(Move_to_Line+1))
                    #Config_Change.append(tabulate([t0_line,t1_line],[t0_line,t1_line]],tablefmt='psql',showindex=False))
                    t_Processed_ACLs += 1


    # OUTPUT HTML FILE for Most_Hitted_ACL-Watch
    t_html_file = ['\n']
    if ACL_GROSS_db.shape[0] > 0:
        t_all_zero = []
        for t_key in Most_Hitted_ACL.keys():
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
        if sum(t_all_zero) == len(Most_Hitted_ACL.keys()):
                t_html_file.append('\n This is based on the Delta HitCnt from the previous run.<br> It needs a second run to be populated.<br>')

    Watch_FName = hostname___ + '-Most_Hitted_ACL-Watch.html'
    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))


    # OUTPUT HTML FILE for Most_Hitted_ACL-Think
    t_html_file = ['\n']
    if ACL_GROSS_db.shape[0] > 0:
        for t_key in Most_Hitted_ACL.keys():
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

                        #t_line = '<table class="table-bordered table-condensed table-striped" id="%s" width="100%%" cellspacing="0"  data-page-length="10" >\n' %table_id

                        t_line = '<table class="table-bordered table-condensed table-striped table-responsive" id="%s" width="100%%" cellspacing="0">\n' %table_id
                        t_html_file.append(t_line)
                        ##t_html_file.append('<table class="table-bordered table-condensed table-striped table-responsive" width="100%" cellspacing="0"  data-page-length="50" >\n')
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

    Watch_FName = hostname___ + '-Most_Hitted_ACL-Think.html'
    try:
        with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
        print('... saved file "%s/%s" '%(html_folder,Watch_FName))
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))


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

        #Config_Change.append('\n----- The Following deny rules are among the top... consider check who is -----')
        #Config_Change.append(tabulate(Deny_ACL_Triggering_TooMuch_df,Deny_ACL_Triggering_TooMuch_df,tablefmt='psql',showindex=False))

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

        Watch_FName = hostname___ + '-Deny_ACL_Triggering_TooMuch-Watch.html'
        try:
            with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
                for t in t_html_file:
                    html_file.write(t)
            print('... saved file "%s/%s" '%(html_folder,Watch_FName))
        except:
            raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))
    else: # nothing to write... clean it!
        Watch_FName = hostname___ + '-Deny_ACL_Triggering_TooMuch-Watch.html'
        try:
            with open("%s/%s"%(html_folder,Watch_FName),mode="w") as html_file:
                html_file.write('\n This is based on the Delta HitCnt from the previous run.<br> It needs a second run to be populated.')
            print('... saved file "%s/%s" '%(html_folder,Watch_FName))
        except:
            raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,Watch_FName))

##    for m in Temp_Config_Change:
##        Config_Change.append(m)

    engine.dispose()
    return Config_Change



##=============================================================================================================================
## ____  ____    ____  _____  ____    _____  ____   ____  ____  ___  ____      _  _  ____  ____
##(  _ \(  _ \  ( ___)(  _  )(  _ \  (  _  )(  _ \ (_  _)( ___)/ __)(_  _)    ( \( )( ___)(_  _)
## )(_) )) _ <   )__)  )(_)(  )   /   )(_)(  ) _ <.-_)(   )__)( (__   )(  ___  )  (  )__)   )(
##(____/(____/  (__)  (_____)(_)\_)  (_____)(____/\____) (____)\___) (__)(___)(_)\_)(____) (__)

def DB_For_OBJNET(t_device, Config_Change, log_folder):
    #from tabulate import tabulate
    #from Network_Calc import Sub_Mask_2
    import shelve
    import pandas as pd
    import sqlalchemy as db

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            OBJNET_db = db.Table('OBJNET', db.MetaData(), autoload_with=engine)
    except Exception as e:
        print(f"error is: {e}")
        print('DB not connected, some feature is unavailable\n')
        with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f:
            f.write('=================[ Warning ]==================')
            f.write('DB not connected, some feature is unavailable\n')
        DB_Available = False

    today = datetime.datetime.now().strftime('%Y-%m-%d')

    hostname___ = t_device.replace('/','___')
    hostname = t_device

    text = ('DB for Object Network @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    #read values from device
    FW_log_folder = log_folder + '/' + hostname___
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obejct_by_value_Dict')
    with shelve.open(tf_name) as shelve_obj: Obejct_by_value_Dict = shelve_obj['0']

    Obejct_by_value_Dict_one = {}
    Obejct_by_value_Dict_two = {}
    for t_key in Obejct_by_value_Dict.keys():
        if len(Obejct_by_value_Dict[t_key]) == 1:
            Obejct_by_value_Dict_one[t_key] = Obejct_by_value_Dict[t_key][0]
        else:
            Obejct_by_value_Dict_two[t_key] = Obejct_by_value_Dict[t_key]


    insert_New_Flag = False
    #read values from DB

    query = db.select(OBJNET_db)
    with engine.connect() as connection:
        OBJNET_db_df = pd.DataFrame(connection.execute(query).fetchall())

    if len(OBJNET_db_df) == 0:
        # New DB
        for t_key in Obejct_by_value_Dict_one.keys():
            New_Vals = dict(
                            Obj_Value = t_key,
                            Obj_Name  = Obejct_by_value_Dict_one[t_key],
                            Last_Seen = today
            )
            insert_stmt = OBJNET_db.insert().values(**New_Vals)
            with engine.begin() as connection:
                connection.execute(insert_stmt)

        query = db.select(OBJNET_db)
        with engine.connect() as connection:
            OBJNET_db_df = pd.DataFrame(connection.execute(query).fetchall())

# per tutte gli oggetti in Obejct_by_value_Dict:
    # se sono lunghi "1":
        #se entry presente in DB:
            # se no la inserisce
            # se si, è uguale?
                # si = aggiorna "Last_Seen"
                # no = inseriscila nel file excel
    # else:
        # inseriscila nel file excel

##Obj_Value   = text (key)
##Obj_Name    = text
##Last_Seen   = date

    N_of_OBJ_new4db = 0
    N_of_OBJ_double = 0
    N_of_OBJ_del4db = 0
    N_of_OBJ_allok  = 0
    Out_Excel_ls = []
    #Out_Excel_ls.columns = ['Obj_Value', 'Obj_Name_from_db', '1_Obj_Name_from_Device', '2_Obj_Name_from_Device', ...]

    for t_key in Obejct_by_value_Dict_one.keys():
        Bool_check = ('Obj_Value == "%s"' %(t_key))
        t_OBJNET_db_df = OBJNET_db_df.query(Bool_check)
        if len(t_OBJNET_db_df) == 0:
            # object nuovo per db
            # t_OBJNET_db_df.loc[-1] = [t_key, Obejct_by_value_Dict_one[t_key]]
            New_Vals = dict(
                            Obj_Value = t_key,
                            Obj_Name  = Obejct_by_value_Dict_one[t_key],
                            Last_Seen = today
            )
            insert_stmt = OBJNET_db.insert().values(**New_Vals)
            with engine.begin() as connection:
                connection.execute(insert_stmt)
            N_of_OBJ_new4db += 1

        elif len(t_OBJNET_db_df) == 1:
            if (Obejct_by_value_Dict_one[t_key] == list(t_OBJNET_db_df.Obj_Name)[0]):
                N_of_OBJ_allok += 1 # stesso valore
                query = db.update(OBJNET_db).values(Last_Seen=today).where(OBJNET_db.columns.Obj_Value==t_key)
                with engine.begin() as connection:
                    results = connection.execute(query)
            else:
                N_of_OBJ_double += 1
                Out_Excel_ls.append([t_key, list(t_OBJNET_db_df.Obj_Name)[0], Obejct_by_value_Dict_one[t_key]])
        else:
            print('ERRORE NON GESTITO IN DB_For_OBJNET')
            exit(123)
    Config_Change.append('Number of New    Object Network for DB = %s' %N_of_OBJ_new4db)
    Config_Change.append('Number of Double Object Network for DB = %s' %N_of_OBJ_double)
    Config_Change.append('Number of Same   Object Network for DB = %s' %N_of_OBJ_allok)
    print('Number of New    Object Network for DB = %s' %N_of_OBJ_new4db)
    print('Number of Double Object Network for DB = %s' %N_of_OBJ_double)
    print('Number of Same   Object Network for DB = %s' %N_of_OBJ_allok)

    for t_key in Obejct_by_value_Dict_two.keys():
        temp = [t_key, '']
        for m in Obejct_by_value_Dict_two[t_key]:
            temp.append(m)
        Out_Excel_ls.append(temp)

    Out_Excel_df = pd.DataFrame(Out_Excel_ls)
    cols_Header = ['Obj_Value', 'Obj_Name_from_db']
    for col_length in range(1, Out_Excel_df.shape[1]-1):
        cols_Header.append(str(col_length) + '_Obj_Name_from_Device')
    if Out_Excel_df.shape[0] > 0:
        Out_Excel_df.columns = cols_Header
        Out_Excel_df.insert(1,'Target_Name','')
    else:
        Out_Excel_df['Obj_Value'] = ''
        Out_Excel_df['Obj_Name_from_db'] = ''
        Out_Excel_df['Target_Name'] = ''


    Excel_IP_Report_FileName = hostname___ + '_DB_For_OBJNET' + '.xlsx'
    writer = pd.ExcelWriter(Excel_IP_Report_FileName)
    Out_Excel_df.to_excel(writer, sheet_name='OBJNET', index=False)
    writer.close()
    print ('Saving "%s" ...' %Excel_IP_Report_FileName)
    Config_Change.append('Saving "%s" ...' %Excel_IP_Report_FileName)

    engine.dispose()
    return Config_Change

# gestire come cancellare le entry dal DB ------------------


## ---------------------------------------------------------------------------
## ____  ____  _  _    __    __  __  ____    _____  ____   ____  ____  ___  ____      _  _  ____  ____
##(  _ \( ___)( \( )  /__\  (  \/  )( ___)  (  _  )(  _ \ (_  _)( ___)/ __)(_  _)    ( \( )( ___)(_  _)
## )   / )__)  )  (  /(__)\  )    (  )__)    )(_)(  ) _ <.-_)(   )__)( (__   )(  ___  )  (  )__)   )(
##(_)\_)(____)(_)\_)(__)(__)(_/\/\_)(____)  (_____)(____/\____) (____)\___) (__)(___)(_)\_)(____) (__)

def Rename_OBJNET(t_device, Config_Change, log_folder):
    import pandas as pd
    import shelve
    from Network_Calc import Sub_Mask_2
    re9 = re.compile(r'(hitcnt=.*)')
    re10 = re.compile(r'line \d+ ')
    re11 = re.compile('[(].*?[)]')

    hostname___ = t_device.replace('/','___')
    hostname = t_device
    Excel_IP_Report_FileName = hostname___ + '_DB_For_OBJNET' + '.xlsx'

    text = ('Rename Object Network @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    FW_log_folder = log_folder + '/' + hostname___
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obj_Net_Dic')
    with shelve.open(tf_name) as shelve_obj: Obj_Net_Dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_NET_Dic')
    with shelve.open(tf_name) as shelve_obj: OBJ_GRP_NET_Dic = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines')
    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines = shelve_obj['0']


    #cols = [Obj_Value, Target_Name, Obj_Name_from_db, 1_Obj_Name_from_Device, 2_Obj_Name_from_Device, 3_Obj_Name_from_Device, ...]
    try:
        OBJNET_xls_df = pd.read_excel(Excel_IP_Report_FileName, sheet_name='OBJNET')
    except:
        print('ERROR!!!')
        print("can't open file %s!" %Excel_IP_Report_FileName)
        exit(123)

    # seleziona solo righe che si vuole rinominare
    t_OBJNET_xls_df = OBJNET_xls_df.loc[OBJNET_xls_df['Target_Name'].notnull()]

##    try:
##        with open("%s/%s___Show_Running-Config.txt"%(FW_log_folder,hostname___),"r") as f:
##            l = f.readlines()
##    except:
##        print('ERROR!!! file %s/%s___Show_Running-Config.txt not found!' %(FW_log_folder,hostname___))
##        exit(0)
    try:
        with open("%s/%s___Show_Nat_Detail.txt"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            nat_file = f.readlines()
    except:
        print('file %s/%s___Show_nat.txt not found! @ CREATE VARIABLES' %(FW_log_folder,hostname___))
        exit(0)

#per ogni riga in "t_OBJNET_xls_df"
#    crea "object network" con nuovo name ()
#    ---- sono ancora da gestige gli Obejct_by_value_Dict con nat
#    cicla negli object group a sostituire
#    cicla nelle acl a sostituire
#    cicla nei nat a sostituire

    # crea nuovo object network
    N_Item_2_Rename = 0
    for row_index, row in t_OBJNET_xls_df.iterrows():
        N_Item_2_Rename += 1
        # find network object name
        t_row_Obj_name = row['1_Obj_Name_from_Device']
        t_Obj_Value = Obj_Net_Dic[t_row_Obj_name]

        #crea "object network" con nuovo name ()
        t_new_name = row['Target_Name']
        Config_Change.append('\nobject network %s' %t_new_name)
        Config_Change.append(' %s' %t_Obj_Value)

        names_2_find = list(row[3:].dropna())
        for t_old_name in names_2_find:
            if t_old_name != t_new_name:
                #cicla negli object group a sostituire
                for t_objgrp in OBJ_GRP_NET_Dic.keys():
                    for t_item in OBJ_GRP_NET_Dic[t_objgrp]:
                        if t_old_name in t_item:
                            Config_Change.append('\nobject-group network %s' %t_objgrp)
                            Config_Change.append('  network-object object %s' %t_new_name)
                            Config_Change.append('  no network-object object %s' %t_old_name)
                #cicla nelle acl a sostituire
                for t_acl_line in Show_ACL_Lines:
                    temp_line = re9.sub('',t_acl_line)
                    if t_old_name in temp_line:
                        new_line = re.sub('\\b'+t_old_name+'\\b', t_new_name, temp_line)
                        Config_Change.append('\n'+new_line)
                        Config_Change.append('no %s' %(re10.sub('',temp_line)))
                for tn_line in nat_file:
                    if t_old_name in tn_line:
                        t_interfaces = ','.join(re11.findall(tn_line)).replace('),(',',')
                        t_index = tn_line.split()[0]
                        temp_line = ('\nnat %s %s %s' %(t_interfaces, t_index, tn_line.split()[4:]))
                        old_line  = ('nat %s %s' %(t_interfaces, tn_line.split()[4:]))
                        new_line = re.sub('\\b'+t_old_name+'\\b', t_new_name, temp_line)
                        Config_Change.append(new_line)
                        Config_Change.append('no %s' %old_line)

    Config_Change.append('\n--- %s object network have been renamed ---' %N_Item_2_Rename)
    print('\n--- %s object network have been renamed ---' %N_Item_2_Rename)
    return Config_Change

##=============================================================================================================================
## ___  _   _    __    ____  _____  _    _  ____  ____       __    ___  __
##/ __)( )_( )  /__\  (  _ \(  _  )( \/\/ )( ___)(  _ \     /__\  / __)(  )
##\__ \ ) _ (  /(__)\  )(_) ))(_)(  )    (  )__)  )(_) )   /(__)\( (__  )(__
##(___/(_) (_)(__)(__)(____/(_____)(__/\__)(____)(____/   (__)(__)\___)(____)

# Check for shadowed ACLS

def Shadowed_ACL(t_device, Config_Change, log_folder):
    #from tabulate import tabulate
    #from Network_Calc import Sub_Mask_2
    #import ipaddress
    #import re
    import shelve
    import pandas as pd
    from Network_Calc import Proto_Map
    from Network_Calc import Tot_Shadow_List
    from Network_Calc import Check_Port_List
    from Network_Calc import Port_Converter
    from Network_Calc import Is_Dec_Overlapping
    MAX_Range_Ports_Counted = 10

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List')
    with shelve.open(tf_name) as shelve_obj: ACL_List = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines_DF')
    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']
    #tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
    #with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_Expanded_DF')
    with shelve.open(tf_name) as shelve_obj: ACL_Expanded_DF = shelve_obj['0']
    #tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    #with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']

    text = ('Shadowed ACLs @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    #for Leg-Fw-01___Fw-Nc-Leg-Db we have len(ACL_Expanded_DF)=4541
    #elapsed time = 0:11:41 = 700 seconds
    #=> n(n+1)/2 = 10312611 ops => 10312611/700 = =14730 cicli/sec

    #for Leg-Fw-01___Fw-CR-Leg-Db we have len(ACL_Expanded_DF)=9955
    #elapsed time = 1:12:33 = 4353 seconds
    #=> n(n+1)/2 = 10312611 ops => 49555990/4353 = =11384 cicli/sec

    expected_running_time = round(len(ACL_Expanded_DF)*len(ACL_Expanded_DF)/13000/2/60)
    print('This is going to take approx %s mins.' %str(expected_running_time))
    print('started at: %s' %datetime.datetime.now().strftime('%H:%M:%S - %d/%m/%Y'))
    if expected_running_time > 60:
         STEPS = 20
    else:
         STEPS = 10

    #BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List)
    BINS = 0; LOOP_INDEX = -1; ITEMS = len(Show_ACL_Lines_DF)#  STEPS = 20
    #Return_Config_Change = []

    for t_ACL_Name in ACL_List:

        #LOOP_INDEX = LOOP_INDEX + 1
        #if LOOP_INDEX > (ITEMS/STEPS)*BINS:
        #    print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1

        Bool_check = ('Name == "%s"') %(t_ACL_Name)
        t_Root_ACL_lines = Show_ACL_Lines_DF.query(Bool_check)
        if len(t_Root_ACL_lines) == 0:
            continue

        #print('t_ACL_Name = %s' %t_ACL_Name)
        for ACL_index in range(max(t_Root_ACL_lines.index), min(t_Root_ACL_lines.index)-1, -1):
            #rint('    ACL_index = %s' %ACL_index)

            Line_Number_Printed = False

            LOOP_INDEX = LOOP_INDEX + 1
            if LOOP_INDEX > (ITEMS/STEPS)*BINS:
                print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1
            #print('ciao')

            #t_Root_ACL_Slice_df.reset_index(inplace=True, drop=True)
            #print ('ACL %s has %s items' %(t_ACL_Name, len(t_Root_ACL_Slice_df)))
            #t_Root_ACL_lines_df = utils_v2.ASA_ACL_to_DF([t_Root_ACL_line])
            t_Root_ACL_line_df_Name = t_Root_ACL_lines.loc[ACL_index].Name
            t_Root_ACL_line_df_Line = t_Root_ACL_lines.loc[ACL_index].Line

            Bool_check = ('Name == "%s" & Line == "%s"') %(t_Root_ACL_line_df_Name, t_Root_ACL_line_df_Line)
            ACL_Line_Expanded_DF = ACL_Expanded_DF.query(Bool_check)
            #ACL_Line_Expanded_DF.reset_index(inplace=True, drop=True)
            ACL_Line_Expanded_DF_Print = pd.DataFrame(ACL_Line_Expanded_DF[['Print','Hitcnt']])
#            ACL_Line_Expanded_DF_Print['Hitcount'] = pd.DataFrame(ACL_Line_Expanded_DF.Print)
            ACL_Line_Expanded_DF_Print['T_Shadowed'] = 0
            ACL_Line_Expanded_DF_Print['P_Shadowed'] = 0
            #START_len_ACL_Line_Expanded_DF_Print = len(ACL_Line_Expanded_DF_Print)

            Bool_check = ('Name == "%s"') %(t_Root_ACL_line_df_Name)
            ACL_Slice_Expanded_DF = ACL_Expanded_DF.query(Bool_check)
            #ACL_Slice_Expanded_DF = ACL_Slice_Expanded_DF[ACL_Slice_Expanded_DF.index < t_ACL_ndex]
            #ACL_Slice_Expanded_DF.reset_index(inplace=True, drop=True)

            #check if last line is any any
            #for debug only added try and except
            try:
                if ACL_Line_Expanded_DF.index[0] == max(ACL_Line_Expanded_DF.index):
                    if ACL_Line_Expanded_DF.Source.item()[0] == [0,0] and ACL_Line_Expanded_DF.Dest.item()[0] == [0,0]:
                        continue
            except:
                print('t_ACL_Name = %s' %t_ACL_Name)
                print('ACL_index = %s' %ACL_index)
                print('ACL_Line_Expanded_DF = %s' %ACL_Line_Expanded_DF)
                print('t_Root_ACL_lines = %s' %t_Root_ACL_lines)
            #next three lines are the originals one
##            if ACL_Line_Expanded_DF.index[0] == max(ACL_Line_Expanded_DF.index):
##                if ACL_Line_Expanded_DF.Source.item()[0] == [0,0] and ACL_Line_Expanded_DF.Dest.item()[0] == [0,0]:
##                    continue

            #Last_Hitted_Line = [0]
            Temp_Config_Change = []
            Temp_Overlapped = {}
            for index_1 in range(max(ACL_Line_Expanded_DF.index), min(ACL_Line_Expanded_DF.index)-1, -1):

                Header_Printed = False
                row1 = ACL_Line_Expanded_DF.loc[index_1]
                item1_Action = row1.Action
                item1_Servic = row1.Service
                item1_Source = row1.Source
                #item1_Line = item1_1_Line = row1.Line
                item1_S_Port = row1.S_Port
                item1_Destin = row1.Dest
                item1_D_Port = row1.D_Port
                Temp_Overlapped[row1.Print] = []

                for index_2 in range(index_1-1, min(ACL_Slice_Expanded_DF.index)-1, -1):
                    row2 = ACL_Slice_Expanded_DF.loc[index_2]
                    item2_Action = row2.Action
                    item2_Servic = row2.Service
                    item2_Source = row2.Source
                    item2_S_Port = row2.S_Port
                    item2_Destin = row2.Dest
                    item2_D_Port = row2.D_Port


                    # check shadowing for each item [src,dst,proto,port]
                    # 0 = no shadowing
                    # 1 = if item1 is totally shadowed by item2 (=subnet of) => item1 can cross item2 and go up or be deleted
                    # 2 = if item1 is partly shadowed by item2 (=supernet of) => can move item1 under item2

                    for t_item1_1_Source in item1_Source:
                        for t_item2_2_Source in item2_Source:

                            #DBG___
        ##                    if 'access-list ACL-OUTSIDE line 764' in row1.Print:
        ##                        if 'ACL-OUTSIDE line 662' in row2.Print:
        ##                            print('xxx' + row2.Print)
                            #DBG___

                            Flag_Ship = [0,0,0,0]   # flags for: [SRC_IP, DST_IP, PROTO, PORT]
                                                    # 0 = no shadow
                                                    # 1 = totally shadowed => can cross item and go up
                                                    # 2 = partly shadowed  => max moving is below the shadower

                            #if t_item1_1_Source.subnet_of(t_item2_2_Source):
##                            print('t_item1_1_Source = %s' %t_item1_1_Source)
##                            print('t_item2_2_Source = %s' %t_item2_2_Source)
                            if Is_Dec_Overlapping(t_item1_1_Source, t_item2_2_Source) == 0:
                                # 0 if no overlap
                                #print('DBG__ t_item1_1_Source=%s,t_item2_2_Source=%s' %(row1.Print,row2.Print))
                                continue
                            elif Is_Dec_Overlapping(t_item1_1_Source, t_item2_2_Source) == 1:
                                Flag_Ship[0] = 1
                                # 1 if a is totally shadowed by b (=subnet of)
                                #    continue
                            elif Is_Dec_Overlapping(t_item1_1_Source, t_item2_2_Source) == 2:
                                Flag_Ship[0] = 2
                                # 2 if a is partly shadowed by b (=supernet of)

                            if (Flag_Ship[0] == 1) or (Flag_Ship[0] == 2):
                                #Port_Found_List = [0]
                                for t_item1_1_Destin in item1_Destin:
                                    for t_item2_2_Destin in item2_Destin:
                                        if Is_Dec_Overlapping(t_item1_1_Destin, t_item2_2_Destin) == 0:
                                            # 0 if no overlap
                                            #print('DBG__ t_item1_1_Destin=%s,t_item2_2_Destin=%s' %(row1.Print,row2.Print))
                                            continue
                                        elif Is_Dec_Overlapping(t_item1_1_Destin, t_item2_2_Destin) == 1:
                                            if int(row2.Hitcnt) == 0:
                                                #Temp_Config_Change.append('line "%s" has 0 hits and will be ignored' %row2.Print)
                                                #print('line "%s" has 0 hits and will be ignored' %row2.Print)
                                                continue
                                            Flag_Ship[1] = 1
                                        elif Is_Dec_Overlapping(t_item1_1_Destin, t_item2_2_Destin) == 2:
                                            if int(row2.Hitcnt) == 0:
                                                #Temp_Config_Change.append('line "%s" has 0 hits and will be ignored' %row2.Print)
                                                #print('line "%s" has 0 hits and will be ignored' %row2.Print)
                                                continue
                                            Flag_Ship[1] = 2

                                        Proto_Check_and = Proto_Map[item1_Servic] & Proto_Map[item2_Servic]
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
                                        elif Proto_Check in [4,16]:         # check port to understand it better
                                            Flag_Ship[2] = 1
                                            Port_Found_List = [0]
                                            for t_item1_D_Port in item1_D_Port:
                                                if t_item1_D_Port in item2_D_Port:
                                                    Port_Found_List.append(1)

                                                    if sum(Port_Found_List) == len(item1_D_Port): #tutte le porte sono in shadowing
                                                        Flag_Ship[3] = 1
                                                    elif sum(Port_Found_List) < len(item1_D_Port): #partial shadow
                                                        Flag_Ship[3] = 2

                                                    if Flag_Ship == [1,1,1,1]: # = [1,1,1,1]
                                                        # 1 = totally shadowed
                                                        if item1_Action != item2_Action:
                                                            #print('Differrent Actions')
                                                            Temp_Config_Change.append('Differrent Actions')

                                                        if not(Line_Number_Printed):
                                                            #print('\n Len of ACL_Line_Expanded_DF_Print = %s' %len(ACL_Line_Expanded_DF_Print))
                                                            Temp_Config_Change.append('\n 2. Len of ACL_Line_Expanded_DF_Print = %s' %len(ACL_Line_Expanded_DF_Print))
                                                            Line_Number_Printed = True
                                                        if not(Header_Printed):
                                                            Temp_Config_Change.append('     '+row1.Print)
                                                            #print('     ' + row1.Print)
                                                            Header_Printed = True
                                                        Temp_Config_Change.append('  t  '+row2.Print)
                                                        #print('  t  '+row2.Print)
                                                        #Last_Hitted_Line.append(int(row2.Line.split()[1]))
                                                        Temp_Overlapped[row1.Print].append('  t  '+row2.Print)
                                                        #print('DBG___ index_1 = %s' %index_1)
                                                        #print('DBG___ row =%s ' %ACL_Line_Expanded_DF.loc[index_1])
                                                        ACL_Line_Expanded_DF_Print.loc[index_1,'T_Shadowed'] = 1
                                                        ACL_Line_Expanded_DF_Print.loc[index_1,'P_Shadowed'] = 1
                                                        #ACL_Line_Expanded_DF_Print.pop(index_1)
                                                    elif sum(Flag_Ship) > 4:
                                                        #print(Flag_Ship)
                        ##                                            if len(item1_D_Port) > MAX_Range_Ports_Counted:
                        ##                                                #print()
                        ##                                                Temp_Config_Change.append(' --- '+row1.Print)
                        ##                                                Temp_Config_Change.append('Port Range is too wide... skipping this line')
                        ##                                                continue
                                                        if Line_Number_Printed == False:
                                                            #print('\n Len of ACL_Line_Expanded_DF_Print = %s' %len(ACL_Line_Expanded_DF_Print))
                                                            Temp_Config_Change.append('\n 3. Len of ACL_Line_Expanded_DF_Print = %s' %len(ACL_Line_Expanded_DF_Print))
                                                            Line_Number_Printed = True
                                                        if not Header_Printed:
                                                            Temp_Config_Change.append('     '+row1.Print)
                                                            #print('     ' + row1.Print)
                                                            Header_Printed = True
                                                        Temp_Config_Change.append('  p  '+row2.Print)
                                                        #print('  p  '+row2.Print)
                                                        #Last_Hitted_Line.append(int(row2.Line.split()[1]))
                                                        Temp_Overlapped[row1.Print].append('  p  '+row2.Print)
                                                        ACL_Line_Expanded_DF_Print.loc[index_1,'P_Shadowed'] = 1

            if sum(ACL_Line_Expanded_DF_Print.T_Shadowed) == 0 :
                if sum(ACL_Line_Expanded_DF_Print.P_Shadowed) == 0 :
                    #print('no shadow')
                    continue
                elif sum(ACL_Line_Expanded_DF_Print.P_Shadowed) > 0 :
                    #print('---Partially Shadowed')
                    #print('---The following lines are not shadowed')
                    Temp_Config_Change.append('---Partially Shadowed')
                    Temp_Config_Change.append('---The following lines are not shadowed')
                    int_hitcnt_list = []
                    for row_index, row in ACL_Line_Expanded_DF_Print.iterrows():
                        if row.P_Shadowed == 0:
                            #print(row.Print)
                            Temp_Config_Change.append(row.Print)
                            int_hitcnt_list.append(int(row.Hitcnt))
                    if sum(int_hitcnt_list) == 0:
                        #print('---Consider splitting the ACL somehow')
                        #print('no %s' %' '.join((ACL_Line_Expanded_DF_Print.Print.values[0]).split()[:-2]))
                        Temp_Config_Change.append('---Consider splitting the ACL somehow')
                        #Temp_Config_Change.append('no %s' %' '.join((ACL_Line_Expanded_DF_Print.Print.values[0]).split()[:-2]))

            elif sum(ACL_Line_Expanded_DF_Print.T_Shadowed) == len(ACL_Line_Expanded_DF_Print):
                #print('---Totally shadowed found for this ACL')
                #print('---ACL can be deleted')
                #print('no %s' %' '.join((ACL_Line_Expanded_DF_Print.Print.values[0]).split()[:-2]))
                Temp_Config_Change.append('---Totally shadowed found for this ACL')
                Temp_Config_Change.append('---ACL can be deleted')
                Temp_Config_Change.append('no %s' %' '.join((ACL_Line_Expanded_DF_Print.Print.values[0]).split()[:-2]))
                #for n in Temp_Config_Change:
                #    Return_Config_Change.append(n)
            else:
                #print('---Partially (Totally) Shadowed')
                #print('---The following lines are not shadowed')
                Temp_Config_Change.append('---Partially (Totally) Shadowed')
                Temp_Config_Change.append('---The following lines are not shadowed')
                int_hitcnt_list = []
                for row_index, row in ACL_Line_Expanded_DF_Print.iterrows():
                    if row.T_Shadowed == 0:
                        #print(row.Print)
                        Temp_Config_Change.append(row.Print)
                        int_hitcnt_list.append(int(row.Hitcnt))
                    elif row.P_Shadowed == 0:
                        #print(row.Print)
                        Temp_Config_Change.append(row.Print)
                        int_hitcnt_list.append(int(row.Hitcnt))
                if sum(int_hitcnt_list) == 0:
                    #print('---ACL can be deleted')
                    #print('no %s' %' '.join((ACL_Line_Expanded_DF_Print.Print.values[0]).split()[:-2]))
                    Temp_Config_Change.append('---ACL can be deleted')
                    Temp_Config_Change.append('no %s' %' '.join((ACL_Line_Expanded_DF_Print.Print.values[0]).split()[:-2]))

            for n in Temp_Config_Change:
                Config_Change.append(n)

    return Config_Change




#def Shadowed_ACL(t_device, Config_Change, log_folder):
#    #from tabulate import tabulate
#    #from Network_Calc import Sub_Mask_2
#    from Network_Calc import Proto_Map
#    from Network_Calc import Tot_Shadow_List
#    from Network_Calc import Check_Port_List
#    import shelve
#    #import re
#    import pandas as pd
#    #import ipaddress
#    from Network_Calc import Port_Converter
#
#    hostname___ = t_device.replace('/','___')
#
#    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_List')
#    with shelve.open(tf_name) as shelve_obj: ACL_List = shelve_obj['0']
#    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_ACL_Lines_DF')
#    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']
#    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_List_Dict')
#    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
#    #tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Accessgroup_Dic_by_ACL')
#    #with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']
#
#    text = ('Shadowed ACLs @ %s' %hostname___)
#    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
#
#    BINS = 0; LOOP_INDEX = -1; STEPS = 10; ITEMS = len(ACL_List)
#
#    for t_ACL_Name in ACL_List:
#        Bool_check = ('Name == "%s"') %(t_ACL_Name)
#        t_Root_ACL_Slice_df = Show_ACL_Lines_DF.query(Bool_check)
#        t_Root_ACL_Slice_df.reset_index(inplace=True, drop=True)
#        #print ('ACL %s has %s items' %(t_ACL_Name, len(t_Root_ACL_Slice_df)))
#
#        LOOP_INDEX = LOOP_INDEX + 1
#        if LOOP_INDEX > (ITEMS/STEPS)*BINS:
#            print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1
#
#        t_ACL_List_Dict_items = []
#        for index_1 in range(0,len(t_Root_ACL_Slice_df)):
#            row1 = t_Root_ACL_Slice_df.loc[index_1].copy()
#            row1['Hitcnt'] = "(hitcnt=%s)" %row1['Hitcnt']
#            if row1.Inactive == 'inactive':
#                continue
#            t1_Root_key = ' '.join(row1)
#            t1_Root_key = re_space.sub(' ', t1_Root_key)
#            for t_item in ACL_List_Dict[t1_Root_key]:
#                t_ACL_List_Dict_items.append(t_item)
#        t_ACL_List_Dict_items_DF = utils_v2.ASA_ACL_to_DF(t_ACL_List_Dict_items)
#        t_ACL_List_Dict_items_DF['Print'] = ''
#        for row_index, row1 in t_ACL_List_Dict_items_DF.iterrows():
#            row1.Print = ' '.join(row1)
#            row1.Source = utils_v2.ASA_ACL_Obj_to_IP(row1.Source)
#            row1.Dest = utils_v2.ASA_ACL_Obj_to_IP(row1.Dest)
#            if 'range ' in row1.S_Port:
#                if (row1.S_Port.split()[1]).isdigit() == True:
#                    Port_Range_Start = row1.S_Port.split()[1]
#                else:
#                    Port_Range_Start = Port_Converter[row1.S_Port.split()[1]]
#                if (row1.S_Port.split()[2]).isdigit() == True:
#                    Port_Range_End = row1.S_Port.split()[2]
#                else:
#                    Port_Range_End = Port_Converter[row1.S_Port.split()[2]]
#                row1.S_Port = range(int(Port_Range_Start),int(Port_Range_End))
#            elif 'eq ' in row1.S_Port:
#                if (row1.S_Port.split()[1]).isdigit() == True:
#                    row1.S_Port = [row1.S_Port.split()[1]]
#                else:
#                    row1.S_Port = [Port_Converter[row1.S_Port.split()[1]]]
#            else:
#                row1.S_Port = [row1.S_Port]
#            if 'range ' in row1.D_Port:
#                if (row1.D_Port.split()[1]).isdigit() == True:
#                    Port_Range_Start = row1.D_Port.split()[1]
#                else:
#                    Port_Range_Start = Port_Converter[row1.D_Port.split()[1]]
#                if (row1.D_Port.split()[2]).isdigit() == True:
#                    Port_Range_End = row1.D_Port.split()[2]
#                else:
#                    Port_Range_End = Port_Converter[row1.D_Port.split()[2]]
#                row1.D_Port = range(int(Port_Range_Start),int(Port_Range_End))
#            elif 'eq ' in row1.D_Port:
#                if (row1.D_Port.split()[1]).isdigit() == True:
#                    row1.D_Port = [row1.D_Port.split()[1]]
#                else:
#                    row1.D_Port = [Port_Converter[row1.D_Port.split()[1]]]
#            else:
#                row1.D_Port = [row1.D_Port]
#
#
#        #Printed_Lines = []
#
#        for index_1 in range(len(t_ACL_List_Dict_items_DF)-1,-1,-1):
#            Sub_ACL_Length = 0
#            Header_Printed = False
#            row1 = t_ACL_List_Dict_items_DF.loc[index_1]
#            item1_Action = row1.Action
#            item1_Servic = row1.Service
#            item1_Source = row1.Source
#            #item1_Line = item1_1_Line = row1.Line
#            item1_S_Port = row1.S_Port
#            item1_Destin = row1.Dest
#            item1_D_Port = row1.D_Port
#
#            for index_2 in range(index_1-1,-1,-1):
#                row2 = t_ACL_List_Dict_items_DF.loc[index_2]
#                item2_Action = row2.Action
#                item2_Servic = row2.Service
#                item2_Source = row2.Source
#                item2_S_Port = row2.S_Port
#                item2_Destin = row2.Dest
#                item2_D_Port = row2.D_Port
#
#                for t_item1_1_Source in item1_Source:
#                    for t_item2_2_Source in item2_Source:
#                        if t_item1_1_Source.subnet_of(t_item2_2_Source):
#                            for t_item1_1_Destin in item1_Destin:
#                                for t_item2_2_Destin in item2_Destin:
#                                    if t_item1_1_Destin.subnet_of(t_item2_2_Destin):
#                                        t_Proto_Check = Proto_Map[item1_Servic] & Proto_Map[item2_Servic]
#                                        Proto_Check = t_Proto_Check+8 if item1_Servic=='ip' else t_Proto_Check
#                                        if Proto_Check in Tot_Shadow_List:
#                                            Check_Port =  (Proto_Map[item1_Servic] + Proto_Map[item2_Servic]) + (Proto_Map[item1_Servic] * Proto_Map[item2_Servic])
#                                            if Check_Port in Check_Port_List:
#                                                #controllare se le porte sono uguali
#                                                Port_Found_List = []
#                                                for t_item1_1_D_Port in item1_D_Port:
#                                                    if t_item1_1_D_Port in item2_D_Port:
#                                                        Port_Found_List.append(1)
#                                                        if sum(Port_Found_List) == len(item1_D_Port):
#                                                            if Header_Printed == False:
#                                                                print('')
#                                                                print(row1.Print)
#
#                                                                Config_Change.append('\n'+row1.Print)
#                                                                Header_Printed = True
#
#                                                            print('  '+row2.Print)
#                                                            Config_Change.append('  '+row2.Print)
#                                                            t_Shadow_Flag = True
#                                            else:
#                                                if Header_Printed == False:
#                                                    print('')
#                                                    print(row1.Print)
#
#                                                    Config_Change.append('\n'+row1.Print)
#                                                    Header_Printed = True
#
#                                                print('  '+row2.Print)
#                                                Config_Change.append('  '+row2.Print)
#                                                t_Shadow_Flag = True
#                                        #check port & protocol
#                                    else:
#                                        continue
#                        else:
#                            continue
#

##=============================================================================================================================
##  ___  _   _  ____  ___  _  _    ___  _   _    __    ____  _____  _    _  ____  _  _  ___
## / __)( )_( )( ___)/ __)( )/ )  / __)( )_( )  /__\  (  _ \(  _  )( \/\/ )(_  _)( \( )/ __)
##( (__  ) _ (  )__)( (__  )  (   \__ \ ) _ (  /(__)\  )(_) ))(_)(  )    (  _)(_  )  (( (_-.
## \___)(_) (_)(____)\___)(_)\_)  (___/(_) (_)(__)(__)(____/(_____)(__/\__)(____)(_)\_)\___/

# given an ACL it tries to move it up until it shadows something else

def Check_Shadowing(t_device, ACL_Line, log_folder):
    #from tabulate import tabulate
    #from Network_Calc import Sub_Mask_2
    from Network_Calc import Proto_Map
    from Network_Calc import Tot_Shadow_List
    from Network_Calc import Check_Port_List
    import shelve
    #import re
    import pandas as pd
    #import ipaddress

    from Network_Calc import Port_Converter
    ACL_Line_DF = utils_v2.ASA_ACL_to_DF([ACL_Line])
    t_ACL_Name = ACL_Line_DF.Name[0]
    t_ACL_Line = ACL_Line_DF.Line[0]
    hostname___ = t_device.replace('1/','___')
    FW_log_folder = log_folder + '/' + hostname___

    #tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List')
    #with shelve.open(tf_name) as shelve_obj: ACL_List = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines_DF')
    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
    #tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    #with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']

    Bool_check = ('Name == "%s"') %(t_ACL_Name)
    t_Root_ACL_Slice_df = Show_ACL_Lines_DF.query(Bool_check)
    t_Root_ACL_Slice_df.reset_index(inplace=True, drop=True)
    t_ACL_ndex = t_Root_ACL_Slice_df.loc[t_Root_ACL_Slice_df['Line'] == t_ACL_Line].index[0]
    t_Root_ACL_Slice_df = t_Root_ACL_Slice_df[t_Root_ACL_Slice_df.index < t_ACL_ndex]
    #print ('ACL %s has %s items' %(t_ACL_Name, len(t_Root_ACL_Slice_df)))

    t_ACL_Expanded = ACL_List_Dict[ACL_Line]
    t_ACL_Expanded_DF = utils_v2.ASA_ACL_to_DF(t_ACL_Expanded)
    t_ACL_Expanded_DF['Print'] = ''

    t_ACL_List_Dict_items = [] # items of root acl(key)
    for index_1 in range(0,len(t_Root_ACL_Slice_df)):
        row1 = t_Root_ACL_Slice_df.loc[index_1].copy()
        row1['Hitcnt'] = "(hitcnt=%s)" %row1['Hitcnt']
        if row1.Inactive == 'inactive':
            continue
        t1_Root_key = ' '.join(row1)
        t1_Root_key = re_space.sub(' ', t1_Root_key)
        for t_item in ACL_List_Dict[t1_Root_key]:
            t_ACL_List_Dict_items.append(t_item)
    t_ACL_List_Dict_items_DF = utils_v2.ASA_ACL_to_DF(t_ACL_List_Dict_items)
    t_ACL_List_Dict_items_DF['Print'] = ''

    # converto ip e porte di "t_ACL_List_Dict_items_DF"
    for row_index, row1 in t_ACL_List_Dict_items_DF.iterrows():
        row1.Print = ' '.join(row1)
        row1.Source = utils_v2.ASA_ACL_Obj_to_IP(row1.Source)
        row1.Dest = utils_v2.ASA_ACL_Obj_to_IP(row1.Dest)
        if 'range ' in row1.S_Port:
            if (row1.S_Port.split()[1]).isdigit() == True:
                Port_Range_Start = row1.S_Port.split()[1]
            else:
                Port_Range_Start = Port_Converter[row1.S_Port.split()[1]]
            if (row1.S_Port.split()[2]).isdigit() == True:
                Port_Range_End = row1.S_Port.split()[2]
            else:
                Port_Range_End = Port_Converter[row1.S_Port.split()[2]]
            row1.S_Port = range(int(Port_Range_Start),int(Port_Range_End))
        elif 'eq ' in row1.S_Port:
            if (row1.S_Port.split()[1]).isdigit() == True:
                row1.S_Port = [row1.S_Port.split()[1]]
            else:
                row1.S_Port = [Port_Converter[row1.S_Port.split()[1]]]
        else:
            row1.S_Port = [row1.S_Port]
        if 'range ' in row1.D_Port:
            if (row1.D_Port.split()[1]).isdigit() == True:
                Port_Range_Start = row1.D_Port.split()[1]
            else:
                Port_Range_Start = Port_Converter[row1.D_Port.split()[1]]
            if (row1.D_Port.split()[2]).isdigit() == True:
                Port_Range_End = row1.D_Port.split()[2]
            else:
                Port_Range_End = Port_Converter[row1.D_Port.split()[2]]
            row1.D_Port = range(int(Port_Range_Start),int(Port_Range_End))
        elif 'eq ' in row1.D_Port:
            if (row1.D_Port.split()[1]).isdigit() == True:
                row1.D_Port = [row1.D_Port.split()[1]]
            else:
                row1.D_Port = [Port_Converter[row1.D_Port.split()[1]]]
        else:
            row1.D_Port = [row1.D_Port]

    # converto ip e porte di "t_ACL_Expanded_DF"
    for row_index, row1 in t_ACL_Expanded_DF.iterrows():
        row1.Print = ' '.join(row1)
        row1.Source = utils_v2.ASA_ACL_Obj_to_IP(row1.Source)
        row1.Dest = utils_v2.ASA_ACL_Obj_to_IP(row1.Dest)
        if 'range ' in row1.S_Port:
            if (row1.S_Port.split()[1]).isdigit() == True:
                Port_Range_Start = row1.S_Port.split()[1]
            else:
                Port_Range_Start = Port_Converter[row1.S_Port.split()[1]]
            if (row1.S_Port.split()[2]).isdigit() == True:
                Port_Range_End = row1.S_Port.split()[2]
            else:
                Port_Range_End = Port_Converter[row1.S_Port.split()[2]]
            row1.S_Port = range(int(Port_Range_Start),int(Port_Range_End))
        elif 'eq ' in row1.S_Port:
            if (row1.S_Port.split()[1]).isdigit() == True:
                row1.S_Port = [row1.S_Port.split()[1]]
            else:
                row1.S_Port = [Port_Converter[row1.S_Port.split()[1]]]
        else:
            row1.S_Port = [row1.S_Port]
        if 'range ' in row1.D_Port:
            if (row1.D_Port.split()[1]).isdigit() == True:
                Port_Range_Start = row1.D_Port.split()[1]
            else:
                Port_Range_Start = Port_Converter[row1.D_Port.split()[1]]
            if (row1.D_Port.split()[2]).isdigit() == True:
                Port_Range_End = row1.D_Port.split()[2]
            else:
                Port_Range_End = Port_Converter[row1.D_Port.split()[2]]
            row1.D_Port = range(int(Port_Range_Start),int(Port_Range_End))
        elif 'eq ' in row1.D_Port:
            if (row1.D_Port.split()[1]).isdigit() == True:
                row1.D_Port = [row1.D_Port.split()[1]]
            else:
                row1.D_Port = [Port_Converter[row1.D_Port.split()[1]]]
        else:
            row1.D_Port = [row1.D_Port]
##    for row_index, row in t_ACL_Expanded_DF.iterrows():
##        for row_index1, row1 in t_ACL_List_Dict_items_DF.iterrows():

    #Printed_Lines = []
    Last_Hitted_Line = [0]
    Temp_Config_Change = []
    for index_1 in range(len(t_ACL_Expanded_DF)-1,-1,-1):
        Header_Printed = False
        row1 = t_ACL_Expanded_DF.loc[index_1]
        item1_Action = row1.Action
        item1_Servic = row1.Service
        item1_Source = row1.Source
        #item1_Line = item1_1_Line = row1.Line
        item1_S_Port = row1.S_Port
        item1_Destin = row1.Dest
        item1_D_Port = row1.D_Port

        for index_2 in range(len(t_ACL_List_Dict_items_DF)-1,-1,-1):
            row2 = t_ACL_List_Dict_items_DF.loc[index_2]
            item2_Action = row2.Action
            item2_Servic = row2.Service
            item2_Source = row2.Source
            item2_S_Port = row2.S_Port
            item2_Destin = row2.Dest
            item2_D_Port = row2.D_Port

            for t_item1_1_Source in item1_Source:
                for t_item2_2_Source in item2_Source:
                    if t_item1_1_Source.subnet_of(t_item2_2_Source):
                        for t_item1_1_Destin in item1_Destin:
                            for t_item2_2_Destin in item2_Destin:
                                if t_item1_1_Destin.subnet_of(t_item2_2_Destin):
                                    t_Proto_Check = Proto_Map[item1_Servic] & Proto_Map[item2_Servic]
                                    Proto_Check = t_Proto_Check+8 if item1_Servic=='ip' else t_Proto_Check
                                    #if Proto_Check in Tot_Shadow_List:
                                    if Proto_Check != 0: # shadowing trovato
                                        Check_Port =  (Proto_Map[item1_Servic] + Proto_Map[item2_Servic]) + (Proto_Map[item1_Servic] * Proto_Map[item2_Servic])
                                        if Check_Port in Check_Port_List:
                                            #controllare se le porte sono uguali
                                            Port_Found_List = []
                                            for t_item1_D_Port in item1_D_Port:
                                                if t_item1_D_Port in item2_D_Port:
                                                    Port_Found_List.append(1)
                                                    if sum(Port_Found_List) == len(item1_D_Port): #tutte le porte sono in shadowing
                                                        if Header_Printed == False:
                                                            #print('')
                                                            #print(row1.Print)

                                                            Temp_Config_Change.append('\n'+row1.Print)
                                                            Header_Printed = True

                                                        #print('  t  '+row2.Print)
                                                        Temp_Config_Change.append('  t  '+row2.Print)
                                                        t_Shadow_Flag = True
                                                        Last_Hitted_Line.append(int(row2.Line.split()[1]))
                                                    else: # solo alcune porte sono in shadowing
                                                        if Header_Printed == False:
                                                            #print('')
                                                            #print(row1.Print)

                                                            Temp_Config_Change.append('\n'+row1.Print)
                                                            Header_Printed = True

                                                        #print('  p  '+row2.Print)
                                                        Temp_Config_Change.append('  p  '+row2.Print)
                                                        t_Shadow_Flag = False
                                                        Last_Hitted_Line.append(int(row2.Line.split()[1]))
                                        else:
                                            if Header_Printed == False:
                                                #print('')
                                                #print(row1.Print)

                                                Temp_Config_Change.append('\n'+row1.Print)
                                                Header_Printed = True

                                            #print('     '+row2.Print)
                                            Temp_Config_Change.append('    '+row2.Print)
                                            t_Shadow_Flag = True
                                            Last_Hitted_Line.append(int(row2.Line.split()[1]))
                                    #check port & protocol
                                else:
                                    continue
                    else:
                        continue

    print(row1.Print)
    print('can be moved up to line %s' %str(1+max(Last_Hitted_Line)))
    return([max(Last_Hitted_Line), Temp_Config_Change])





##===================================================================================================
##  ___  _   _  ____  ___  _  _       ____  ____  ___       ___  _   _    __    ____  _____  _    _  ____  _  _  ___
## / __)( )_( )( ___)/ __)( )/ )     (  _ \( ___)/ __)     / __)( )_( )  /__\  (  _ \(  _  )( \/\/ )(_  _)( \( )/ __)
##( (__  ) _ (  )__)( (__  )  (  ___  )(_) ))__)( (__  ___ \__ \ ) _ (  /(__)\  )(_) ))(_)(  )    (  _)(_  )  (( (_-.
## \___)(_) (_)(____)\___)(_)\_)(___)(____/(____)\___)(___)(___/(_) (_)(__)(__)(____/(_____)(__/\__)(____)(_)\_)\___/
##

# given an ACL it tries to move it up until it shadows something else
# if the ACL is partially shadowed stop the processing after "MAX_Partially_Shadowed_Lines" lines found

def Check_Dec_Shadowing(t_device, ACL_Line, log_folder, Max_ACL_Expand_Ratio):
    #from tabulate import tabulate
    #from Network_Calc import Sub_Mask_2
    from Network_Calc import Proto_Map
    #from Network_Calc import Tot_Shadow_List
    #from Network_Calc import Check_Port_List
    import shelve
    #import re
    import pandas as pd
    #import ipaddress
    #from Network_Calc import Port_Converter
    from Network_Calc import Is_Dec_Overlapping, PRTOTOCOLS
    MAX_Partially_Shadowed_Lines = 15

    #print('called "Check_Dec_Shadowing" for ACL: %s' %ACL_Line)
    ACL_Line_DF = utils_v2.ASA_ACL_to_DF([ACL_Line])
    t_ACL_Name = ACL_Line_DF.Name[0]
    t_ACL_Line = ACL_Line_DF.Line[0]
    hostname___ = t_device.replace('/','___')
    #log_folder = log_folder + '/' + hostname___
    #print(ACL_Line)
    #print('line 2703')

    Last_Hitted_Line = [0]
    Temp_Config_Change = []
    Temp_Overlapped = {}
    #tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_ACL_Lines_DF')
    #with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']
    #tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_List_Dict')
    #with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
    #tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Accessgroup_Dic_by_ACL')
    #with shelve.open(tf_name) as shelve_obj: Accessgroup_Dic_by_ACL = shelve_obj['0']
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'ACL_Expanded_DF')
    with shelve.open(tf_name) as shelve_obj: ACL_Expanded_DF = shelve_obj['0']

    Bool_check = ('Name == "%s" & Line == "%s"') %(t_ACL_Name, t_ACL_Line)
    ACL_Line_Expanded_DF = ACL_Expanded_DF.query(Bool_check)
    t_ACL_ndex = ACL_Line_Expanded_DF.index[0]
    ACL_Line_Expanded_DF.reset_index(inplace=True, drop=True)
    ACL_Line_Expanded_DF_Print = pd.DataFrame(ACL_Line_Expanded_DF.Print)
    ACL_Line_Expanded_DF_Print['Shadowed'] = 0
    #print('1. Len of ACL_Line_Expanded_DF_Print = %s' %len(ACL_Line_Expanded_DF_Print))
    #Temp_Config_Change.append('1. Len of ACL_Line_Expanded_DF_Print = %s' %len(ACL_Line_Expanded_DF_Print))
    if len(ACL_Line_Expanded_DF_Print) > 2*Max_ACL_Expand_Ratio:
        print('ACL too big, split it!')
        print('--- %s' %ACL_Line)
        #Temp_Config_Change.append('Len of ACL_Line_Expanded_DF_Print = %s' %len(ACL_Line_Expanded_DF_Print))
        Temp_Config_Change.append('ACL too big, split it!')
        Temp_Config_Change.append('--- %s' %ACL_Line)
        return([-1, ('--- access-list %s %s' %(t_ACL_Name,t_ACL_Line))])
    #START_len_ACL_Line_Expanded_DF_Print = len(ACL_Line_Expanded_DF_Print)

    Bool_check = ('Name == "%s"') %(t_ACL_Name)
    ACL_Slice_Expanded_DF = ACL_Expanded_DF.query(Bool_check)
    ACL_Slice_Expanded_DF = ACL_Slice_Expanded_DF[ACL_Slice_Expanded_DF.index < t_ACL_ndex]
    ACL_Slice_Expanded_DF.reset_index(inplace=True, drop=True)

    #Printed_Lines = []
    for index_1 in range(len(ACL_Line_Expanded_DF)-1,-1,-1):
        Header_Printed = False
        row1 = ACL_Line_Expanded_DF.loc[index_1]
        item1_Action = row1.Action
        item1_Servic = row1.Service
        item1_Source = row1.Source
        #item1_Line = item1_1_Line = row1.Line
        item1_S_Port = row1.S_Port
        item1_Destin = row1.Dest
        item1_D_Port = row1.D_Port
        Temp_Overlapped[row1.Print] = []
        #print('looking for: ' + row1.Print)

        if (item1_Source == [[0,0]] and item1_Destin == [[0,0]]):
            #Temp_Config_Change.append('Line can not be moved...')
            Last_Hitted_Line.append(int(row1.Line.split()[1])-1)
            continue

        N_Partially_Shadowed_Lines = 0
        Break_Flag = False
        for index_2 in range(len(ACL_Slice_Expanded_DF)-1,-1,-1):
            if Break_Flag == True:
                break
            row2 = ACL_Slice_Expanded_DF.loc[index_2]
            item2_Action = row2.Action
            item2_Servic = row2.Service
            item2_Source = row2.Source
            item2_S_Port = row2.S_Port
            item2_Destin = row2.Dest
            item2_D_Port = row2.D_Port
            if item2_Servic not in PRTOTOCOLS:
                continue
            if row2.Inactive == 'inactive': # skip inactive lines
                break


            # check shadowing for each item [src,dst,proto,port]
            # 0 = no shadowing
            # 1 = if item1 is totally shadowed by item2 (=subnet of) => item1 can cross item2 and go up
            # 2 = if item1 is partly shadowed by item2 (=supernet of) => can move item1 under item2

            for t_item1_1_Source in item1_Source:
                if Break_Flag == True:
                    break
                for t_item2_2_Source in item2_Source:

                    #DBG___
##                    if 'access-list ACL-OUTSIDE line 764' in row1.Print:
##                        if 'ACL-OUTSIDE line 662' in row2.Print:
##                            print('xxx' + row2.Print)
                    #DBG___

                    Flag_Ship = [0,0,0,0]   # flags for: [SRC_IP, DST_IP, PROTO, PORT]
                                            # 0 = no shadow
                                            # 1 = totally shadowed => can cross item and go up
                                            # 2 = partly shadowed  => max moving is below the shadower

                    #if t_item1_1_Source.subnet_of(t_item2_2_Source):
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
##                                    if int(row2.Hitcnt) == 0:
##                                        #Temp_Config_Change.append('line "%s" has 0 hits and will be ignored' %row2.Print)
##                                        #print('line "%s" has 0 hits and will be ignored' %row2.Print)
##                                        continue
                                    Flag_Ship[1] = 1
                                elif ip_dst_check == 2:
##                                    if int(row2.Hitcnt) == 0:
##                                        #Temp_Config_Change.append('line "%s" has 0 hits and will be ignored' %row2.Print)
##                                        #print('line "%s" has 0 hits and will be ignored' %row2.Print)
##                                        continue
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
                                    Port_Found_List = [0]

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

##                                    for t_item1_D_Port in item1_D_Port:
##                                        if t_item1_D_Port in item2_D_Port:
##                                            Port_Found_List.append(1)
##                                            #if sum(Port_Found_List) == 0: #no shadowing
##                                            #    Flag_Ship[3] = 0
##                                            if sum(Port_Found_List) == len(item1_D_Port): #tutte le porte sono in shadowing
##                                                Flag_Ship[3] = 1
##                                            elif sum(Port_Found_List) < len(item1_D_Port): #partial shadow
##                                                Flag_Ship[3] = 2


                    if Flag_Ship == [1,1,1,1]: # = [1,1,1,1]
                        # 1 = totally shadowed => can cross item and go up (UNLESS different action)
                        #if item1_Action != item2_Action:
                            #print('Differrent Actions')
                            #Temp_Config_Change.append('Differrent Actions')
                            #print('Different Actions:')
                            #print('H___ '+row1.Print)
                            #print('  t  '+row2.Print)
                            ##continue
                        if not(Header_Printed):
                            Temp_Config_Change.append('H___ '+row1.Print)
                            #print(row1.Print)
                            Header_Printed = True
                        Temp_Config_Change.append('  t  '+row2.Print)
                        #print('  t  '+row2.Print)
                        ##Last_Hitted_Line.append(int(row2.Line.split()[1]))
                        Temp_Overlapped[row1.Print].append('  t  '+row2.Print)
                        #print('DBG___ index_1 = %s' %index_1)
                        #print('DBG___ row =%s ' %ACL_Line_Expanded_DF.loc[index_1])
                        ACL_Line_Expanded_DF_Print.loc[index_1,'Shadowed'] = 1
                        #ACL_Line_Expanded_DF_Print.pop(index_1)
                    elif sum(Flag_Ship) > 4:
                        #if item1_Action != item2_Action:
                            #print('Different Actions:')
                            #print('H___ '+row1.Print)
                            #print('  p  '+row2.Print)
                            ##continue
                        if not(Header_Printed):
                            Temp_Config_Change.append('H___ '+row1.Print)
                            #print(row1.Print)
                            Header_Printed = True
                        Temp_Config_Change.append('  p  '+row2.Print)
                        #print('  p  '+row2.Print)
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
        #Temp_Config_Change.append('Totally shadowed found for this ACL')
        pass
    elif sum(ACL_Line_Expanded_DF_Print.Shadowed) != 0:
        #print('The following lines are not shadowed')
        #Temp_Config_Change.append('The following lines are not shadowed')
        for row_index, row in ACL_Line_Expanded_DF_Print.iterrows():
            if row.Shadowed == 0:
                #print(row.Print)
                Temp_Config_Change.append('H_n_ '+row.Print)
    #print('can be moved up to line %s\n\n' %str(1+max(Last_Hitted_Line)))
    #Temp_Config_Change.append('can be moved up to line %s\n\n' %str(1+max(Last_Hitted_Line)))

    return([max(Last_Hitted_Line), Temp_Config_Change])



##===================================================================================================
##  ___  _   _  ____  ___  _  _    _  _    __   ____
## / __)( )_( )( ___)/ __)( )/ )  ( \( )  /__\ (_  _)
##( (__  ) _ (  )__)( (__  )  (    )  (  /(__)\  )(
## \___)(_) (_)(____)\___)(_)\_)  (_)\_)(__)(__)(__)


##Max_NAT_ZeroHit_Age  = 180 #days
##Max_NAT_Inactive_Age = 180 #days
##Min_NAT_Hitcnt_Threshold   = 20  #sotto questo numero la ACL è in dubbio
##N_ACL_Most_Triggered   = 10  #numero di regole a maggiore hit che vengono visualizzate


def Check_NAT(t_device, Config_Change, log_folder):

    import shelve
    import sqlalchemy as db
    import pandas as pd
    from tabulate import tabulate
    import ipaddress
    #global N_NAT_Most_Triggered

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
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_NAT_DF')
    try:
        with shelve.open(tf_name) as shelve_obj: Show_NAT_DF = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_NAT exit ERROR.')

    #load Show_NAT_DB for this device
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
            #Show_NAT_DB_df.columns = ['ID','HostName','Last_Seen','Section','Line_N','IF_IN','IF_OUT','StaDin','SRC_IP','SNAT_IP','DST_IP','DNAT_IP','service','SRVC','DSRVC','inactive','Direction','DESC','Tr_Hit','Un_Hit','Delta_Tr_Hit','Delta_Un_Hit','Nat_Line','SRC_Origin','SRC_Natted','DST_Origin','DST_Natted']
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
                #print(f"{result.rowcount} row(s) deleted.")
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
##        Show_NAT_DB_df.columns = ['ID','HostName','Last_Seen','Section','Line_N','IF_IN','IF_OUT','StaDin','SRC_IP','SNAT_IP','DST_IP','DNAT_IP','service','SRVC','DSRVC','inactive','Direction','DESC','Tr_Hit','Un_Hit','Delta_Tr_Hit','Delta_Un_Hit','Nat_Line','SRC_Origin','SRC_Natted','DST_Origin','DST_Natted']
##        Show_NAT_DB_df = Show_NAT_DB_df.drop('ID', 1)
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
                            #t_Days = (t_today-t_Show_NAT_DB.Last_Seen.item()).days
                            # Following nat can be removed
                            #t0_line = 'Tr_Hit = %s' %(row.Tr_Hit)
                            #t1_line = 'Un_Hit = %s' %(row.Un_Hit)
                            #t2_line = '[%s|%s] %s' %(row.Section, row.Line_N, row.Nat_Line)
                            #List_of_NAT_to_Remove.append("{:<17}| {:<17} | {:<10}".format(t0_line, t1_line, t2_line))
                            t_N_NAT_Inactive_toDel += 1
                            List_of_NAT_to_Remove.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
                        else:
                            List_of_NAT_aging_to_Remove.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])

                    else:
                        # check if to make inactive
                        if t_Days >= Max_NAT_ZeroHit_Age:  #make NAT inactive
                            # Following nat can be turned inactive
                            #t0_line = 'Tr_Hit = %s' %(row.Tr_Hit)
                            #t1_line = 'Un_Hit = %s' %(row.Un_Hit)
                            #t2_line = '[%s|%s] %s' %(row.Section, row.Line_N, row.Nat_Line)
                            #List_of_NAT_to_Inactive.append("{:<17}| {:<17} | {:<10}".format(t0_line, t1_line, t2_line))
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

    #text = ('Following nat can be removed (Threshold at %s days)' %Max_NAT_ZeroHit_Age)
    #utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    #List_of_NAT_to_Remove_DF = pd.DataFrame(List_of_NAT_to_Remove, columns = ['Days', 'Tr_Hit', 'Un_Hit', 'Section', 'NAT'])
    #Config_Change.append(tabulate(List_of_NAT_to_Remove_DF,List_of_NAT_to_Remove_DF,tablefmt='psql',showindex=False))
    #for row_index, row in List_of_NAT_to_Remove_DF[::-1].iterrows():
    #    t_section = int(row.Section.strip('[').strip(']').split('|')[0])
    #    if t_section == 1:
    #        Config_Change.append('no nat %s' %row.NAT.replace(') to (',','))
    #    elif t_section == 2:
    #        Config_Change.append('to be implemented --- remove object nat for\n %s' %row.NAT)
    #    elif t_section == 3:
    #        temp = ('no nat %s' %row.NAT.replace(') to (',','))
    #        Config_Change.append(temp.replace(') ',') after-auto '))

    #text = ('Following nat can be turned inactive (Threshold at %s days)' %Max_NAT_Inactive_Age)
    #utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    #List_of_NAT_to_Inactive_DF = pd.DataFrame(List_of_NAT_to_Inactive, columns = ['Days', 'Tr_Hit', 'Un_Hit', 'Section', 'NAT'])
    #Config_Change.append(tabulate(List_of_NAT_to_Inactive_DF,List_of_NAT_to_Inactive_DF,tablefmt='psql',showindex=False))
    #for row_index, row in List_of_NAT_to_Inactive_DF[::-1].iterrows():
    #    t_section = int(row.Section.strip('[').strip(']').split('|')[0])
    #    if t_section == 1:
    #        if ' description ' in row.NAT:
    #            Config_Change.append('nat %s' %row.NAT.replace(') to (',',').replace(' description ',' inactive description '))
    #        else:
    #            Config_Change.append('nat %s inactive' %row.NAT.replace(') to (',','))
    #    elif t_section == 2:
    #        Config_Change.append('to be implemented --- make inactive object nat for\n %s' %row.NAT)
    #    elif t_section == 3:
    #        if ' description ' in row.NAT:
    #            temp = ('nat %s' %row.NAT.replace(') to (',',').replace(' description ',' inactive description '))
    #            Config_Change.append(temp.replace(') ',') after-auto '))
    #        else:
    #            temp = ('nat %s inactive' %row.NAT.replace(') to (',','))
    #            Config_Change.append(temp.replace(') ',') after-auto '))

    #List_of_NAT_aging_to_Inactive_DF = pd.DataFrame(List_of_NAT_aging_to_Inactive, columns = ['Days', 'Tr_Hit', 'Un_Hit', 'Section', 'NAT'])
    #Config_Change.append('The Following are still aging...\n')
    #Config_Change.append(tabulate(List_of_NAT_aging_to_Inactive_DF,List_of_NAT_aging_to_Inactive_DF,tablefmt='psql',showindex=False))
#---------------------------------------------------------------------------------------------------------------------------------
    Moved_NAT_Think = []
##    Most_Triggered_NAT_txt = []
    Moved_NAT = []
    Moved_NAT_done = []
    Temp_Tr_Nat = []


    if DB_Available:
        query = db.select(Show_NAT_DB).where(db.and_(Show_NAT_DB.columns.HostName==hostname___), (Show_NAT_DB.columns.Section!=0))
        #query = db.select(Show_NAT_DB).where(Show_NAT_DB.columns.HostName=="%s" %hostname___)
        with engine.begin() as connection:
            Show_NAT_DB_df = pd.DataFrame(connection.execute(query).fetchall())

        NRows_Show_NAT_DB_df = 0
        N_Tr_Hit_Zero = 0
        N_Un_Hit_Zero = 0
        t_N_NAT_Inactive = 0
        N_NAT_Average_Position_4db = 0
##        N_of_NAT_Incremented = 0
##        N_of_NAT_Resetted = 0
##        N_of_NAT_Deleted = 0
##        N_of_NAT_New = 0

        # ----- most triggered NAT -----
        tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Name_dic')
        with shelve.open(tf_name) as shelve_obj: Name_dic = shelve_obj['0']
        if len(Show_NAT_DB_df) > 0:
            # ----- find most triggered -----
            #Show_NAT_DB_df.columns = ['ID','HostName','Last_Seen','Section','Line_N','IF_IN','IF_OUT','StaDin','SRC_IP','SNAT_IP','DST_IP','DNAT_IP','service','SRVC','DSRVC','inactive','Direction','DESC','Tr_Hit','Un_Hit','Delta_Tr_Hit','Delta_Un_Hit','Nat_Line','SRC_Origin','SRC_Natted','DST_Origin','DST_Natted']
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
##            Most_Triggered_NAT_txt.append('Tr_Hit == 0 for %s over %s NAT Lines (%s%%)\n' %(N_Tr_Hit_Zero, NRows_Show_NAT_DB_df, N_Tr_Hit_xcnt))
##            Most_Triggered_NAT_txt.append('Un_Hit == 0 for %s over %s NAT Lines (%s%%)\n' %(N_Un_Hit_Zero, NRows_Show_NAT_DB_df, N_Un_Hit_xcnt))
##            Most_Triggered_NAT_txt.append('inactive    for %s over %s NAT Lines (%s%%)\n' %(t_N_NAT_Inactive, NRows_Show_NAT_DB_df, N_inactive_xcnt))


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
##            Most_Triggered_NAT_txt.append('%s lines out of %s (%s%%) trigger %s hitcnt out of %s (%s%%)\n' %(N_NAT_Most_Triggered, len(Show_NAT_DB_df['Line_N']), prcnt_lines, Sum_Delta_sorted, Sum_Delta, prcnt_hitcnt))

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
                        #print("{:>10}".format("TEST"))
                        percent = round(NAT_Position/(NRows_Show_NAT_DB_df)*100) if NRows_Show_NAT_DB_df else 0
                        #t0_line = 'Delta_Tr/Un_Hit = %s' %(row.Delta_Tr_Hit_Un_Hit)
                        #t1_line = '%s%%' %(percent)
                        #t2_line = '[%s|%s] %s' %(row.Section, row.Line_N, row.Nat_Line)
                        #Config_Change.append("{:<25}| {:>6} | {:<10}".format(t0_line, t1_line, t2_line))
                        Temp_Tr_Nat.append(['%s' %(row.Delta_Tr_Hit_Un_Hit), '%s%%' %(percent), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
                        t_Processed_NATs += 1

            Temp_Tr_Nat_DF = pd.DataFrame(Temp_Tr_Nat, columns = ['Diff_Tr/Un' , '%', 'Section', 'NAT'])
            #Config_Change.append(tabulate(Temp_Tr_Nat_DF,Temp_Tr_Nat_DF,tablefmt='psql',showindex=False))
##            Most_Triggered_NAT_txt.append(tabulate(Temp_Tr_Nat_DF,Temp_Tr_Nat_DF,tablefmt='psql',showindex=False))
            temp = 0
            for row_index, row in Temp_Tr_Nat_DF.iterrows():
                temp = temp + float(row['%'].strip('%'))
            temp = temp / N_NAT_Most_Triggered if N_NAT_Most_Triggered else 0
            N_NAT_Average_Position_4db = round(temp,1)
            #Config_Change.append('\n Average NAT percent position = %.1f\n' %temp)
##            Most_Triggered_NAT_txt.append('\n Average NAT percent position = %.1f\n' %temp)

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
                                            #if re_iprange.match(row_0_SRC):

                                            try:
                                                try:
                                                    row_0_SRC_IP = ipaddress.IPv4Network(row_0_SRC, strict=False)
                                                except:
                                                    row_0_SRC_IP = ipaddress.IPv4Network(Name_dic[row_0_SRC.rsplit('/')[0]] +'/'+ row_0_SRC.rsplit('/')[1], strict=False)
                                            except:
                                                print('1. Cannot convert "%s" to IPv4' %row_0_SRC)
                                                continue
                                                #print(row_0_SRC)
                                            #row_0_SRC_IP = ipaddress.IPv4Network(row_0_SRC, strict=False)
                                            for row_2_SRC in row_2['SRC_Origin']:
                                                try:
                                                    try:
                                                        row_2_SRC_IP = ipaddress.IPv4Network(row_2_SRC, strict=False)
                                                    except:
                                                        row_2_SRC_IP = ipaddress.IPv4Network(Name_dic[row_2_SRC.rsplit('/')[0]] +'/'+ row_2_SRC.rsplit('/')[1], strict=False)
                                                except:
                                                    print('2. Cannot convert "%s" to IPv4' %row_2_SRC)
                                                    continue
                                                    #print(row_2_SRC)
                                                #row_2_SRC_IP = ipaddress.IPv4Network(row_2_SRC, strict=False)
                                                #if row_0_SRC_IP.subnet_of(row_2_SRC_IP):
                                                if row_0_SRC_IP.subnet_of(row_2_SRC_IP) or row_0_SRC_IP.supernet_of(row_2_SRC_IP):
                                                    flag_ship[2] = 1

                                                    for row_0_DST in row_0['DST_Origin']:
                                                        try:
                                                            try:
                                                                row_0_DST_IP = ipaddress.IPv4Network(row_0_DST, strict=False)
                                                            except:
                                                                row_0_DST_IP = ipaddress.IPv4Network(Name_dic[row_0_DST.rsplit('/')[0]] +'/'+ row_0_DST.rsplit('/')[1], strict=False)
                                                        except:
                                                            print('3. Cannot convert "%s" to IPv4' %row_0_DST)
                                                            continue
                                                            #print(row_0_DST)
                                                        #row_0_DST_IP = ipaddress.IPv4Network(row_0_DST, strict=False)
                                                        for row_2_DST in row_2['DST_Origin']:
                                                            try:
                                                                try:
                                                                    row_2_DST_IP = ipaddress.IPv4Network(row_2_DST, strict=False)
                                                                except:
                                                                    row_2_DST_IP = ipaddress.IPv4Network(Name_dic[row_2_DST.rsplit('/')[0]] +'/'+ row_2_DST.rsplit('/')[1], strict=False)
                                                            except:
                                                                print('4. Cannot convert "%s" to IPv4' %row_2_DST)
                                                                continue
                                                                #print(row_2_DST)
                                                            #row_2_DST_IP = ipaddress.IPv4Network(row_2_DST, strict=False)
                                                            else:
                                                                #if row_0_DST_IP.subnet_of(row_2_DST_IP):
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
                                                #row_0_SRC_IP = ipaddress.IPv4Network(row_0_SRC, strict=False)
                                                try:
                                                    try:
                                                        row_0_SRC_IP = ipaddress.IPv4Network(row_0_SRC, strict=False)
                                                    except:
                                                        row_0_SRC_IP = ipaddress.IPv4Network(Name_dic[row_0_SRC.rsplit('/')[0]] +'/'+ row_0_SRC.rsplit('/')[1], strict=False)
                                                except:
                                                    print('5. Cannot convert "%s" to IPv4' %row_0_SRC)
                                                    continue
                                                #print(row_0_SRC)
                                                for row_2_SRC in row_2['DST_Natted']:
                                                    #row_2_SRC_IP = ipaddress.IPv4Network(row_2_SRC, strict=False)
                                                    try:
                                                        try:
                                                            row_2_SRC_IP = ipaddress.IPv4Network(row_2_SRC, strict=False)
                                                        except:
                                                            row_2_SRC_IP = ipaddress.IPv4Network(Name_dic[row_2_SRC.rsplit('/')[0]] +'/'+ row_2_SRC.rsplit('/')[1], strict=False)
                                                    except:
                                                        print('6. Cannot convert "%s" to IPv4' %row_2_SRC)
                                                        continue
                                                        #print(row_2_SRC)
                                                    #if row_0_SRC_IP.subnet_of(row_2_SRC_IP):
                                                    if row_0_SRC_IP.subnet_of(row_2_SRC_IP) or row_0_SRC_IP.supernet_of(row_2_SRC_IP):
                                                        flag_ship[2] = 1

                                                        for row_0_DST in row_0['SRC_Natted']:
                                                            #row_0_DST_IP = ipaddress.IPv4Network(row_0_DST, strict=False)
                                                            try:
                                                                try:
                                                                    row_0_DST_IP = ipaddress.IPv4Network(row_0_DST, strict=False)
                                                                except:
                                                                    row_0_DST_IP = ipaddress.IPv4Network(Name_dic[row_0_DST.rsplit('/')[0]] +'/'+ row_0_DST.rsplit('/')[1], strict=False)
                                                            except:
                                                                print('7. Cannot convert "%s" to IPv4' %row_0_DST)
                                                                continue
                                                                #print(row_0_DST)
                                                            for row_2_DST in row_2['SRC_Natted']:
                                                                #row_2_DST_IP = ipaddress.IPv4Network(row_2_DST, strict=False)
                                                                try:
                                                                    try:
                                                                        row_2_DST_IP = ipaddress.IPv4Network(row_2_DST, strict=False)
                                                                    except:
                                                                        row_2_DST_IP = ipaddress.IPv4Network(Name_dic[row_2_DST.rsplit('/')[0]] +'/'+ row_2_DST.rsplit('/')[1], strict=False)
                                                                except:
                                                                    print('8. Cannot convert "%s" to IPv4' %row_2_DST)
                                                                    continue
                                                                    #print(row_2_DST)
                                                                else:
                                                                    #if row_0_DST_IP.subnet_of(row_2_DST_IP):
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
            #t_new_item.append('no nat %s' %t_field[2])
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
            #t_new_item.append('no nat %s after-auto' %t_field[2])
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

##    Most_Triggered_NAT_txt.append('\n\n\n')
##    for t_block in Moved_NAT_Fix:
##        Most_Triggered_NAT_txt.append('\n')
##        for m in t_block:
##            Most_Triggered_NAT_txt.append(m+'\n')
##
##    txt_FName   = FW_log_folder + '/' + hostname___ + '-Most_Triggered_NAT.txt'
##    try:
##        with open(txt_FName,mode="w") as my_file:
##            my_file.writelines(Most_Triggered_NAT_txt)
##        print('... saved file "%s" '%(txt_FName))
##    except:
##        raise OSError("Can't write to destination file (%s)!" % (txt_FName))

    #---------------- Most_Triggered_NAT-Watch.html
    Watch_FList = []
    Watch_FList.append('<div class="card-body">\n')
    #Watch_FList.append('   <table class="table-bordered table-condensed table-striped" id="dataTable" width="100%" cellspacing="0" data-page-length="50">\n')
    Watch_FList.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('         <th>%s</th>\n' %'Delta_Tr/Un')
    Watch_FList.append('         <th>%s</th>\n' %'%')
    Watch_FList.append('         <th>%s</th>\n' %'Position')
    Watch_FList.append('         <th>%s</th>\n' %'NAT')
    Watch_FList.append('      <thead><tr>\n')
    Watch_FList.append('      <tbody>\n')
    for t_line in Temp_Tr_Nat:
        #List_of_NAT_to_Remove.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
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
            #html_file.writelines(line for line in Watch_FList)
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
            #html_file.writelines(line for line in Fix_FList)
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
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ROUTE_DF')
    try:
        with shelve.open(tf_name) as shelve_obj: ROUTE_DF = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_NAT exit ERROR.')

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_Crypto_RemoteNet_List')
    try:
        with shelve.open(tf_name) as shelve_obj: Show_Crypto_RemoteNet_List = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_NAT exit ERROR.')

    ROUTE_IP_DF = ROUTE_DF.copy()
    for row_index, row in ROUTE_IP_DF.iterrows():
        try:
            ROUTE_IP_DF.at[row_index, 'Network'] = ipaddress.IPv4Network(row.Network)
        except:
            Moved_NAT_Think.append('ERROR 3915 while converting %s to ipaddress\n' %row.Network)
            print('ERROR 3915 while converting %s to ipaddress\n' %row.Network)
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
                print('can not translate to IP this "%s" @ "%s"' %(t_SRC_Origin, row.Nat_Line))
                continue

            Bool_check = ('Interface == "%s"') %(t_IF_IN)
            #Wider_Object_Found = False
            BEST_ROUTE = ''
            WIDE_ROUTE_List = []
            if t_IF_IN == 'any':
                Routing_L = ROUTE_IP_DF['Network'].to_list()
            else:
                Routing_L = ROUTE_IP_DF.query(Bool_check)['Network'].to_list()
            for this_route in Routing_L:
            #for this_route in Routing_Table:
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
                #text_line = ('\n---### NAT Object wider than routing ###---\n')
                text_line = ('\n [%s|%s] %s\n' %(row.Section,row.Line_N,row.Nat_Line))
                if text_line not in Printed_Lines:
                    #print (text_line)
                    Moved_NAT_Think.append('\n---### NAT Object wider than routing ###---' + text_line)
                    Printed_Lines.append(text_line)
                text_line = (' - Surce_Object is "%s", interface is "%s", routing is:' %(t_SRC_Origin, t_IF_IN))
                if text_line not in Printed_Lines:
                    #print (text_line)
                    Moved_NAT_Think.append(text_line)
                    Printed_Lines.append(text_line)
                    for n in WIDE_ROUTE_List:
                        #print ('   %s' %n)
                        Moved_NAT_Think.append('   %s' %n)
                    #print('!')
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
                            #print (text_line)
                            Moved_NAT_Think.append(text_line)
                            Object_Found = True
                        #else:
                            #t0_line = 'Object %s' %(t_SRC_Origin)
                            #t1_line = 'does not belong to interface %s but is in a VPN' %(t_IF_IN)
                            #text_line = ("{:<26} {:<1}".format(t0_line, t1_line))
                            #t_SRC_Origin_L.remove(t_SRC_Origin)
                            #print (text_line)
                            #Config_Change.append(text_line)
                            #Object_Found = True

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
            #print (text_line)
            Moved_NAT_Think.append(text_line)
        else:
            if Object_Found == True:
                text_line = ('Remaining objects are:\n - ')
                for n in t_SRC_Origin_L:
                    text_line = text_line+('%s, ' %n)
                text_line = text_line +('\n - (%s/%s) [%s|%s] @ %s\n' %(row.Tr_Hit,row.Un_Hit,row.Section,row.Line_N,row.Nat_Line))
                #print (text_line)
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


    Merge_Flist = []
    Merge_FName = FW_log_folder + '/' + hostname___ + '-Inactive_NAT-Merge.txt'
    Merge_Flist.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
    Merge_Flist.append('!')

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
        #List_of_NAT_to_Remove.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
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
            #html_file.writelines(line for line in Watch_FList)
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
        #List_of_NAT_to_Remove.append(['%s' %(t_Days), '%s' %(row.Tr_Hit), '%s' %(row.Un_Hit), '[%s|%s]'%(row.Section, row.Line_N), '%s' %row.Nat_Line])
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
            #html_file.writelines(line for line in Watch_FList)
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
            #html_file.writelines(line for line in Fix_FList)
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
            #html_file.writelines(line for line in Watch_FList)
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
            #html_file.writelines(line for line in Watch_FList)
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
            #html_file.writelines(line for line in Fix_FList)
            html_file.writelines(Fix_FList)
        print('... saved file "%s" '%(Fix_FName))
    except:
        raise OSError("Can't write to destination file (%s)!" % (Fix_FName))
    #Write_Think_File(Fix_FName, Fix_FList)

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

# controlla non ci siano range troppo grossi sia porte che ip


def Check_Range(t_device, Config_Change, log_folder):

    import shelve
    import sqlalchemy as db
    import pandas as pd
    from tabulate import tabulate
    import ipaddress
    from Network_Calc import IPv4_to_DecList, Port_Converter

    html_file_list = []
    t_html_file = []
    t_Config_Change = []

    hostname___ = t_device.replace('/','___')
    FW_log_folder = log_folder + '/' + hostname___
    Err_folder  = log_folder
    html_folder = FW_log_folder

    hostname = t_device
    config_range_html = hostname___ + '-Config_Range.html'
##    config_range_txt  = hostname___ + '-Config_Range.txt'
##    nologacl_txt_FList.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
##    nologacl_txt_FList.append('!\n')

    text = ('Check_Range @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
##    t_Config_Change.append(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S\n'))
##    t_Config_Change.append('!\n')

##    t_Config_Change.append('!  (==                   Check_Range @ %s                   ==)\n' %hostname)
##    t_Config_Change.append('!\n')

    #utils_v2.Text_in_Frame (text, t_Config_Change)

##    t_html_file.append('<p class="text-secondary">\n')
##    t_html_file.append('''
##    <style>
##        p.small {
##          line-height: 1.0;
##          font-family:"Courier New";
##          font-size: 1rem;
##        }
##    </style>''')
    t_html_file.append('<div class="card-body">\n')
    t_html_file.append('<table class="table-bordered table-condensed table-striped table-responsive" id="dataTable" width="100%" cellspacing="0" data-page-length="50" >\n')
##    t_html_file.append('       <thead><tr>\n')
##    t_html_file.append('           <th>Object Service</th>\n')
##    t_html_file.append('       </tr></thead>\n')
    t_html_file.append('       <tbody>\n')
##    t_html_file.append('<ul>\n')

    DB_Available = True
    try:
        engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
        with engine.connect() as connection:
            My_Devices = db.Table('My_Devices', db.MetaData(), autoload_with=engine)
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
    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Obj_Net_Dic')
    try:
        with shelve.open(tf_name) as shelve_obj: Obj_Net_Dic = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_Range exit ERROR.')

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_SVC_Dic')
    try:
        with shelve.open(tf_name) as shelve_obj: OBJ_SVC_Dic = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_Range exit ERROR.')

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'OBJ_GRP_SVC_Dic')
    try:
        with shelve.open(tf_name) as shelve_obj: OBJ_GRP_SVC_Dic = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_Range exit ERROR.')
    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic.keys():
        if len(t_OBJ_GRP_SVC_Dic_key.split()) == 2:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = [t_OBJ_GRP_SVC_Dic_key.split()[1], OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)]
        else:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = ['', OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)]

    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines')
    try:
        with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_Range exit ERROR.')

    remove_tags = re.compile('<.*?>')
    #notag = remove_tags.sub('\n', working_on)

    N_Range_IP_Obj = 0
    N_Max_Range_IP = 0
    for t_obj_key in Obj_Net_Dic.keys():
        t_value = Obj_Net_Dic[t_obj_key]
        if t_value.startswith('range '):
            IP_1_dec = IPv4_to_DecList(t_value.split()[1], '0.0.0.0')
            IP_2_dec = IPv4_to_DecList(t_value.split()[2], '0.0.0.0')
            N_of_IPs = IP_2_dec[0] - IP_1_dec[0] + 1
            if N_of_IPs > Max_IPv4_Range:
                N_Range_IP_Obj += 1
                if (N_of_IPs > N_Max_Range_IP): N_Max_Range_IP = N_of_IPs
##                t_Config_Change.append('\n\n============[ IP Range: %s ]=============\n' %N_of_IPs)
##                print('\n\n============[ IP Range: %s ]=============' %N_of_IPs)
                text_line = 'object network %s\n  %s\n' %(t_obj_key,t_value)
##                t_Config_Change.append(text_line)
##                print (text_line)
                t_html_file.append('<tr><td class="text-nowrap"><ul>\n')
                t_html_file.append('<_L1_TEXT_> '+'<br><li>IPs Range: %s</li>\n' %(N_of_IPs))
                t_html_file.append('<_CODE_> '+'object network %s<br>\n &nbsp;&nbsp; %s<br><br>\n' %(t_obj_key,t_value))
                Out = []
                t_Out = Where_Used(t_device, t_obj_key, FW_log_folder, Out)
                if t_Out:
                    for line in t_Out:
                        t_html_file.append(line+'<br>')
                t_html_file.append('</ul></td></tr>\n')
##                        t_Config_Change.append(remove_tags.sub('', line.strip())+'\n')


##object service RH-MGR-SERIAL-RANGE
## service tcp destination range 5900 6923
    N_Range_Port_Obj = 0
    N_Max_Range_Port = 0
    for t_obj_key in OBJ_SVC_Dic.keys():
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
##                t_Config_Change.append('\n\n===========[ Port Range: %s ]============\n' %N_of_Ports)
##                print('\n\n===========[ Port Range: %s ]============' %N_of_Ports)
                text_line = 'object service %s\n %s\n' %(t_obj_key,t_value)
##                t_Config_Change.append(text_line)
##                print (text_line)
                t_html_file.append('<tr><td class="text-nowrap"><ul>\n')
                t_html_file.append('<_L1_TEXT_> '+'<br><li>Port Range: %s</li>\n' %(N_of_Ports))
                t_html_file.append('<_CODE_> '+'object service %s<br>\n &nbsp;&nbsp; %s<br><br>\n' %(t_obj_key,t_value))
                Out = []
                t_Out = Where_Used(t_device, t_obj_key, FW_log_folder, Out)
                if t_Out:
                    for line in t_Out:
                        t_html_file.append(line+'<br>')
                t_html_file.append('</ul></td></tr>\n')
##                        t_Config_Change.append(remove_tags.sub('', line.strip())+'\n')

##object-group service TCP-STORAGE-SC5020
## service-object tcp destination eq https
## service-object tcp destination range 10001 10008
##object-group service TCP_8003-8010 tcp
## port-object range 8003 8010
## port-object range rsh 7002

    for t_obj_key in OBJ_GRP_SVC_Dic_2.keys():
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
##                    t_Config_Change.append('\n\n===========[ Port Range: %s ]============\n' %N_of_Ports)
##                    print('\n\n===========[ Port Range: %s ]============' %N_of_Ports)
                    text_line = 'object-group service %s %s\n %s\n' %(t_obj_key,t_proto,tt_item)
##                    t_Config_Change.append(text_line)
##                    print (text_line)
                    t_html_file.append('<tr><td class="text-nowrap"><ul>\n')
                    t_html_file.append('<_L1_TEXT_> '+'<br><li>Port Range: %s</li>\n' %(N_of_Ports))
                    t_html_file.append('<_CODE_> '+'object-group service %s %s<br>\n &nbsp;&nbsp; %s<br><br>\n' %(t_obj_key,t_proto,tt_item))
                    Out = []
                    t_Out = Where_Used(t_device, t_obj_key, FW_log_folder, Out)
                    if t_Out:
                        for line in t_Out:
                            t_html_file.append(line+'<br>')
                    t_html_file.append('</ul></td></tr>\n')
##                            t_Config_Change.append(remove_tags.sub('', line.strip())+'\n')


##access-list IPMI_DP01_access_in extended permit udp object-group GR01_SE-HD5K-B object Host_SNMP_SERVER_10.206.1.18 range snmp snmptrap

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
                text_line = '\n\n==> spans %s Ports\n%s\n' %(N_of_Ports,t_item)
##                t_Config_Change.append(text_line)
##                print (text_line)
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

    try:
        with open("%s/%s"%(html_folder,config_range_html),mode="w") as html_file:
            for t in t_html_file:
                html_file.write(t)
    except:
        raise OSError("Can't write to destination file (%s/%s)!" % (html_folder,config_range_html))

##    with open("%s/%s"%(html_folder,config_range_txt),mode="w") as txt_file:
##        for t in t_Config_Change:
##            txt_file.write(t)

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
    import shelve

    hostname___ = t_device.replace('/','___')
    #log_folder = log_folder + '/' + hostname___
    hostname = t_device

    Obj_Net_Dic = None
    Obj_Net_Dic = {}
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Obj_Net_Dic')
##    try:
##        with shelve.open(tf_name) as shelve_obj: Obj_Net_Dic = shelve_obj['0']
##    except:
##        print('ERROR!!!..... File not found %s' %tf_name)
##        exit('Check_Range exit ERROR.')
    Obj_Net_Dic = utils_v2.Shelve_Read_Try(tf_name,Obj_Net_Dic)

    OBJ_SVC_Dic = None
    OBJ_SVC_Dic = {}
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'OBJ_SVC_Dic')
##    try:
##        with shelve.open(tf_name) as shelve_obj: OBJ_SVC_Dic = shelve_obj['0']
##    except:
##        print('ERROR!!!..... File not found %s' %tf_name)
##        exit('Check_Range exit ERROR.')
    OBJ_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,OBJ_SVC_Dic)

    OBJ_GRP_NET_Dic = None
    OBJ_GRP_NET_Dic = {}
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'OBJ_GRP_NET_Dic')
##    try:
##        with shelve.open(tf_name) as shelve_obj: OBJ_GRP_NET_Dic = shelve_obj['0']
##    except:
##        print('ERROR!!!..... File not found %s' %tf_name)
##        exit('Check_Range exit ERROR.')
    OBJ_GRP_NET_Dic = utils_v2.Shelve_Read_Try(tf_name,OBJ_GRP_NET_Dic)

    OBJ_GRP_SVC_Dic = None
    OBJ_GRP_SVC_Dic = {}
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'OBJ_GRP_SVC_Dic')
##    try:
##        with shelve.open(tf_name) as shelve_obj: OBJ_GRP_SVC_Dic = shelve_obj['0']
##    except:
##        print('ERROR!!!..... File not found %s' %tf_name)
##        exit('Check_Range exit ERROR.')
    OBJ_GRP_SVC_Dic = utils_v2.Shelve_Read_Try(tf_name,OBJ_GRP_SVC_Dic)
    OBJ_GRP_SVC_Dic_2 = OBJ_GRP_SVC_Dic.copy()
    for t_OBJ_GRP_SVC_Dic_key in OBJ_GRP_SVC_Dic.keys():
        if len(t_OBJ_GRP_SVC_Dic_key.split()) == 2:
            OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_SVC_Dic_key.split()[0]] = OBJ_GRP_SVC_Dic_2.pop(t_OBJ_GRP_SVC_Dic_key)

    Show_ACL_Lines = None
    Show_ACL_Lines = []
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_ACL_Lines')
##    try:
##        with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines = shelve_obj['0']
##    except:
##        print('ERROR!!!..... File not found %s' %tf_name)
##        exit('Check_Range exit ERROR.')
    Show_ACL_Lines = utils_v2.Shelve_Read_Try(tf_name,Show_ACL_Lines)


    Show_NAT_DF = None
    tf_name = "%s/VAR_%s___%s"%(log_folder,hostname___,'Show_NAT_DF')
    try:
        with shelve.open(tf_name) as shelve_obj: Show_NAT_DF = shelve_obj['0']
    except:
        print('ERROR!!!..... File not found %s' %tf_name)
        exit('Check_Range exit ERROR.')
##    Show_NAT_DF = utils_v2.Shelve_Read_Try(tf_name,Show_NAT_DF)


    if  ( (t_Object_Name in Obj_Net_Dic.keys()) or
        (t_Object_Name in OBJ_GRP_NET_Dic.keys()) or
        (t_Object_Name in OBJ_SVC_Dic.keys()) or
        (t_Object_Name in OBJ_GRP_SVC_Dic_2.keys()) ):
        # find in access-list
        Printed_Lines = []
        for t_acl_line in Show_ACL_Lines:
            if t_Object_Name in t_acl_line.strip().split():
                #print('%s found as object in ACL:\n    %s' %(t_Object_Name, t_acl_line))
                #print('"%s" found as object in ACL' %t_Object_Name) if not (t_Object_Name in Printed_Lines) else ''
                #print('    %s' %t_acl_line)
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> found as object in ACL\n' %t_Object_Name) if not (t_Object_Name in Printed_Lines) else ''
                Out.append('<_CODE_> '+'%s\n' %t_acl_line)
                Printed_Lines.append(t_Object_Name)
        #find in nat
        Printed_Lines = []
        for row in Show_NAT_DF.itertuples():
            if t_Object_Name in row.Nat_Line.strip().split():
                #print('%s found as object in NAT:\n    %s' %(t_Object_Name, row.Nat_Line))
                #print('"%s" found as object in NAT' %t_Object_Name) if not (t_Object_Name in Printed_Lines) else ''
                #print('    %s' %row.Nat_Line)
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> found as object in NAT\n' %t_Object_Name) if not (t_Object_Name in Printed_Lines) else ''
                Out.append('<_CODE_> '+'%s\n' %row.Nat_Line)
                Printed_Lines.append(t_Object_Name)

    for t_OBJ_GRP_KEY in OBJ_GRP_NET_Dic.keys():
        for t_OBJ_GRP_VALS in OBJ_GRP_NET_Dic[t_OBJ_GRP_KEY]:
            if t_Object_Name in t_OBJ_GRP_VALS.strip().split():
                #find in OBJ_GRP_NET_Dic
                #print('"%s" OBJ_GRP_NET_Dic nested found as object in "%s"' %(t_Object_Name, t_OBJ_GRP_KEY))
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> nested found as object in <b>"%s"</b>\n' %(t_Object_Name, t_OBJ_GRP_KEY))
                Where_Used(t_device, t_OBJ_GRP_KEY, log_folder, Out)

    for t_OBJ_GRP_KEY in OBJ_GRP_SVC_Dic_2.keys():
        for t_OBJ_GRP_VALS in OBJ_GRP_SVC_Dic_2[t_OBJ_GRP_KEY]:
            if t_Object_Name in t_OBJ_GRP_VALS.strip().split():
                #find in OBJ_GRP_SVC_Dic_2
                #print('"%s" OBJ_GRP_SVC_Dic_2 nested found as object in "%s"' %(t_Object_Name, t_OBJ_GRP_KEY))
                Out.append('<_L2_TEXT_> '+'<b>"%s"</b> nested found as object in <b>"%s"</b>\n' %(t_Object_Name, t_OBJ_GRP_KEY))
                Where_Used(t_device, t_OBJ_GRP_KEY, log_folder, Out)

    return Out




