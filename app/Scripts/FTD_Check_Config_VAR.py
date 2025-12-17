# pylint: disable=C0103

#----------------------------------------------------------------------------------------------------
# def VAR_FTD_Show_Run_ACGR
# def VAR_FTD_Show_Access_List
#----------------------------------------------------------------------------------------------------

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
from Check_Config_PARAM import *

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
#----- for FTD -----
re11_FTD = re.compile(r'^access-list .* line \d* advanced', re.IGNORECASE)
re12_FTD = re.compile(r'.*access-list .* line \d* advanced')

#=================================================================================================================================
#  _  _  __    ____       ____  ____  ____       ___  _   _  _____  _    _       ____  __  __  _  _         __    ___  ___  ____
# ( \/ )/__\  (  _ \     ( ___)(_  _)(  _ \     / __)( )_( )(  _  )( \/\/ )     (  _ \(  )(  )( \( )       /__\  / __)/ __)(  _ \
#  \  //(__)\  )   / ___  )__)   )(   )(_) )___ \__ \ ) _ (  )(_)(  )    (  ___  )   / )(__)(  )  (  ___  /(__)\( (__( (_-. )   /
#   \/(__)(__)(_)\_)(___)(__)   (__) (____/(___)(___/(_) (_)(_____)(__/\__)(___)(_)\_)(______)(_)\_)(___)(__)(__)\___)\___/(_)\_)
#=================================================================================================================================
def VAR_FTD_Show_Run_ACGR(t_device, Config_Change, log_folder):
    hostname___ = t_device.replace('/','___')
    Err_folder = log_folder
    log_folder = log_folder + '/' + hostname___
    global WTF_Error_FName

    text = f'VAR_FTD_Show_Run_ACGR @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    file_path = os.path.join(log_folder, f"{hostname___}___Show_Run_Access-Group.log")
    err_path = os.path.join(Err_folder, WTF_Error_FName)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            l = f.readlines()
    except FileNotFoundError:
        msg = f"File not found: {file_path} @ VAR_FTD_Show_Run_ACGR"
        print(msg)
        with open(err_path, 'a+', encoding='utf-8') as err_file:
            err_file.write(msg + '\n')
        sys.exit(msg)
    except OSError as e:
        msg = f"Error reading {file_path} @ VAR_FTD_Show_Run_ACGR: {e}"
        print(msg)
        with open(err_path, 'a+', encoding='utf-8') as err_file:
            err_file.write(msg + '\n')
        sys.exit(msg)

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Nameif_List")
    Nameif_List = utils_v2.Shelve_Read_Try(tf_name,'')

    Global_ACL_Dic = {}
    for n in range(1,len(l)):
        if l[n].startswith('access-group'):
            if l[n].split()[-1] not in ['global','per-user-override','control-plane']:
                pass
##                Accessgroup_Dic_by_if[l[n].split()[4]] = l[n].split()[1]
##                Accessgroup_Dic_by_ACL[l[n].split()[1]] = l[n].split()[4]
            elif l[n].strip().endswith('global'):
                Global_ACL_Dic['global'] = l[n].split()[1]

    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Global_ACL_Dic")
    retries = utils_v2.Shelve_Write_Try(tf_name,Global_ACL_Dic)
    if retries == 3:
        msg = f"Cannot write file {tf_name}! @ VAR_FTD_Show_Run_ACGR\n"
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(msg)

    Accessgroup_Dic_by_if = {}
    for t_if in Nameif_List:
        Accessgroup_Dic_by_if[t_if] = f'TMP_ACL_{t_if}'
    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Accessgroup_Dic_by_if")
    retries = utils_v2.Shelve_Write_Try(tf_name, Accessgroup_Dic_by_if)
    if retries == 3:
        msg = f"Cannot write file {tf_name}! @ VAR_FTD_Show_Run_ACGR\n"
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(msg)

    Accessgroup_Dic_by_ACL = {}
    for t_key in Accessgroup_Dic_by_if:
        Accessgroup_Dic_by_ACL[Accessgroup_Dic_by_if[t_key]] = t_key
    tf_name = os.path.join(log_folder, f"VAR_{hostname___}___Accessgroup_Dic_by_ACL")
    retries = utils_v2.Shelve_Write_Try(tf_name,Accessgroup_Dic_by_ACL)
    if retries == 3:
        msg = f"Cannot write file {tf_name}! @ VAR_FTD_Show_Run_ACGR\n"
        with open(err_file, "a+", encoding="utf-8") as f:
            f.write(msg)



##=======================================================================================================================================================
##  _  ___  ___    _  _  __    ____       ____  ____  ____       ___  _   _  _____  _    _         __    ___  ___  ____  ___  ___       __    ____  ___  ____    ___  ___  _
## / )(___)(___)  ( \/ )/__\  (  _ \     ( ___)(_  _)(  _ \     / __)( )_( )(  _  )( \/\/ )       /__\  / __)/ __)( ___)/ __)/ __)     (  )  (_  _)/ __)(_  _)  (___)(___)( \
##( (  ___  ___    \  //(__)\  )   / ___  )__)   )(   )(_) )___ \__ \ ) _ (  )(_)(  )    (  ___  /(__)\( (__( (__  )__) \__ \\__ \ ___  )(__  _)(_ \__ \  )(     ___  ___  ) )
## \_)(___)(___)    \/(__)(__)(_)\_)(___)(__)   (__) (____/(___)(___/(_) (_)(_____)(__/\__)(___)(__)(__)\___)\___)(____)(___/(___/(___)(____)(____)(___/ (__)   (___)(___)(_/
##
##=======================================================================================================================================================

def VAR_FTD_Show_Access_List(t_device, Config_Change, log_folder):
    hostname___ = t_device.replace('/','___')
    log_folder = f"{log_folder}/{hostname___}"
    html_folder = log_folder

    text = f'VAR_FTD_Show_Access_List @ {hostname___}'
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)
    start = datetime.datetime.now()
    print(f'start time is {start}')

    tf_name = f"{log_folder}/VAR_{hostname___}___Global_ACL_Dic"
    Global_ACL_Dic = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_if"
    Accessgroup_Dic_by_if = utils_v2.Shelve_Read_Try(tf_name,'')

    tf_name = f"{log_folder}/VAR_{hostname___}___Accessgroup_Dic_by_ACL"
    Accessgroup_Dic_by_ACL = utils_v2.Shelve_Read_Try(tf_name,'')

    Show_ACL_Lines = []
    ACL_List_Dict = {}
    ACL_List = []
    ACL_remark_Lines = []

    Show_ACL_Lines_Global = []
    ACL_List_Dict_Global = {}
    ACL_List_Global = []
    #ACL_remark_Lines_Global = []

    try:
        with open(f"{log_folder}/{hostname___}___Show_Access-List.log", 'r', encoding='utf-8', errors='ignore') as f:
            pass
    except FileNotFoundError:
        print(f'File not found: {log_folder}/{hostname___}___Show_Access-List.log @ CREATE VARIABLES')
        sys.exit(f'File not found: {log_folder}/{hostname___}___Show_Access-List.log @ CREATE VARIABLES')
    except Exception as e:
        print(f'Unexpected error reading ACL file: {e}')
        sys.exit(f'Unexpected error reading ACL file: {e}')

    Global_ACL_Name = Global_ACL_Dic['global']
    with open(f"{log_folder}/{hostname___}___Show_Access-List.log", 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            l = line.rstrip()
            if ' trust ' in l:
                print(f'TRUST ACL: {l}')
                l = l.replace(' trust ',' permit ')
            if not l.isascii():
                continue
            l_parts = l.split()

            #re11_FTD = re.compile('^access-list .* line \d* advanced', re.IGNORECASE)   # seleziona acl advanced only
            if re11_FTD.match(l):
                if l_parts[1] not in ACL_List_Global:
                    ACL_List_Global.append(l_parts[1])
                if l_parts[1] == Global_ACL_Name:
                    if 'remark' not in l:
                        Show_ACL_Lines_Global.append(l)

            #re3 = re.compile('^access-list .* line', re.IGNORECASE) # a questo punto dovrebbero rimanere solo le std acl e remark
            elif re3.match(l):
                if l_parts[1] not in ACL_List: # evaluate to hide this part
                    ACL_List.append(l_parts[1])
                if 'remark' in l:
                    ACL_remark_Lines.append(l)

            #re5 = re.compile(r'^\s*$') # empty line
            elif re5.match(l):
                continue

            #re2 = re.compile('access-list .* element', re.IGNORECASE)
            elif re2.match(l):
                continue

            if l_parts[1] == Global_ACL_Name:
                # re12_FTD = re.compile('.*access-list .* line \d* advanced')
                # remove remark
                if re12_FTD.match(l):
                    if '(inactive)' not in l:
                        if l.startswith('access-list '):
                            if l not in ACL_List_Dict_Global:
                                if 'object' not in l:
                                    ACL_List_Dict_Global[l] = [l]
                                else:
                                    ACL_List_Dict_Global[l] = []
                                t_Key = l
                                t_ACL_Line = l_parts[3]
                        elif l.startswith('  access-list'):
                            if l_parts[3] == t_ACL_Line:
                                ACL_List_Dict_Global[t_Key].append(l)

##    Show_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(Show_ACL_Lines)
    Show_ACL_Lines_Global_DF = utils_v2.FTD_ACL_to_DF(Show_ACL_Lines_Global)

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


    for t_key, acl_lines in ACL_List_Dict_Global.items():
        if '(inactive)' not in t_key:
            t_N_ACL_Lines_Expanded += len(acl_lines)

            # Expanded_ACL_List --- start
            if len(acl_lines) >= Max_ACL_Expand_Ratio:
                Expanded_ACL_List.append([len(acl_lines), t_key])
                temp = utils_v2.FTD_ACL_to_DF([t_key])
                t_line_N = int(temp.Line[0].split()[1])
                Expanded_ACL_List_bis.append([len(acl_lines), temp.Name[0], t_line_N, t_key])
                t_N_ACL_Oversize_Expanded += len(acl_lines)
            # Expanded_ACL_List --- end

        t_ACL_Expanded_DF = utils_v2.FTD_ACL_to_DF(acl_lines)
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
##    #Expanded_ACL_List_bis_df = pd.DataFrame(Expanded_ACL_List_bis, columns = ['X_Lines', 'Name', 'Line#', 'ACL'])
##    #Expanded_ACL_List_bis_df = Expanded_ACL_List_bis_df.sort_values(['Name', 'Line#'], ascending = (True,False))
    Splitted_ACL = []
    Splitted_ACL_Wrap = []

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


    # --- convert -----------------------------------------------
    # - Show_ACL_Lines_Global
    # - ACL_List_Dict_Global
    # to their ASA equivalent
    # - Show_ACL_Lines
    # - Show_ACL_Lines_DF
    # - ACL_List_Dict
    for t_row_index, t_row in Show_ACL_Lines_Global_DF.iterrows():
        if t_row['IF_in'].startswith('ifc '):
            if t_row['IF_in'].strip('ifc ') in Accessgroup_Dic_by_if:
                IF_name = t_row['IF_in'].strip('ifc ')
                temp_line = ( t_row['ACL'],
                              Accessgroup_Dic_by_if[IF_name],
                              t_row['Line'],
                              'extended',
                              t_row['Action'],
                              t_row['Service'],
                              t_row['Source'],
                              t_row['S_Port'],
                              t_row['Dest'],
                              t_row['D_Port'],
                              t_row['Rest'],
                              t_row['Inactive'],
                              f"(hitcnt={t_row['Hitcnt']})",
                              f"{t_row['Hash']}_{IF_name}")
                temp_line = re.sub(r'\s+', ' ', ' '.join(temp_line))
                Show_ACL_Lines.append(temp_line)
        else: # same acl to all interfaces
            for t_if in Accessgroup_Dic_by_if:
                temp_line = ( t_row['ACL'],
                              Accessgroup_Dic_by_if[t_if],
                              t_row['Line'],
                              'extended',
                              t_row['Action'],
                              t_row['Service'],
                              t_row['Source'],
                              t_row['S_Port'],
                              t_row['Dest'],
                              t_row['D_Port'],
                              t_row['Rest'],
                              t_row['Inactive'],
                              f"(hitcnt={t_row['Hitcnt']})",
                              #t_row['Hash'])
                              f"{t_row['Hash']}_{t_if}")
                temp_line = re.sub(r'\s+', ' ', ' '.join(temp_line))
                Show_ACL_Lines.append(temp_line)

    Show_ACL_Lines_DF = utils_v2.ASA_ACL_to_DF(Show_ACL_Lines)

    ACL_List_Dict={}
    for t_key in ACL_List_Dict_Global:
        t_key_DF = utils_v2.FTD_ACL_to_DF([t_key])
        if t_key_DF['IF_in'][0].startswith('ifc '):
            if t_key_DF['IF_in'][0].strip('ifc ') in Accessgroup_Dic_by_if:
                IF_name = t_key_DF['IF_in'][0].strip('ifc ')
                new_key = ( t_key_DF['ACL'][0],
                              Accessgroup_Dic_by_if[IF_name],
                              t_key_DF['Line'][0],
                              'extended',
                              t_key_DF['Action'][0],
                              t_key_DF['Service'][0],
                              t_key_DF['Source'][0],
                              t_key_DF['S_Port'][0],
                              t_key_DF['Dest'][0],
                              t_key_DF['D_Port'][0],
                              t_key_DF['Rest'][0],
                              t_key_DF['Inactive'][0],
                              f"(hitcnt={t_key_DF['Hitcnt'][0]})",
                              #t_key_DF['Hash'][0])
                              f"{t_key_DF['Hash'][0]}_{IF_name}")
                new_key = re.sub(r'\s+', ' ', ' '.join(new_key))
                items_DF = utils_v2.FTD_ACL_to_DF(ACL_List_Dict_Global[t_key])
                temp_sub_acls = []
                for _, t_items_DF in items_DF.iterrows():
                    if t_items_DF['IF_in'].startswith('ifc '):
                        if t_items_DF['IF_in'].strip('ifc ') in Accessgroup_Dic_by_if:
                            IF_name = t_items_DF['IF_in'].strip('ifc ')
                            temp_line = ( t_items_DF['ACL'],
                                          Accessgroup_Dic_by_if[IF_name],
                                          t_items_DF['Line'],
                                          'extended',
                                          t_items_DF['Action'],
                                          t_items_DF['Service'],
                                          t_items_DF['Source'],
                                          t_items_DF['S_Port'],
                                          t_items_DF['Dest'],
                                          t_items_DF['D_Port'],
                                          t_items_DF['Rest'],
                                          t_items_DF['Inactive'],
                                          f"(hitcnt={t_items_DF['Hitcnt']})",
                                          #t_items_DF['Hash'])
                                          f"{t_items_DF['Hash']}_{IF_name}")
                            temp_line = re.sub(r'\s+', ' ', ' '.join(temp_line))
                            temp_sub_acls.append(temp_line)
            ACL_List_Dict[new_key] = temp_sub_acls
        else:
            for t_if in Accessgroup_Dic_by_if:
                temp_line = ( t_key_DF['ACL'][0],
                              Accessgroup_Dic_by_if[t_if],
                              t_key_DF['Line'][0],
                              'extended',
                              t_key_DF['Action'][0],
                              t_key_DF['Service'][0],
                              t_key_DF['Source'][0],
                              t_key_DF['S_Port'][0],
                              t_key_DF['Dest'][0],
                              t_key_DF['D_Port'][0],
                              t_key_DF['Rest'][0],
                              t_key_DF['Inactive'][0],
                              f"(hitcnt={t_key_DF['Hitcnt'][0]})",
                              #t_key_DF['Hash'][0])
                              f"{t_key_DF['Hash'][0]}_{IF_name}")
                new_key = re.sub(r'\s+', ' ', ' '.join(temp_line))
                items_DF = utils_v2.FTD_ACL_to_DF(ACL_List_Dict_Global[t_key])
                temp_sub_acls = []
                for _, t_items_DF in items_DF.iterrows():
                    temp_line = ( t_items_DF['ACL'],
                                  Accessgroup_Dic_by_if[t_if],
                                  t_items_DF['Line'],
                                  'extended',
                                  t_items_DF['Action'],
                                  t_items_DF['Service'],
                                  t_items_DF['Source'],
                                  t_items_DF['S_Port'],
                                  t_items_DF['Dest'],
                                  t_items_DF['D_Port'],
                                  t_items_DF['Rest'],
                                  t_items_DF['Inactive'],
                                  f"(hitcnt={t_items_DF['Hitcnt']})",
                                  #t_items_DF['Hash'])
                                  f"{t_items_DF['Hash']}_{t_if}")
                    temp_line = re.sub(r'\s+', ' ', ' '.join(temp_line))
                    temp_sub_acls.append(temp_line)
                ACL_List_Dict[new_key] = temp_sub_acls



    #------------------------------------------------------------

    tf_name = f'{log_folder}/VAR_{hostname___}___Show_ACL_Lines'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Show_ACL_Lines)
    if retries == 3:
        print(err_line)
        with open(f'{Err_folder}/{WTF_Error_FName}',"a+") as f:
            f.write(err_line)

    tf_name = f'{log_folder}/VAR_{hostname___}___Show_ACL_Lines_Global'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Show_ACL_Lines_Global)
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

    tf_name = f'{log_folder}/VAR_{hostname___}___Show_ACL_Lines_Global_DF'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,Show_ACL_Lines_Global_DF)
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

    tf_name = f'{log_folder}/VAR_{hostname___}___ACL_List_Dict_Global'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_List_Dict_Global)
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

    tf_name = f'{log_folder}/VAR_{hostname___}___ACL_List_Global'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    retries = utils_v2.Shelve_Write_Try(tf_name,ACL_List_Global)
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

    # convert ACL_Expanded_DF to ASA format ---------------------
    rows = []
    for _, row in ACL_Expanded_DF.iterrows():
        if not row['IF_in']:  # empty IF_in
            for t_if in Accessgroup_Dic_by_if:
                new_row = row.copy()
                new_row['Name'] = Accessgroup_Dic_by_if[t_if]
                new_row['Root_Key'] = row['Root_Key'].replace('CSM_FW_ACL_', Accessgroup_Dic_by_if[t_if])
                new_row['Print'] = row['Print'].replace('CSM_FW_ACL_', Accessgroup_Dic_by_if[t_if])
                rows.append(new_row)
        else:
            new_row = row.copy()
            t_iface = row['IF_in'].strip('ifc ')
            new_row['Name'] = Accessgroup_Dic_by_if[t_iface]
            new_row['Root_Key'] = row['Root_Key'].replace('CSM_FW_ACL_', Accessgroup_Dic_by_if[t_iface])
            new_row['Print'] = row['Print'].replace('CSM_FW_ACL_', Accessgroup_Dic_by_if[t_iface])
            rows.append(new_row)

    ACL_Expanded_DF_new = pd.DataFrame(rows).reset_index(drop=True)
    ACL_Expanded_DF_new = ACL_Expanded_DF_new.drop(columns=['IF_in', 'IF_out', 'rule-id'])
    ACL_Expanded_DF = ACL_Expanded_DF_new

    tf_name = f'{log_folder}/VAR_{hostname___}___ACL_Expanded_DF'
    err_line = f'Can Not Write File {tf_name} @ VAR_Show_Access_List\n'
    for c in ["S_Port", "D_Port", "Source", "Dest"]:
        if c in ACL_Expanded_DF.columns:
            ACL_Expanded_DF[c] = ACL_Expanded_DF[c].apply(lambda x: json.dumps(x) if isinstance(x, (list, tuple)) else x)
    ACL_Expanded_DF.to_feather(f"{tf_name}.feather", compression="zstd")

    end = datetime.datetime.now()
    print(f'VAR Show_Access_List elapsed time is: {str(end-start)}')
    return Config_Change
