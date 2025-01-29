
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
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obejct_by_value_Dict"
    Obejct_by_value_Dict = utils_v2.Shelve_Read_Try(tf_name,'')

    Obejct_by_value_Dict_one = {}
    Obejct_by_value_Dict_two = {}
    for t_key in Obejct_by_value_Dict.keys():
        if len(Obejct_by_value_Dict[t_key]) == 1:
            Obejct_by_value_Dict_one[t_key] = Obejct_by_value_Dict[t_key][0]
        else:
            Obejct_by_value_Dict_two[t_key] = Obejct_by_value_Dict[t_key]

    insert_New_Flag = False

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

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Obj_Net_Dic"
    Obj_Net_Dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___OBJ_GRP_NET_Dic"
    OBJ_GRP_NET_Dic = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines"
    Show_ACL_Lines = utils_v2.Shelve_Read_Try(tf_name,'')

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
        with open("%s/%s___Show_Nat_Detail.log"%(FW_log_folder,hostname___),'r', encoding='utf-8', errors='replace') as f:
            nat_file = f.readlines()
    except:
        print('file %s/%s___Show_nat.log not found! @ CREATE VARIABLES' %(FW_log_folder,hostname___))
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

    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_List"
    ACL_List = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines_DF"
    Show_ACL_Lines_DF = utils_v2.Shelve_Read_Try(tf_name,'')
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_Expanded_DF"
    ACL_Expanded_DF = utils_v2.Shelve_Read_Try(tf_name,'')

    text = ('Shadowed ACLs @ %s' %hostname___)
    utils_v2.Text_in_Frame (text, Config_Change, Print_also=1)

    expected_running_time = round(len(ACL_Expanded_DF)*len(ACL_Expanded_DF)/13000/2/60)
    print('This is going to take approx %s mins.' %str(expected_running_time))
    print('started at: %s' %datetime.datetime.now().strftime('%H:%M:%S - %d/%m/%Y'))
    if expected_running_time > 60:
         STEPS = 20
    else:
         STEPS = 10

    BINS = 0; LOOP_INDEX = -1; ITEMS = len(Show_ACL_Lines_DF)#  STEPS = 20

    for t_ACL_Name in ACL_List:

        Bool_check = ('Name == "%s"') %(t_ACL_Name)
        t_Root_ACL_lines = Show_ACL_Lines_DF.query(Bool_check)
        if len(t_Root_ACL_lines) == 0:
            continue

        for ACL_index in range(max(t_Root_ACL_lines.index), min(t_Root_ACL_lines.index)-1, -1):
            Line_Number_Printed = False

            LOOP_INDEX = LOOP_INDEX + 1
            if LOOP_INDEX > (ITEMS/STEPS)*BINS:
                print ('...%s%%' %int(BINS*100/STEPS)); BINS = BINS + 1

            t_Root_ACL_line_df_Name = t_Root_ACL_lines.loc[ACL_index].Name
            t_Root_ACL_line_df_Line = t_Root_ACL_lines.loc[ACL_index].Line

            Bool_check = ('Name == "%s" & Line == "%s"') %(t_Root_ACL_line_df_Name, t_Root_ACL_line_df_Line)
            ACL_Line_Expanded_DF = ACL_Expanded_DF.query(Bool_check)
            ACL_Line_Expanded_DF_Print = pd.DataFrame(ACL_Line_Expanded_DF[['Print','Hitcnt']])
            ACL_Line_Expanded_DF_Print['T_Shadowed'] = 0
            ACL_Line_Expanded_DF_Print['P_Shadowed'] = 0

            Bool_check = ('Name == "%s"') %(t_Root_ACL_line_df_Name)
            ACL_Slice_Expanded_DF = ACL_Expanded_DF.query(Bool_check)

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
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___Show_ACL_Lines_DF"
    Show_ACL_Lines_DF = utils_v2.Shelve_Read_Try(tf_name,'')
##    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'Show_ACL_Lines_DF')
##    with shelve.open(tf_name) as shelve_obj: Show_ACL_Lines_DF = shelve_obj['0']
    tf_name = f"{FW_log_folder}/VAR_{hostname___}___ACL_List_Dict"
    ACL_List_Dict = utils_v2.Shelve_Read_Try(tf_name,'')
##    tf_name = "%s/VAR_%s___%s"%(FW_log_folder,hostname___,'ACL_List_Dict')
##    with shelve.open(tf_name) as shelve_obj: ACL_List_Dict = shelve_obj['0']
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


