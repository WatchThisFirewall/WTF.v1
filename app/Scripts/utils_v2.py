#!/usr/bin/env python3 @ asacheck config

import argparse
import os
import re
import errno
import logging
import json
import pandas as pd
import ipaddress
import shelve
import time
import datetime

#=============================================================================================================================
def Get_Args():
    """
    Parse command line arguments
    example: -d FW-ALPHA-01 -f -r
    """

    parser = argparse.ArgumentParser(description=(''))
    parser.add_argument("-d", action="store", default= "", type=str, help=("-d My_Hostname => Hostname to check"))
    parser.add_argument("-e", action="store_false", required=False,  help=("-e = Do not See Elapsed Time"))
    parser.add_argument("-f", action="store_false", required=False,  help=("-f = Read Local Files (if omitted connect to device)"))
    parser.add_argument("-r", action="store_false", required=False,  help=("-r = Do not Rebuild Variables (if omitted Rebuild Variables)"))
    parser.add_argument("-p", action="store_true", required=False,   help=("-p = Parallel Processing (if omitted serial processing)"))
    # validate user input
    return parser.parse_args()


#=============================================================================================================================
def ASA_ACL_to_DF(Show_ACL_Lines):
    """
    Converts the output from the "show access-list" command in a DataFrame
    ##re3 = re.compile('^access-list .* line', re.IGNORECASE)
    Show_ACL_Lines is a list
    """

    re1 = re.compile(r'hitcnt=\d*', re.IGNORECASE)
    re2 = re.compile(r'inactive', re.IGNORECASE)
    re10 = re.compile(r'\(hitcnt=\d*\)')
    re11 = re.compile(r'inactive')
    re12 = re.compile(r'\(\)')
    temp_list = []
    for n in Show_ACL_Lines:
        temp_item = []
        if ' fqdn ' in n:
            continue
        if 'remark' in n:
            continue
        l = n.split()
        s = 1
        l.insert(s,'?') #access-list
        s = s + 2
        l.insert(s,'?') # acl_name
        s = s + 3 #6
        l.insert(s,'?') # line xxx
        s = s + 2 #8
        if l[s-1] == 'standard':
            continue
        l.insert(s,'?') #extended
        s = s + 2 #10
        l.insert(s,'?') # permit

        if l[s+1] in ['icmp6','tcp','udp','ip','icmp','gre','ah','eigrp','esp','igmp','igrp','ipinip','ipsec','nos','ospf','pcp','pim','pptp','sctp','snp']:
            s = s + 2 # 12
            l.insert(s,'?')
        elif 'object' in l[s+1]: #service-object
            s = s + 3 #13
            l.insert(s,'?')
        elif 'host' in l[s+1]: #standard ACL ------------------ da gestire
            print('ACL non gestita: "%s"' %n)
        else:
            try:
                isinstance(int(l[s+1]), int) #check if is integer
                s = s + 2 # 12
                l.insert(s,'?')
            except:
                print('%s non riconosciuto in "utils.py"' %l[s+1])
                exit(1)

        #source field
        if l[s+1].count('.') == 3:
            s = s + 3
            l.insert(s,'?')
        elif '/' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif 'any' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif l[s+1] == 'range': # range nel source ip
            s = s + 4
            l.insert(s,'?')
        else:
            s = s + 3
            l.insert(s,'?')
        # check source port if used
        if l[s+1] in ['eq','gt','lt','neq']:
            s = s + 3
            l.insert(s,'?')
        elif l[s+1] == 'range': # range nel source port
            if l[s+2].count('.') != 3:
                s = s + 4
                l.insert(s,'?')
            else:
                s = s + 1
                l.insert(s,'?')
        else:
            s = s + 1
            l.insert(s,'?')

        #dest field
        if l[s+1].count('.') == 3:
            s = s + 3
            l.insert(s,'?')
        elif '/' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif 'any' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif l[s+1] == 'range': #range nel dest ip
            s = s + 4
            l.insert(s,'?')
        else:
            s = s + 3
            l.insert(s,'?')

        # check dest port if used
        try:
            if l[s+1] in ['eq','gt','lt','neq']:
                s = s + 3
                l.insert(s,'?')
            elif l[s+1] == 'range':
                s = s + 4
                l.insert(s,'?')
            elif 'object' in l[s+1]: #service-object
                s = s + 3 #13
                l.insert(s,'?')
            else:
                s = s + 1
                l.insert(s,'?')
        except:
                s = s + 1
                l.insert(s,'?')

        j = ' '.join(l)
        l = j.split('?')
        for n in range(0,len(l)):
            l[n] = l[n].strip()

        temp_item = l
        temp_list.append(temp_item)

    col_names = ['ACL', 'Name', 'Line', 'Type', 'Action', 'Service', 'Source', 'S_Port','Dest','D_Port','Rest','Inactive','Hitcnt','Hash']
    for n in range(0,len(temp_list)):
        t_rest = temp_list[n][-1]
        t_hash = t_rest.split(' ')[-1]
        try:
            t_hitcnt = str(re1.search(t_rest)[0].split('=')[1])
        except:
            print('AIO!!! %s @ %s' %(t_rest,n))
        try:
            t_inactive = re2.search(t_rest)[0]
        except:
            t_inactive = ''
        t_rest = ' '.join(t_rest.split(' ')[:-1])
        t_rest = re10.sub('', t_rest)
        t_rest = re11.sub('', t_rest)
        t_rest = (re12.sub('', t_rest)).strip()
        temp_list[n][-1] = t_rest
        temp_list[n].append(t_inactive)
        temp_list[n].append(t_hitcnt)
        temp_list[n].append(t_hash)
    a = pd.DataFrame(temp_list, columns = col_names)

    return a


#=============================================================================================================================
def ASA_ACL_to_DF_light(Show_ACL_Lines):
    """
    Converts the output from the "show access-list" negletging from the command in a DataFrame
    ##re3 = re.compile('^access-list .* line', re.IGNORECASE)
    'Rest' = 'D_Port','Rest','Inactive','Hitcnt','Hash'
    """

    re1 = re.compile(r'hitcnt=\d*', re.IGNORECASE)
    re2 = re.compile(r'inactive', re.IGNORECASE)
    re10 = re.compile(r'\(hitcnt=\d*\)')
    re11 = re.compile(r'inactive')
    re12 = re.compile(r'\(\)')
    temp_list = []
    for n in Show_ACL_Lines:
        temp_item = []
        if ' fqdn ' in n:
            continue
        if 'remark' in n:
            continue
        l = n.split()
        s = 1
        l.insert(s,'?') #access-list
        s = s + 2
        l.insert(s,'?') # acl_name
        s = s + 3 #6
        l.insert(s,'?') # line xxx
        s = s + 2 #8
        if l[s-1] == 'standard':
            continue
        l.insert(s,'?') #extended
        s = s + 2 #10
        l.insert(s,'?') # permit

        if l[s+1] in ['icmp6','tcp','udp','ip','icmp','gre','ah','eigrp','esp','igmp','igrp','ipinip','ipsec','nos','ospf','pcp','pim','pptp','sctp','snp']:
            s = s + 2 # 12
            l.insert(s,'?')
        elif 'object' in l[s+1]: #service-object
            s = s + 3 #13
            l.insert(s,'?')
        elif 'host' in l[s+1]: #standard ACL ------------------ da gestire
            print('ACL non gestita: "%s"' %n)
        else:
            try:
                isinstance(int(l[s+1]), int) #check if is integer
                s = s + 2 # 12
                l.insert(s,'?')
            except:
                print('%s non riconosciuto in "utils.py"' %l[s+1])
                exit(1)

        #source field
        if l[s+1].count('.') == 3:
            s = s + 3
            l.insert(s,'?')
        elif '/' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif 'any' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif l[s+1] == 'range': # range nel source ip
            s = s + 4
            l.insert(s,'?')
        else:
            s = s + 3
            l.insert(s,'?')
        # check source port if used
        if l[s+1] in ['eq','gt','lt','neq']:
            s = s + 3
            l.insert(s,'?')
        elif l[s+1] == 'range': # range nel source port
            if l[s+2].count('.') != 3:
                s = s + 4
                l.insert(s,'?')
            else:
                s = s + 1
                l.insert(s,'?')
        else:
            s = s + 1
            l.insert(s,'?')

        #dest field
        if l[s+1].count('.') == 3:
            s = s + 3
            l.insert(s,'?')
        elif '/' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif 'any' in l[s+1]:
            s = s + 2
            l.insert(s,'?')
        elif l[s+1] == 'range': #range nel dest ip
            s = s + 4
            l.insert(s,'?')
        else:
            s = s + 3
            l.insert(s,'?')

        j = ' '.join(l)
        l = j.split('?')
        for n in range(0,len(l)):
            l[n] = l[n].strip()
        temp_item = l
        temp_list.append(temp_item)

    col_names = ['ACL', 'Name', 'Line', 'Type', 'Action', 'Service', 'Source', 'S_Port','Dest','Rest']
    a = pd.DataFrame(temp_list, columns = col_names)
    return a


#=============================================================================================================================
def Text_in_Frame(some_text,OutBuffer=[],Print_also=0):
    """
    given a text it will print int into a frame
    if Print_also == 1 fa anche print
    if Print_also == 2 fa solo print
    """
    beginning = '!  '
    strt = '('
    stop = ')'
    Base_Lent = 70
    LENT = Base_Lent+6

    if (Print_also == 1) or (Print_also == 2):
        print ("!")
        print (beginning + strt + '='*(LENT-2) + stop)
        print (beginning + strt + '==' + '{:^70}'.format(some_text.title()) + '==)')
        print (beginning + strt + '='*(LENT-2) + stop)
        print ("!")
    if (Print_also != 2):
        OutBuffer.append ('!')
        OutBuffer.append (beginning + strt + '='*(LENT-2) + stop)
        OutBuffer.append (beginning + strt + '==' + '{:^70}'.format(some_text.title()) + '==)')
        OutBuffer.append (beginning + strt + '='*(LENT-2) + stop)
        OutBuffer.append ("!")
        return(OutBuffer)


#=============================================================================================================================
def ASA_ACL_Obj_to_Net(IN_ACL_Obj):
    this_host = []
    #print (IN_ACL_Obj)

    if 'host' in IN_ACL_Obj:
        try:
            t_IP = ipaddress.ip_interface(IN_ACL_Obj.split()[1])
            if t_IP.version == 4:
                this_host = ['%s 255.255.255.255' %IN_ACL_Obj.split()[1]]
            elif t_IP.version == 6:
            # it is IPv6 and do something
                this_host = []
        except:
            print ('1. Unhandled Exception in "IN_ACL_Obj@"utils.ASA_ACL_Obj_to_Net')
            print ('===> %s' %IN_ACL_Obj)
            exit(247)

    elif 'any' in IN_ACL_Obj:
        this_host = ['0.0.0.0 0.0.0.0']

    elif 'any4' in IN_ACL_Obj:
        this_host = ['0.0.0.0 0.0.0.0']

    elif 'range' in IN_ACL_Obj:
        first_host = IN_ACL_Obj.split()[1]
        last_host  = IN_ACL_Obj.split()[2]
        if (int(ipaddress.IPv4Address(last_host))-int(ipaddress.IPv4Address(first_host))) < 1024:
            temp = ipaddress.IPv4Address(first_host)
            while ipaddress.IPv4Address(temp) <= ipaddress.IPv4Address(last_host):
                this_host.append(str(ipaddress.IPv4Address(temp))+' 255.255.255.255')
                temp = temp + 1
        else:
            print(f'ERROR in ASA_ACL_Obj_to_Net! - IP RANGE > 1024 for {IN_ACL_Obj}')
            this_host = ['%s 255.255.255.255' %IN_ACL_Obj.split()[1]]

    elif IN_ACL_Obj.count('.') == 6:
        if len(IN_ACL_Obj.split()) == 2:
            this_host = ['%s %s' %(IN_ACL_Obj.split()[0],IN_ACL_Obj.split()[1])]

    elif (':' in IN_ACL_Obj):
        # check if it is IPv6 and do something
        this_host = []

    else:
        print ('2. Unhandled Exception in "IN_ACL_Obj@"utils.ASA_ACL_Obj_to_Net')
        print ('===> %s' %IN_ACL_Obj)
        exit(100)

    return this_host


#=============================================================================================================================
from Network_Calc import Sub_Mask_2
def ASA_ACL_Obj_to_IP(IN_ACL_Obj):
    this_host = []

    if (':' in IN_ACL_Obj):
        # check if it is IPv6 and do something
        this_host = [-1]

    elif 'host' in IN_ACL_Obj:
        try:
            t_IP = ipaddress.ip_interface(IN_ACL_Obj.split()[1])
            if t_IP.version == 4:
                this_host = ['%s/32' %IN_ACL_Obj.split()[1]]
            elif t_IP.version == 6:
            # it is IPv6 and do something
                this_host = []
        except:
            print ('1. Unhandled Exception in "IN_ACL_Obj@"utils.ASA_ACL_Obj_to_IP')
            print ('===> %s' %IN_ACL_Obj)
            exit(247)

    elif 'any' in IN_ACL_Obj:
        this_host = ['0.0.0.0/0']

    elif 'any4' in IN_ACL_Obj:
        this_host = ['0.0.0.0/0']

    elif 'range' in IN_ACL_Obj:
        first_host = IN_ACL_Obj.split()[1]
        last_host  = IN_ACL_Obj.split()[2]
        if (int(ipaddress.IPv4Address(last_host))-int(ipaddress.IPv4Address(first_host))) < 1024:
            temp = ipaddress.IPv4Address(first_host)
            while ipaddress.IPv4Address(temp) <= ipaddress.IPv4Address(last_host):
                this_host.append(str(ipaddress.IPv4Address(temp))+'/32')
                temp = temp + 1
        else:
            print(f'ERROR in ASA_ACL_Obj_to_IP! - IP RANGE > 1024 for {IN_ACL_Obj}')
            this_host = ['%s/32' %IN_ACL_Obj.split()[1]]

    elif IN_ACL_Obj.count('.') == 6:
        if len(IN_ACL_Obj.split()) == 2:
            try:
                this_host = ['%s%s' %(IN_ACL_Obj.split()[0],Sub_Mask_2[IN_ACL_Obj.split()[1]])]
            except:
                # subnet mask errata
                print('wrong subnet mask in %s %s, rendering it as /32' % (IN_ACL_Obj.split()[0], IN_ACL_Obj.split()[1]))
                this_host = ['%s/32' %(IN_ACL_Obj.split()[0])]

    else:
        print ('2. Unhandled Exception in "IN_ACL_Obj@"utils.ASA_ACL_Obj_to_IP')
        print ('===> %s' %IN_ACL_Obj)
        exit(100)

    if (this_host != [-1]) :
        for n in range (0,len(this_host)):
            this_host[n] = ipaddress.IPv4Network(this_host[n], strict=False)

    return this_host


#=============================================================================================================================
def ASA_ACL_Obj_to_DecIP(IN_ACL_Obj):
    # return something like [[3232235778, 4294967040]]
    # for ranges becomes [[3232235778, 4294967295], [3232235779, 4294967295], [3232235780, 4294967295], ...]
    from Network_Calc import IPv4_to_DecList

    this_host = []

    if 'host' in IN_ACL_Obj:
        this_host = IPv4_to_DecList(IN_ACL_Obj.split()[1], '255.255.255.255')

    elif 'any' in IN_ACL_Obj:
        this_host = [0, 0]

    elif 'any4' in IN_ACL_Obj:
        this_host = [0, 0]

    elif 'range' in IN_ACL_Obj:
        first_host = IPv4_to_DecList(IN_ACL_Obj.split()[1], '255.255.255.255')[0]
        last_host  = IPv4_to_DecList(IN_ACL_Obj.split()[2], '255.255.255.255')[0]
        if (last_host - first_host) < 1024:
            while first_host <= last_host:
                this_host.append([first_host, 4294967295])
                first_host = first_host + 1
            return this_host
        else:
            print(f'ERROR in ASA_ACL_Obj_to_DecIP! - IP RANGE > 1024 for {IN_ACL_Obj}')
            this_host = [first_host, 4294967295]

    elif IN_ACL_Obj.count('.') == 6:
        this_host = IPv4_to_DecList(IN_ACL_Obj.split()[0], IN_ACL_Obj.split()[1])

    elif (':' in IN_ACL_Obj):
        # check if it is IPv6 and do something
        this_host = [-1, -1]

    else:
        print ('2. Unhandled Exception in "IN_ACL_Obj@"utils.ASA_ACL_Obj_to_DecIP')
        print ('===> %s' %IN_ACL_Obj)
        exit(100)

    return [this_host]


#=============================================================================================================================
def ASA_NAT_to_DF(Show_NAT_Lines):
    """
    Converts the output from the "show nat" command in a DataFrame
    """

    re1 = re.compile(r'hitcnt=\d*', re.IGNORECASE)
    re2 = re.compile(r'inactive', re.IGNORECASE)
    re10 = re.compile(r'\(hitcnt=\d*\)')
    re11 = re.compile(r'inactive')
    re12 = re.compile(r'\(\)')
    temp_list = []
    for n in Show_NAT_Lines:
        continue


#=============================================================================================================================
def Shelve_Write_Try(tf_name,Temp_Var):
    import gc

    retries = 0
    while retries <3:
        try:
            shelve_obj = shelve.open(tf_name, "c")
            shelve_obj['0'] = Temp_Var
            shelve_obj.close()
            gc.collect()
            return retries
        except:
            retries +=1
            time.sleep(retries*2)
            gc.collect()
    if retries == 3:
        print('ERROR!!! Cannot write to shelve file %s' %tf_name)
        return retries


#=============================================================================================================================
def Shelve_Read_Try(tf_name,Temp_Var):
    import gc

    retries = 0
    while retries <3:
        try:
            with shelve.open(tf_name, writeback=False) as shelve_obj: Temp_Var = shelve_obj['0']
            shelve_obj.close()
            gc.collect()
            return Temp_Var
        except:
            retries +=1
            time.sleep(retries*2)
            gc.collect()
    if retries == 3:
        print('ERROR!!! Cannot read shelve file %s' %tf_name)


#=============================================================================================================================
def File_Save_Try(tf_name,Temp_Var):

    retries = 0
    while retries < 3:
        try:
            with open(tf_name, "w") as f:
                for line in Temp_Var:
                    f.write(line)
                print('... saved file "%s"' %tf_name)
                return retries
        except:
            retries +=1
            time.sleep(retries*2)
    if retries == 3:
        print('ERROR!!! Cannot write to file %s' %tf_name)
        return retries


#=============================================================================================================================

def File_Save_Try2(g_DestFileFullName, g_List, g_ErrFileFullName, Config_Change):
    # return "row" for writing it to DB as:
        #row = {'TimeStamp' : datetime.datetime.now().astimezone(),
        #       'Level'     : 'ERROR',
        #       'Message'   : (f"Can't write to destination file {html_folder}/{Watch_FName}")}
    #with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))

    retries = 0
    while retries < 3:
        try:
            with open(g_DestFileFullName, "w+", encoding="utf-8", errors="replace") as f:
                for t_line in g_List:
                    f.write(t_line)
            print(f'... saved file "{g_DestFileFullName}" ')
            Config_Change.append(f'... saved file "{g_DestFileFullName}"')
            return ''
        except Exception as e:
            retries +=1
            time.sleep(retries*2)
            if retries == 3:
                print(f"ERROR! Can't write to destination file {g_DestFileFullName}")
                print(f'error is: {e}')
                with open(g_ErrFileFullName, "a+") as f:
                    f.write(f"ERROR! Can't write to destination file {g_DestFileFullName}")
                    f.write(f"error is: {e}")
                row = {'TimeStamp' : datetime.datetime.now().astimezone(),
                       'Level'     : 'ERROR',
                       'Message'   : (f"Can't write to destination file {g_DestFileFullName}")}
                return(row)
            else:
                continue


#=============================================================================================================================
def Color_Line(IN_Line):
    Red_Words    = ['no', 'NEW','|','i','ip','any','any4','clear','tcp','udp','ip','icmp','deny','(hitcnt=0)','inactive','shutdown','address','standby','route','ssh','circular-buffer','[Capturing','0']
    Blu_Words    = ['interface','access-group','access-list','host','network','nat','route','show','run','unidirectional']
    Green_Words  = ['in','log','description','logging','permit']
    Purple_Words = ['configure', 'extended', 'service','protocol','capture']
    Brown_Words  = ['network-object','source','dynamic','static','destination','object-group','object','port-object','policy-map','match','to','eq','line','range']
    Red_Color    = '#ba1e28'
    Blu_Color    = '#1e25ba'
    Green_Color  = '#1cb836'
    Purple_Color = '#8f1489'
    Brown_Color  = '#995c00'

    OUT_Line = ''
    for t_word in IN_Line.split():
        if t_word in Blu_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Blu_Color, t_word)
        elif t_word in Red_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Red_Color, t_word)
        elif t_word in Green_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Green_Color, t_word)
        elif t_word in Purple_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Purple_Color, t_word)
        elif t_word in Brown_Words:
            OUT_Line = OUT_Line + '<font color="%s"> %s </font>' %(Brown_Color, t_word)
        else:
            OUT_Line = OUT_Line + '%s ' %t_word
    return OUT_Line


#=============================================================================================================================
def Write_Think_File(Think_File_Name, Think_List):

    retries = 0
    while retries < 3:
        try:
            with open(Think_File_Name, "w") as f:
                f.write('''
<style>
    p.small {
      line-height: 1.0;
      font-family:"Courier New";
      font-size: 1rem;
    }
</style>
<p class="text-dark small ">
''')
                for t_line in Think_List:
                    t_line = t_line.replace('\n','<br>')

                    t_line = Color_Line(t_line)
                    f.write('<br>%s\n'%t_line)
                f.write('</p>\n')
                print('... saved file "%s"' %Think_File_Name)
                break
        except:
            retries +=1
            time.sleep(retries*2)
    if retries == 3:
        print('ERROR!!! Cannot write to file %s' %Think_File_Name)


#=============================================================================================================================
def timedelta_in_months(start_date, end_date):
    start_year = start_date.year
    start_month = start_date.month
    end_year = end_date.year
    end_month = end_date.month

    delta_years = end_year - start_year
    delta_months = end_month - start_month
    total_months = delta_years * 12 + delta_months

    return total_months


#=============================================================================================================================
