#def NetworkCalc(IP_ADDRESS,SUBNET_MASK)
#def wildcard_mask_test (test_octet, acl_octet, acl_wildcard_octet)
#def test_octet (acl_octet, acl_wildcard_octet)
#def IPv4_to_intList (IpAddr, SubMsk)
#def IPv4_to_DecList (IpAddr, SubMsk)
#def Is_Overlapping(ip_a, sm_a, ip_b, sm_b)
#def Is_Dec_Overlapping(dec_ip_a, dec_ip_b)
#def INTv4_to_IPv4 (ip_int)

import ipaddress
import sys

##re1 = re.compile('(permit|deny) (tcp|icmp|udp|gre|ip|esp|ipsec|ospf)', re.IGNORECASE)
##re2 = re.compile('access-list .* element', re.IGNORECASE)
##re3 = re.compile('^access-list .* line', re.IGNORECASE)
##re4 = re.compile('^  access-list .* line', re.IGNORECASE)
##re5 = re.compile(r'^\s*$') # empty line
##re6 = re.compile('.*(permit|deny) (tcp|icmp|udp|gre|ip|esp|ipsec|ospf)', re.IGNORECASE)
##re7 = re.compile('.*(permit|deny)', re.IGNORECASE)
##re8 = re.compile('.*(permit|deny) (ah|eigrp|esp|gre|icmp|icmp6|igmp|igrp|ip|ipinip|ipsec|nos|ospf|pcp|pim|pptp|sctp|snp|tcp|udp)', re.IGNORECASE)
##re9 = re.compile('.*(permit|deny) (object-group|object)', re.IGNORECASE)

#=============================================================================================================================
PRTOTOCOLS = ['ah','eigrp','esp','gre','icmp','icmp6','igmp','igrp','ip','ipinip','ipsec','nos','ospf','pcp','pim','pptp','sctp','snp','tcp','udp']

#=============================================================================================================================
Sub_Mask_1  = dict    ([
                      ("/0",  "0.0.0.0"      ),
                      ("/1",  "128.0.0.0"      ),
                      ("/2",  "192.0.0.0"      ),
                      ("/3",  "224.0.0.0"      ),
                      ("/4",  "240.0.0.0"      ),
                      ("/5",  "248.0.0.0"      ),
                      ("/6",  "252.0.0.0"      ),
                      ("/7",  "254.0.0.0"      ),
                      ("/8",  "255.0.0.0"      ),
                      ("/9",  "255.128.0.0"    ),
                      ("/10", "255.192.0.0"    ),
                      ("/11", "255.224.0.0"    ),
                      ("/12", "255.240.0.0"    ),
                      ("/13", "255.248.0.0"    ),
                      ("/14", "255.252.0.0"    ),
                      ("/15", "255.254.0.0"    ),
                      ("/16", "255.255.0.0"    ),
                      ("/17", "255.255.128.0"  ),
                      ("/18", "255.255.192.0"  ),
                      ("/19", "255.255.224.0"  ),
                      ("/20", "255.255.240.0"  ),
                      ("/21", "255.255.248.0"  ),
                      ("/22", "255.255.252.0"  ),
                      ("/23", "255.255.254.0"  ),
                      ("/24", "255.255.255.0"  ),
                      ("/25", "255.255.255.128"),
                      ("/26", "255.255.255.192"),
                      ("/27", "255.255.255.224"),
                      ("/28", "255.255.255.240"),
                      ("/29", "255.255.255.248"),
                      ("/30", "255.255.255.252"),
                      ("/31", "255.255.255.254"),
                      ("/32", "255.255.255.255"),
                      ])

Sub_Mask_2  = dict    ([
                      ("0.0.0.0"         ,"/0",),
                      ("128.0.0.0"       ,"/1",),
                      ("192.0.0.0"       ,"/2",),
                      ("224.0.0.0"       ,"/3",),
                      ("240.0.0.0"       ,"/4",),
                      ("248.0.0.0"       ,"/5",),
                      ("252.0.0.0"       ,"/6",),
                      ("254.0.0.0"       ,"/7",),
                      ("255.0.0.0"       ,"/8",),
                      ("255.128.0.0"     ,"/9",),
                      ("255.192.0.0"     ,"/10"),
                      ("255.224.0.0"     ,"/11"),
                      ("255.240.0.0"     ,"/12"),
                      ("255.248.0.0"     ,"/13"),
                      ("255.252.0.0"     ,"/14"),
                      ("255.254.0.0"     ,"/15"),
                      ("255.255.0.0"     ,"/16"),
                      ("255.255.128.0"   ,"/17"),
                      ("255.255.192.0"   ,"/18"),
                      ("255.255.224.0"   ,"/19"),
                      ("255.255.240.0"   ,"/20"),
                      ("255.255.248.0"   ,"/21"),
                      ("255.255.252.0"   ,"/22"),
                      ("255.255.254.0"   ,"/23"),
                      ("255.255.255.0"   ,"/24"),
                      ("255.255.255.128" ,"/25"),
                      ("255.255.255.192" ,"/26"),
                      ("255.255.255.224" ,"/27"),
                      ("255.255.255.240" ,"/28"),
                      ("255.255.255.248" ,"/29"),
                      ("255.255.255.252" ,"/30"),
                      ("255.255.255.254" ,"/31"),
                      ("255.255.255.255" ,"/32"),
                      ])

Wild_Mask = dict    ([
                    ( "/0",  "255.255.255.255"),
                    ( "/1",  "127.255.255.255"),
                    ( "/2",  "63.255.255.255" ),
                    ( "/3",  "31.255.255.255" ),
                    ( "/4",  "15.255.255.255" ),
                    ( "/5",  "7.255.255.255"  ),
                    ( "/6",  "3.255.255.255"  ),
                    ( "/7",  "1.255.255.255"  ),
                    ( "/8",  "0.255.255.255"  ),
                    ( "/9",  "0.127.255.255"  ),
                    ( "/10", "0.63.255.255"   ),
                    ( "/11", "0.31.255.255"   ),
                    ( "/12", "0.15.255.255"   ),
                    ( "/13", "0.7.255.255"    ),
                    ( "/14", "0.3.255.255"    ),
                    ( "/15", "0.1.255.255"    ),
                    ( "/16", "0.0.255.255"    ),
                    ( "/17", "0.0.127.255"    ),
                    ( "/18", "0.0.63.255"     ),
                    ( "/19", "0.0.31.255"     ),
                    ( "/20", "0.0.15.255"     ),
                    ( "/21", "0.0.7.255"      ),
                    ( "/22", "0.0.3.255"      ),
                    ( "/23", "0.0.1.255"      ),
                    ( "/24", "0.0.0.255"      ),
                    ( "/25", "0.0.0.127"      ),
                    ( "/26", "0.0.0.63"       ),
                    ( "/27", "0.0.0.31"       ),
                    ( "/28", "0.0.0.15"       ),
                    ( "/29", "0.0.0.7"        ),
                    ( "/30", "0.0.0.3"        ),
                    ( "/31", "0.0.0.1"        ),
                    ( "/32", "0.0.0.0"        ),
                    ])

Wild_Mask_2 = dict  ([
                    ("255.255.255.255" ,"/2" ),
                    ("127.255.255.255" ,"/3" ),
                    ("63.255.255.255"  ,"/2" ),
                    ("31.255.255.255"  ,"/3" ),
                    ("15.255.255.255"  ,"/4" ),
                    ("7.255.255.255"   ,"/5" ),
                    ("3.255.255.255"   ,"/6" ),
                    ("1.255.255.255"   ,"/7" ),
                    ("0.255.255.255"   ,"/8" ),
                    ("0.127.255.255"   ,"/9" ),
                    ("0.63.255.255"    ,"/10"),
                    ("0.31.255.255"    ,"/11"),
                    ("0.15.255.255"    ,"/12"),
                    ("0.7.255.255"     ,"/13"),
                    ("0.3.255.255"     ,"/14"),
                    ("0.1.255.255"     ,"/15"),
                    ("0.0.255.255"     ,"/16"),
                    ("0.0.127.255"     ,"/17"),
                    ("0.0.63.255"      ,"/18"),
                    ("0.0.31.255"      ,"/19"),
                    ("0.0.15.255"      ,"/20"),
                    ("0.0.7.255"       ,"/21"),
                    ("0.0.3.255"       ,"/22"),
                    ("0.0.1.255"       ,"/23"),
                    ("0.0.0.255"       ,"/24"),
                    ("0.0.0.127"       ,"/25"),
                    ("0.0.0.63"        ,"/26"),
                    ("0.0.0.31"        ,"/27"),
                    ("0.0.0.15"        ,"/28"),
                    ("0.0.0.7"         ,"/29"),
                    ("0.0.0.3"         ,"/30"),
                    ("0.0.0.1"         ,"/31"),
                    ("0.0.0.0"         ,"/32"),
                    ])

#=============================================================================================================================
def NetworkCalc(IP_ADDRESS,SUBNET_MASK):
    "Return the Network of a given IP Address"

    Sub_Mask_1  = dict    ([
                      ("/2",  "128.0.0.0"      ),
                      ("/3",  "192.0.0.0"      ),
                      ("/4",  "224.0.0.0"      ),
                      ("/5",  "240.0.0.0"      ),
                      ("/6",  "248.0.0.0"      ),
                      ("/7",  "252.0.0.0"      ),
                      ("/8",  "254.0.0.0"      ),
                      ("/9",  "255.128.0.0"    ),
                      ("/10", "255.192.0.0"    ),
                      ("/11", "255.224.0.0"    ),
                      ("/12", "255.240.0.0"    ),
                      ("/13", "255.248.0.0"    ),
                      ("/14", "255.252.0.0"    ),
                      ("/15", "255.254.0.0"    ),
                      ("/16", "255.255.0.0"    ),
                      ("/17", "255.255.128.0"  ),
                      ("/18", "255.255.192.0"  ),
                      ("/19", "255.255.224.0"  ),
                      ("/20", "255.255.240.0"  ),
                      ("/21", "255.255.248.0"  ),
                      ("/22", "255.255.252.0"  ),
                      ("/23", "255.255.254.0"  ),
                      ("/24", "255.255.255.0"  ),
                      ("/25", "255.255.255.128"),
                      ("/26", "255.255.255.192"),
                      ("/27", "255.255.255.224"),
                      ("/28", "255.255.255.240"),
                      ("/29", "255.255.255.248"),
                      ("/30", "255.255.255.252"),
                      ("/31", "255.255.255.254"),
                      ("/32", "255.255.255.255"),
                      ])

    temp_net = []
    if SUBNET_MASK not in Sub_Mask_1.values():
        print ('NetworkCalc ERROR!')
        print ('IP_ADDRESS=%s,   SUBNET_MASK=%s' %(IP_ADDRESS,SUBNET_MASK))
        sys.exit('ERROR!!! --- Submask not allowed ---')
    else:
        for k in range (0,4):
            this_byte = IP_ADDRESS.split('.')[k]
            this_mask = SUBNET_MASK.split('.')[k]
            this_net = int(this_byte) & int(this_mask)
            temp_net.append(str(this_net))

        NETORK_IP = '.'.join(temp_net)
        return NETORK_IP

#=============================================================================================================================
Port_Converter = {}
Port_Converter['aol'] = '5190'
Port_Converter['bgp'] = '179'
Port_Converter['biff'] = '512'
Port_Converter['bootpc'] = '68'
Port_Converter['bootps'] = '67'
Port_Converter['chargen'] = '19'
Port_Converter['cifs'] = '3020'
Port_Converter['citrix-ica'] = '1494'
Port_Converter['cmd'] = '514'
Port_Converter['ctiqbe'] = '2748'
Port_Converter['daytime'] = '13'
Port_Converter['discard'] = '9'
Port_Converter['dnsix'] = '195'
Port_Converter['domain'] = '53'
Port_Converter['echo'] = '7'
Port_Converter['exec'] = '512'
Port_Converter['finger'] = '79'
Port_Converter['ftp'] = '21'
Port_Converter['ftp-data'] = '20'
Port_Converter['gopher'] = '70'
Port_Converter['h323'] = '1720'
Port_Converter['hostname'] = '101'
Port_Converter['http'] = '80'
Port_Converter['https'] = '443'
Port_Converter['ident'] = '113'
Port_Converter['imap4'] = '143'
Port_Converter['irc'] = '194'
Port_Converter['isakmp'] = '500'
Port_Converter['kerberos'] = '750'
Port_Converter['klogin'] = '543'
Port_Converter['kshell'] = '544'
Port_Converter['ldap'] = '389'
Port_Converter['ldaps'] = '636'
Port_Converter['login'] = '513'
Port_Converter['lotusnotes'] = '1352'
Port_Converter['lpd'] = '515'
Port_Converter['mobile-ip'] = '434'
Port_Converter['nameserver'] = '42'
Port_Converter['netbios-dgm'] = '138'
Port_Converter['netbios-ns'] = '137'
Port_Converter['netbios-ssn'] = '139'
Port_Converter['nfs'] = '2049'
Port_Converter['nntp'] = '119'
Port_Converter['ntp'] = '123'
Port_Converter['pcanywhere-data'] = '5631'
Port_Converter['pcanywhere-status'] = '5632'
Port_Converter['pim-auto-rp'] = '496'
Port_Converter['pop2'] = '109'
Port_Converter['pop3'] = '110'
Port_Converter['pptp'] = '1723'
Port_Converter['radius'] = '1645'
Port_Converter['radius-acct'] = '1646'
Port_Converter['rip'] = '520'
Port_Converter['rsh'] = '514'
Port_Converter['rtsp'] = '554'
Port_Converter['secureid-udp'] = '5510'
Port_Converter['sip'] = '5060'
Port_Converter['smtp'] = '25'
Port_Converter['snmp'] = '161'
Port_Converter['snmptrap'] = '162'
Port_Converter['sqlnet'] = '1521'
Port_Converter['ssh'] = '22'
Port_Converter['sunrpc'] = '111'
Port_Converter['syslog'] = '514'
Port_Converter['tacacs'] = '49'
Port_Converter['talk'] = '517'
Port_Converter['telnet'] = '23'
Port_Converter['tftp'] = '69'
Port_Converter['time'] = '37'
Port_Converter['uucp'] = '540'
Port_Converter['vxlan'] = '4789'
Port_Converter['who'] = '513'
Port_Converter['whois'] = '43'
Port_Converter['www'] = '80'
Port_Converter['xdmcp'] = '177'

#=============================================================================================================================
Proto_Map = {}
Proto_Map['icmp']   = 1
Proto_Map['udp']    = 2
Proto_Map['tcp']    = 4
Proto_Map['ip']     = 6
Proto_Map['icmp6']  = 0
Proto_Map['gre']    = 0
Proto_Map['ah']     = 0
Proto_Map['eigrp']  = 0
Proto_Map['esp']    = 0
Proto_Map['igmp']   = 0
Proto_Map['igrp']   = 0
Proto_Map['ipinip'] = 0
Proto_Map['ipsec']  = 0
Proto_Map['nos']    = 0
Proto_Map['ospf']   = 0
Proto_Map['pcp']    = 0
Proto_Map['pim']    = 0
Proto_Map['pptp']   = 0
Proto_Map['sctp']   = 0
Proto_Map['snp']    = 0

#=============================================================================================================================
# (Prt_Src & Prt_Dst) + (8 if Prt_Src == ip)
Tot_Shadow_List = [1,2,4,14]

Part_Shadow_List = [1,2,4,10,12,14]

# (Prt_Src + Prt_Dst) + (Prt_Src * Prt_Dst)
Check_Port_List = [8,24]

#=============================================================================================================================
def wildcard_mask_test (test_octet, acl_octet, acl_wildcard_octet):
    #Test one number against acl address and mask
    #Bitwise OR of test_octet and acl_octet against the octet of the wildcard mask
    test_result = test_octet | acl_wildcard_octet
    acl_result  = acl_octet | acl_wildcard_octet
    #Return value is whether they match
    return (acl_result == test_result)

#=============================================================================================================================
def test_octet (acl_octet, acl_wildcard_octet):
    matches = []
    #Test all possible numbers in an octet (0..255) against octet of acl and mask
    #Short circuit here for a mask value of 0 since it matches only the $acl_octet
    if (acl_wildcard_octet == 0):
        matches.append(acl_octet)
        return matches
    else:
        for test_octet in range(0,256):
            if (wildcard_mask_test(test_octet, acl_octet, acl_wildcard_octet)):
                matches.append(test_octet)
        return matches

#=============================================================================================================================
def IPv4_to_intList (IpAddr, SubMsk):
    # import Sub_Mask_2
    # given an ip address and the correspondign subnet mask
    # convert it to an 1x4 int-List
    # '192.168.1.2' => [192,168,1,2]

    #check if it is ipv4
    if IpAddr.count('.') != 3:
        print ('this is not a valid ip address (%s)' %IpAddr)
        # return something that will be descarded
    if SubMsk.count('.') != 3:
        print ('this is not a valid subnet mask (%s)' %SubMsk)
        # return something that will be descarded
    if SubMsk not in Sub_Mask_2.keys():
        print ('non convetnional subnet mask for (%s %s)' %(IpAddr, SubMsk))
        # ma andiamo avanti...

    ip_a = list(map(int, IpAddr.split('.')))
    sm_a = list(map(int, SubMsk.split('.')))

    return(ip_a, sm_a)

#=============================================================================================================================
def IPv4_to_DecList (IpAddr, SubMsk):
    # given an ip address and the correspondign subnet mask
    # convert it to an 1x2 Decimal-List
    # IPv4_to_DecList('192.168.1.2', '255.255.255.0') => [3232235778, 4294967040]

    # convert an ip address 1.2.3.4 255.255.255.1 in decimal format
    # 192.168.1.2
    # = 192*(256)^3  + 168*(256)^2 + 1*(256)^1 + 2*(256)^0
    # = 192*16777216 + 168*65536   + 1*256     + 2
    # = 3221225472   + 11010048    + 256       + 2 = 3232235778

    # 255.255.255.255 = 4294967295

    #check if it is ipv4
    if IpAddr.count('.') != 3:
        print ('this is not a valid ip address (%s)' %IpAddr)
        # return something that will be descarded
        return([-1,-1])
    if SubMsk.count('.') != 3:
        print ('this is not a valid subnet mask (%s)' %SubMsk)
        # return something that will be descarded
        return([-1,-1])
    if SubMsk not in Sub_Mask_2.keys():
        print ('non convetnional subnet mask for (%s %s)' %(IpAddr, SubMsk))
        # ma andiamo avanti...

    ip_a = list(map(int, IpAddr.split('.')))
    sm_a = list(map(int, SubMsk.split('.')))
    c = [16777216, 65536, 256, 1]

    d_ip_a = ip_a[0]*c[0] + ip_a[1]*c[1] + ip_a[2]*c[2] + ip_a[3]
    d_sm_a = sm_a[0]*c[0] + sm_a[1]*c[1] + sm_a[2]*c[2] + sm_a[3]
    return([d_ip_a, d_sm_a])

#=============================================================================================================================
def Is_Overlapping(ip_a, sm_a, ip_b, sm_b):
    # check if ip_a/sm_a is subnet of ip_b/sm_b
    # --- return: ---
    # 0 if no overlap
    # 1 if a is totally shadowed by b (=subnet of)
    # 2 if a is partly shadowed by b (=supernet of)

    #ip_a = [10,1,1,2]
    #sm_a = [255,255,255,255]

    #ip_b = [10,1,1,5]
    #sm_b = [255,255,255,0]

    c = [16777216, 65536, 256, 1]

    d_ip_a = ip_a[0]*c[0] + ip_a[1]*c[1] + ip_a[2]*c[2] + ip_a[3]
    d_sm_a = sm_a[0]*c[0] + sm_a[1]*c[1] + sm_a[2]*c[2] + sm_a[3]
    d_ip_b = ip_b[0]*c[0] + ip_b[1]*c[1] + ip_b[2]*c[2] + ip_b[3]
    d_sm_b = sm_b[0]*c[0] + sm_b[1]*c[1] + sm_b[2]*c[2] + sm_b[3]

    if sm_a == [0,0,0,0]:
        if sm_b == [0,0,0,0]:
            return(1)
        else:
            return(2) #same as defualt route
    elif sm_b == [0,0,0,0]:
        return(1) #same as default route
    elif (d_ip_a & d_sm_b) == (d_ip_b & d_sm_b):
        return(1)
        #print('.'.join(map(str, ip_a)) + ' subnet of ' + '.'.join(map(str, ip_b)))
    elif (d_ip_a & d_sm_a) == (d_ip_b & d_sm_a):
        return(2)
        #print('.'.join(map(str, ip_a)) + ' supernet of ' + '.'.join(map(str, ip_b)))
    else:
        return(0) # no shadowing

#=============================================================================================================================
def Is_Dec_Overlapping(dec_ip_a, dec_ip_b):
    # dec_ip_a = [d_ip_a, d_sm_a] , dec_ip_b = [d_ip_b, d_sm_b] ex:[3232235778, 4294967040]
    #...
    # check if ip_a/sm_a is subnet of ip_b/sm_b
    # --- return: ---
    # 0 if no overlap
    # 1 if a is totally shadowed by b (A = subnet of B)
    # 2 if a is partly shadowed by b  (A = supernet of B)

    #ip_a = [10,1,1,2]
    #sm_a = [255,255,255,255]

    #ip_b = [10,1,1,5]
    #sm_b = [255,255,255,0]

    ##    c = [16777216, 65536, 256, 1]
    ##
    ##    d_ip_a = ip_a[0]*c[0] + ip_a[1]*c[1] + ip_a[2]*c[2] + ip_a[3]
    ##    d_sm_a = sm_a[0]*c[0] + sm_a[1]*c[1] + sm_a[2]*c[2] + sm_a[3]
    ##    d_ip_b = ip_b[0]*c[0] + ip_b[1]*c[1] + ip_b[2]*c[2] + ip_b[3]
    ##    d_sm_b = sm_b[0]*c[0] + sm_b[1]*c[1] + sm_b[2]*c[2] + sm_b[3]
    d_ip_a = dec_ip_a[0]
    d_sm_a = dec_ip_a[1]
    d_ip_b = dec_ip_b[0]
    d_sm_b = dec_ip_b[1]
##    print ('DBG__ d_ip_a = %s' %d_ip_a)
##    print ('DBG__ d_sm_a = %s' %d_sm_a)
##    print ('DBG__ d_ip_b = %s' %d_ip_b)
##    print ('DBG__ d_sm_b = %s' %d_sm_b)

    if d_sm_a == 0: #same as defualt route
        if d_sm_b == 0: #same as defualt route
            return(1)
        else:
            return(2)
    elif d_sm_b == 0:
        return(1) #same as default route
    elif (d_ip_a & d_sm_b) == (d_ip_b & d_sm_b):
        return(1)
        #print('.'.join(map(str, ip_a)) + ' subnet of ' + '.'.join(map(str, ip_b)))
    elif (d_ip_a & d_sm_a) == (d_ip_b & d_sm_a):
        return(2)
        #print('.'.join(map(str, ip_a)) + ' supernet of ' + '.'.join(map(str, ip_b)))
    else:
        return(0) # no shadowing

#=============================================================================================================================
def INTv4_to_IPv4 (ip_int):
    # given an ip address in decimal format
    # convert it to an ipv4
    # 168496141 => 10.11.12.13

    #ip = 168496141
    #byte_4 = int(ip/256^3 % 256) <=> int(ip/16777216 % 256) <=> int(10.0431526303) <=> 10
    #byte_3 = int(ip/256^2 % 256) <=> int(ip/65536 % 256) <=> int(11.0470733643) <=> 11
    #byte_2 = int(ip/256^1 % 256) <=> int(ip/256 % 256) <=> int(12.05078125) <=> 12
    #byte_1 = int(ip/256^0 % 256) <=> int(ip % 256) <=> int(13) <=> 13
    #ip_str = $byte_4 + "." + $byte_3 + "." + $byte_2 + "." + $byte_1 <=> 10.11.12.13

    if ip_int <= 4294967295:
        B1 = int(ip_int/16777216 % 256)
        B2 = int(ip_int/65536 % 256)
        B3 = int(ip_int/256 % 256)
        B4 = int(ip_int % 256)
        return('%s.%s.%s.%s' %(B1,B2,B3,B4))

    else:
        print ('this is not a valid ipv4 integer conversion: %s ' %ip_int)
        exit(4444)

#=============================================================================================================================

