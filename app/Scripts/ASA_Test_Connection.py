
from ASA_Check_Config_PARAM import *
import utils_v2
import sqlalchemy as db
import datetime
import pandas as pd
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException, BadHostKeyException

args = utils_v2.Get_Args()
#print('\nargs = %s' %args)

if args.d != '':
    ARGS_DEVICE = args.d
else:
    ARGS_DEVICE = None
    print("Device IP Address not provided!\n")
    exit()


DB_Available = True
try:
    engine = db.create_engine("postgresql://%s:%s@%s:%s/%s" % (PostgreSQL_User, PostgreSQL_PW, PostgreSQL_Host, PostgreSQL_Port, db_Name))
    with engine.connect() as connection:
        My_Devices          = db.Table('My_Devices',          db.MetaData(), autoload_with=engine)
        Devices_Model       = db.Table('Devices_Model',       db.MetaData(), autoload_with=engine)
        Default_Credentials = db.Table('Default_Credentials', db.MetaData(), autoload_with=engine)
except Exception as e:
    print(f"error is: {e}")
    print("DB not connected, can't Retrive Device informations...\n")
    DB_Available = False
    raise SystemExit("ASA_Test_Connection :: Exiting due to database connection failure.")

if ARGS_DEVICE:
    if DB_Available:
        query = db.select(My_Devices).where(My_Devices.c.IP_Address=="%s" %ARGS_DEVICE)
        with engine.connect() as connection:
            Device_to_Check = pd.DataFrame(connection.execute(query).fetchall())
        query = db.select(Default_Credentials)
        with engine.connect() as connection:
            Default_Credentials = pd.DataFrame(connection.execute(query).fetchall())
        query = db.select(Devices_Model)
        with engine.connect() as connection:
            Devices_Model_df = pd.DataFrame(connection.execute(query).fetchall())

Flag_QUIT = False
#t_Device = []
d_HostName = Device_to_Check.HostName[0]
d_IP_Address = Device_to_Check.IP_Address[0]
d_Username = Device_to_Check.Username[0]
d_Password = Device_to_Check.Password[0]
d_dev_type = Device_to_Check.Type_id[0]
g_Username = Default_Credentials.Username[0]
g_Password = Default_Credentials.Password[0]
t_Device_type = d_dev_type
t_Device_Vendor = Devices_Model_df.query(f'id == {t_Device_type}')['Device_Vendor'][0]
t_Device_Model = Devices_Model_df.query(f'id == {t_Device_type}')['Device_Model'][0]
if ( (t_Device_Vendor == 'Cisco') and (t_Device_Model == 'ASA') ):
    t_dev_type = 'cisco_asa'
else:
    Log_Message = (f'ERROR! Device Type "{t_Device_type}" Unknown'); print(Log_Message)
    with open("%s/%s"%(Err_folder,WTF_Error_FName),"a+") as f: f.write(Log_Message)
    row = {'TimeStamp':datetime.datetime.now().astimezone(), 'Level':'ERROR', 'Message':Log_Message}
    with engine.begin() as connection: connection.execute(WTF_Log.insert().values(**row))
    Flag_QUIT = True

if not d_IP_Address is None:
    t_IP_Address = d_IP_Address
else:
    print('...ERROR!')
    print("IP_Address not provided for device")
    Flag_QUIT = True

if not d_Username is None:
    t_Username = d_Username
elif not g_Username is None:
    t_Username = g_Username
else:
    print('...ERROR!')
    print("Username not provided for device %s" %d_IP_Address)
    Flag_QUIT = True

if not d_Password is None:
    t_Password = d_Password
elif not g_Password is None:
    t_Password = g_Password
else:
    print('...ERROR!')
    print("Password not provided for device %s" %d_IP_Address)
    Flag_QUIT = True

if Flag_QUIT == False:

    Device_Info = {
        "host"       : t_IP_Address,
        "username"   : t_Username,
        "password"   : t_Password,
        "device_type": t_dev_type,
        "timeout"    : 60
    }
    retries = 0
    device_connection = None
    while retries <= 3:
        try:
            print(f'trying to connect to {Device_Info["host"]}...')
            device_connection = ConnectHandler(**Device_Info)
            if device_connection.is_alive() == False:
                print('device_connection.is_alive() == False:')
                raise Exception
            else:
                print('device_connection.is_alive() == True:')
                break
        except NetmikoTimeoutException:
            print('...ERROR!')
            print("Connection timed out!")
            retries +=1
        except NetmikoAuthenticationException:
            print('...ERROR!')
            print("Authentication failed!")
            retries +=1
        except BadHostKeyException:
            print('...ERROR!')
            print("The host key is not recognized. Possible man-in-the-middle attack!")
            retries +=1
        except SSHException:
            print('...ERROR!')
            print("SSH connection failed!")
            retries +=1
        except Exception as e:
            print('...ERROR!')
            print(f"An unexpected error occurred: {e}")
            retries +=1

    if retries >= 3:
        print(f'_________________________________________________________')
        print(f'FAILED TO CONNECT TO {d_HostName}@{t_IP_Address}')
        Flag_QUIT = True


    if not Flag_QUIT:
        hostname = ''
        hostname = device_connection.find_prompt()[:-1]
        print(hostname)
        if 'act' in hostname:
            hostname=hostname.replace('/act','')
        if 'pri' in hostname:
            hostname=hostname.replace('/pri','')
        if 'sec' in hostname:
            hostname=hostname.replace('/sec','')
        if '/' in hostname:
            hostname=hostname.replace('/','___')
        if hostname != d_HostName:
            print('!')
            print('!  (=================================================)')
            print('!  (==                  Warning!                   ==)')
            print('!  (==             Hostname Mismatch!              ==)')
            print('!  (==                                             ==)')
            print('!      This Device is %s' %(d_HostName))
            print('!      while connected device is %s' %(hostname))
            print('!  (==                                             ==)')
            print('!  (=================================================)')
            print('!  Please correct the Device Hostname in the database ')
            print('!  (=================================================)')

        hostname___ = hostname.replace('/','___')
        print('... Connecting to %s\n' %hostname)


        import time
        Commands = []
        Commands.append('term page 0')
        Commands.append('show clock')

        if DB_Available:
            Updated_Vals = dict(
                                Fetching_Config_Spinner = True,
                                )
            query = db.update(My_Devices).where(My_Devices.c.HostName == hostname___).values(**Updated_Vals)
            try:
                with engine.begin() as connection:
                    connection.execute(query)
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print('My_Devices DB NOT AVAILABLE... Can not update "Fetching_Config_Spinner=True" status for %s.\n' %hostname___)

        retries = 1
        output = []
        for t_Command in Commands:
            if t_Command.startswith("#") or t_Command.startswith("!"):
                continue
            print('%s \t|\t on %s \t|\t %s' %(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M'), hostname, t_Command.strip()))
            while retries <3:
                try:
                    output.append("%s\n%s" %(t_Command, device_connection.send_command(t_Command,max_loops=50000,delay_factor=1,read_timeout=3*retries)))
                    break
                except OSError:
                    retries +=1
                    time.sleep(retries*2)
            if retries == 4:
                output.append("UNABLE TO RUN COMMAND %s on %s" %(t_Command, t_IP_Address))
        device_connection.disconnect()

        print('\n!_________________________________________________________\n')
        for n in output:
            print(n)

        if hostname != '':
            print('SUCCESS!')
        else:
            print('FAILED!')

        if DB_Available:
            Updated_Vals = dict(
                                Fetching_Config_Spinner = False,
                                )
            query = db.update(My_Devices).where(My_Devices.c.HostName == hostname___).values(**Updated_Vals)
            try:
                with engine.begin() as connection:
                    connection.execute(query)
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print('My_Devices DB NOT AVAILABLE... Can not update "Fetching_Config_Spinner=True" status for %s.\n' %hostname___)
else:
    print('FAILED!')
