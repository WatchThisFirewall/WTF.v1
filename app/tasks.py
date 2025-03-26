# myapp/tasks.py
from background_task import background
from background_task.models import Task
from datetime import datetime, timedelta
from django.utils import timezone
from django.utils.timezone import make_aware, utc, is_naive, now, localtime
from app.models import My_Devices
from pathlib import Path
import subprocess
import logging


logger = logging.getLogger(__name__)


@background(schedule=60)
def check_device_schedules():
    _now_ =  timezone.localtime(timezone.now())
    
    #logger.info(f"in the check_device_schedules....")
    db_Run_Script_Bkgnd_WTF_dic = {}
    try:
        db_tasks = Task.objects.all()
        for t_task in db_tasks:
            #print(f"Task ID: {t_task.id}, Task Name: {t_task.task_name}, Scheduled Time: {t_task.run_at}, Parameters: {t_task.task_params}")
            if t_task.task_name == 'app.tasks.Run_Script_Bkgnd_WTF':
                t_device_IP = t_task.task_params.split('"')[1]
                if t_device_IP not in db_Run_Script_Bkgnd_WTF_dic.keys():
                    db_Run_Script_Bkgnd_WTF_dic[t_device_IP] = 1
                else:
                    db_Run_Script_Bkgnd_WTF_dic[t_device_IP] = db_Run_Script_Bkgnd_WTF_dic[t_device_IP] + 1
        #print(f"db_Run_Script_Bkgnd_WTF_dic = {db_Run_Script_Bkgnd_WTF_dic}")
    except Exception as e:
        logger.error(f"{_now_} - CDS - Error while fetching device schedules from DB: {str(e)}")

    day_map = {'MON': 0, 'TUE': 1, 'WED': 2, 'THU': 3, 'FRI': 4, 'SAT': 5, 'SUN': 6}
    
    try:
        # Get all devices
        devices = My_Devices.objects.all()

        for t_device in devices:
            if t_device.Enabled == False: 
                continue
             
            # check if task scheduling is enabled
            if t_device.RUN_Enabled == False: 
                continue
            
            # check for new devices and set the first run to be now
            if not t_device.RUN_Last_Run_Time:
                if t_device.IP_Address not in db_Run_Script_Bkgnd_WTF_dic.keys():
                    logger.info(f"{_now_} - CDS - 1st queuing Run_Script_Bkgnd_WTF for device: {t_device.HostName}@{t_device.IP_Address}")
                    Run_Script_Bkgnd_WTF(t_device.IP_Address)
                
            # checkif last run failed for some reason
            elif (t_device.TimeStamp_t0-timedelta(days=7)) < t_device.RUN_Last_Run_Time:
                if t_device.IP_Address not in db_Run_Script_Bkgnd_WTF_dic.keys():
                    logger.info(f"{_now_} - CDS - re-queuing Run_Script_Bkgnd_WTF for device: {t_device.HostName}@{t_device.IP_Address}")
                    #print(f"print... re-queuing Run_Script_Bkgnd_WTF for device: {t_device.HostName}@{t_device.IP_Address}")
                    Run_Script_Bkgnd_WTF(t_device.IP_Address)
            
            # check if last run is too old
            elif t_device.RUN_Last_Run_Time < (t_device.TimeStamp_t0-timedelta(days=14)):
                if t_device.IP_Address not in db_Run_Script_Bkgnd_WTF_dic.keys():
                    logger.info(f"{_now_} - CDS - old-re-queuing Run_Script_Bkgnd_WTF for device: {t_device.HostName}@{t_device.IP_Address}")
                    #print(f"print... re-queuing Run_Script_Bkgnd_WTF for device: {t_device.HostName}@{t_device.IP_Address}")
                    Run_Script_Bkgnd_WTF(t_device.IP_Address)          
            
            # check if task already scheduled
            elif t_device.IP_Address in db_Run_Script_Bkgnd_WTF_dic.keys():
                continue
            
            else:
                _now_ = timezone.localtime(timezone.now())
                current_day = _now_.weekday()
                                
                #t_RUN_Last_Run_Time_date = t_device.RUN_Last_Run_Time
                #t_RUN_Last_Run_Time_date = t_RUN_Last_Run_Time_date.replace(tzinfo=None)
                #t_Last_Run_Time_Delta = t_RUN_Last_Run_Time_date - now
                    
                # Calculate the next scheduled datetime for this device
                t_day_of_week = t_device.RUN_Day_of_Week  # e.g., 'MON'
                t_time_of_day = t_device.RUN_Time_of_Day  # e.g., '00:30'
                t_target_day = day_map[t_day_of_week]
                
                days_until_target = (t_target_day - current_day) % 7
                if days_until_target == 0:
                    days_until_target = 7
                next_run_date = _now_ + timedelta(days=days_until_target)
                next_run_datetime = next_run_date.replace(
                    hour=int(t_time_of_day.split(":")[0]),
                    minute=int(t_time_of_day.split(":")[1]),
                    second=0,
                    microsecond=0
                )
                if is_naive(next_run_datetime):
                    next_run_datetime_utc = make_aware(next_run_datetime, timezone=utc)
                else:
                    next_run_datetime_utc = next_run_datetime
                Run_Script_Bkgnd_WTF(t_device.IP_Address, schedule=next_run_datetime_utc)
                #run_device_task(t_device.IP_Address, schedule=next_run_datetime)
                logger.info(f"{_now_} - CDS - Queuing Run_Script_Bkgnd_WTF for device: {t_device.HostName}/{t_device.IP_Address} @ {next_run_datetime_utc}")
                #print(f"print... Queuing Run_Script_Bkgnd_WTF for device: {t_device.HostName}@{t_device.IP_Address}")
            
            # controllare se è passata più di una settimana dall ultima volta ...
            
        clean_completed_tasks()
            
    except Exception as e:
        logger.error(f"{_now_} - CDS - Error while checking device schedules: {str(e)}")



@background(schedule=5)
def Run_Script_Bkgnd_WTF(t_IP_Address):
    _now_ = timezone.localtime(timezone.now())
    
    db_Run_Script_Bkgnd_WTF_dic = {}
    try:
        db_tasks = Task.objects.all()
        for t_task in db_tasks:
            #print(f"Task ID: {t_task.id}, Task Name: {t_task.task_name}, Scheduled Time: {t_task.run_at}, Parameters: {t_task.task_params}")
            if t_task.task_name == 'app.tasks.Run_Script_Bkgnd_WTF':
                t_device_IP = t_task.task_params.split('"')[1]
                if t_device_IP not in db_Run_Script_Bkgnd_WTF_dic.keys():
                    db_Run_Script_Bkgnd_WTF_dic[t_device_IP] = 1
                else:
                    db_Run_Script_Bkgnd_WTF_dic[t_device_IP] = db_Run_Script_Bkgnd_WTF_dic[t_device_IP] + 1
        #print(f"db_Run_Script_Bkgnd_WTF_dic = {db_Run_Script_Bkgnd_WTF_dic}")
    except Exception as e:
        logger.error(f"{_now_} - RSB - Error while fetching device schedules from DB: {str(e)}")    

    t_device  = My_Devices.objects.get(IP_Address=t_IP_Address)
    t_hostName = t_device.HostName

    #python_path = Path("./../venv311/Scripts/python.exe")
    python_path = get_python_path()
    script_path = Path("./app/Scripts/ASA_Check_Config.v.1.py")
    output_path = Path("./_Log_FW_").joinpath(t_hostName)
    
    output_path.mkdir(parents=True, exist_ok=True)  # Create directories if not present
    
    out_log_file = output_path / f"{t_hostName}.OutLog.txt"
    out_err_file = output_path / f"{t_hostName}.ErrLog.txt"

    MyTaskExecuted = False
    
    logger.info(f"{_now_} - RSB - Executing Run_Script_Bkgnd for device: {t_device.HostName}/{t_device.IP_Address}")
    # Open files for stdout and stderr
    with open(out_log_file, 'w+') as stdout_file, open(out_err_file, 'w+') as stderr_file:
        try:
            subprocess.run(
                [str(python_path), str(script_path), '-d', t_hostName],
                stdout=stdout_file,
                stderr=stderr_file,
                text=True,
                check=True
            )
            MyTaskExecuted = True
            
            _now_ = timezone.localtime(timezone.now())
            if MyTaskExecuted:
                _now_ = timezone.localtime(timezone.now())
                logger.info(f"{_now_} - RSB - Task Run_Script_Bkgnd executed successfully for {t_hostName}. Logs saved to {output_path}")
                _now_ = timezone.localtime(timezone.now())
                day_map = {'MON': 0, 'TUE': 1, 'WED': 2, 'THU': 3, 'FRI': 4, 'SAT': 5, 'SUN': 6}
                current_day = _now_.weekday()
                t_day_of_week = t_device.RUN_Day_of_Week  # e.g., 'MON'
                t_time_of_day = t_device.RUN_Time_of_Day  # e.g., '00:30'
                t_target_day = day_map[t_day_of_week]
                
                #days_until_target = ((t_target_day - current_day - 1) % 7)+1
                days_until_target = (t_target_day - current_day) % 7
                if days_until_target == 0:
                    days_until_target = 7
                next_run_date = _now_ + timedelta(days=days_until_target)
                next_run_datetime = next_run_date.replace(
                    hour=int(t_time_of_day.split(":")[0]),
                    minute=int(t_time_of_day.split(":")[1]),
                    second=0,
                    microsecond=0
                )
                if is_naive(next_run_datetime):
                    next_run_datetime_utc = make_aware(next_run_datetime, timezone=utc)
                else:
                    next_run_datetime_utc = next_run_datetime
                    
                _now_ = timezone.localtime(timezone.now())
                if t_device.IP_Address not in db_Run_Script_Bkgnd_WTF_dic.keys():
                    logger.info(f"{_now_} - RSB - Re1-Queuing Run_Script_Bkgnd for device: {t_device.HostName}/{t_device.IP_Address} @ {next_run_datetime_utc}")
                    Run_Script_Bkgnd_WTF(t_device.IP_Address, schedule=next_run_datetime_utc)
                elif db_Run_Script_Bkgnd_WTF_dic[t_device_IP] < 2:
                    logger.info(f"{_now_} - RSB - Re2-Queuing Run_Script_Bkgnd for device: {t_device.HostName}/{t_device.IP_Address} @ {next_run_datetime_utc}")
                    Run_Script_Bkgnd_WTF(t_device.IP_Address, schedule=next_run_datetime_utc)
                else:
                    logger.info(f"{_now_} - RSB - NOT Re-Queuing Run_Script_Bkgnd for device: {t_device.HostName}/{t_device.IP_Address}, already there")
                
                #t_device.refresh_from_db()
                #t_device.RUN_Last_Run_Time = _now_
                #t_device.save()
                My_Devices.objects.filter(IP_Address=t_IP_Address).update(RUN_Last_Run_Time=_now_)
            else:
                logger.info(f"{_now_} - RSB - MyTask NOT Executed for device: {t_device.HostName}/{t_device.IP_Address} @ {next_run_datetime_utc}")
                
                    
        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in subprocess: {e}")

    # try:
    #     device = My_Devices.objects.get(IP_Address=t_IP_Address)
    #     logger.info(f"{now} - RSB - Executing Run_Script_Bkgnd for device: {device.HostName}/{device.IP_Address}")
    #     # Open files for stdout and stderr
    #     with open(out_log_file, 'w+') as stdout_file, open(out_err_file, 'w+') as stderr_file:
            
    #         subprocess.run(
    #             [str(python_path), str(script_path), '-d', t_hostName],  # Pass arguments separately
    #             stdout=stdout_file,                     # Redirect stdout to output.log
    #             stderr=stderr_file,                     # Redirect stderr to error.log
    #             text=True,                              # Write as text instead of binary
    #             check=True                              # Raise exception on failure
    #         )
    #     logger.info(f"{now} - RSB - Task Run_Script_Bkgnd executed successfully for {t_hostName}. Logs saved to {output_path}")
    #     MyTaskExecuted = True

    # except My_Devices.DoesNotExist:
    #     logger.error(f"{now} - RSB - Device with IP {t_IP_Address} does not exist.")
    # except Exception as e:
    #     logger.error(f"{now} - RSB - Error while executing task for device {t_IP_Address}: {str(e)}")
     



    
@background()  
def Print_Something():
    print('Print: Hallo Sono TASK in Esecuzione!!!')
    logger.info(f"Logger: @ {timezone.now().time()} - Hallo Sono TASK in Esecuzione!!!") 




from datetime import timedelta
from django.utils.timezone import now
from background_task.models import CompletedTask
    
@background() 
def clean_completed_tasks(days=14):
    _now_ = timezone.localtime(timezone.now())
    """Delete completed tasks older than the specified number of days."""
    logger.info(f"{_now_} - checking for completed tasks to delete older than {days} days.")
    cutoff_date = _now_ - timedelta(days=days)
    old_tasks = CompletedTask.objects.filter(run_at__lt=cutoff_date)
    count = old_tasks.count()
    old_tasks.delete()
    logger.info(f"{_now_} - Deleted {count} completed tasks.")
    
    
#=================================================================================================================
import os
import platform
from pathlib import Path

def get_python_path():
    """
    Dynamically determine the Python executable path based on the system.
    """
    if platform.system() == "Windows":
        python_path = Path("./../venv311/Scripts/python.exe")
    elif platform.system() == "Linux":
        # Linux system (e.g., Docker, local Linux)
        if "DOCKER" in os.environ:
            python_path = Path("./../venv311/bin/python")  # Typical Python path in Docker
        else:
            python_path = Path("./../venv311/bin/python")  # Local Linux virtual environment
    else:
        # MacOS or other systems
        python_path = Path("./../venv311/bin/python")
    
    #print(f"Using Python path: {python_path}")
    return python_path
    