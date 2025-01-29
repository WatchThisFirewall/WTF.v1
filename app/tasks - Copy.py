# myapp/tasks.py
from background_task import background
from background_task.models import Task
from datetime import datetime, timedelta
from django.utils import timezone
from django.utils.timezone import make_naive
from app.models import My_Devices
from pathlib import Path
import subprocess
import logging


logger = logging.getLogger(__name__)


@background(schedule=60)
def check_device_schedules():
    #logger.info(f"in the check_device_schedules....")
    db_tasks_dic = {}
    try:
        db_tasks = Task.objects.all()
        for t_task in db_tasks:
            #print(f"Task ID: {t_task.id}, Task Name: {t_task.task_name}, Scheduled Time: {t_task.run_at}, Parameters: {t_task.task_params}")
            if t_task.task_name == 'app.tasks.run_device_task':
                t_device_IP = t_task.task_params.split('"')[1]
                t_Scheduled_Time = t_task.run_at
                db_tasks_dic[t_device_IP] = t_Scheduled_Time
        #print(f"db_tasks_dic = {db_tasks_dic}")
    except Exception as e:
        logger.error(f"{now} - Error while fetching device schedules from DB: {str(e)}")

    day_map = {'MON': 0, 'TUE': 1, 'WED': 2, 'THU': 3, 'FRI': 4, 'SAT': 5, 'SUN': 6}
    now = timezone.now()
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
            if t_device.RUN_Last_Run_Time is None:
                logger.info(f"{now} - 1st queuing run_device_task for device: {t_device.HostName}@{t_device.IP_Address}")
                run_device_task(t_device.IP_Address)
                continue
            
            # checkif last run failed for some reason
            if t_device.TimeStamp_t0 < t_device.RUN_Last_Run_Time:
                logger.info(f"{now} - re-queuing run_device_task for device: {t_device.HostName}@{t_device.IP_Address}")
                #print(f"print... re-queuing run_device_task for device: {t_device.HostName}@{t_device.IP_Address}")
                run_device_task(t_device.IP_Address)
                continue
            
            # check if task already scheduled
            if t_device.IP_Address in db_tasks_dic.keys():
                continue
            else:
                now = timezone.now()
                current_day = now.weekday()
                                
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
                next_run_date = now + timedelta(days=days_until_target)
                next_run_datetime = next_run_date.replace(
                    hour=int(t_time_of_day.split(":")[0]),
                    minute=int(t_time_of_day.split(":")[1]),
                    second=0,
                    microsecond=0
                )
                next_run_datetime_utc = make_naive(next_run_datetime, timezone.utc)
                run_device_task(t_device.IP_Address, schedule=next_run_datetime_utc)
                #run_device_task(t_device.IP_Address, schedule=next_run_datetime)
                logger.info(f"{now} - Queuing run_device_task for device: {t_device.HostName}/{t_device.IP_Address} @ {next_run_datetime_utc}")
                #print(f"print... Queuing run_device_task for device: {t_device.HostName}@{t_device.IP_Address}")
            
            # controllare se è passata più di una settimana dall ultima volta ...
            
        clean_completed_tasks()
            
    except Exception as e:
        logger.error(f"{now} - Error while checking device schedules: {str(e)}")


@background(schedule=1)
def run_device_task(t_IP_Address):
    db_tasks_dic = {}
    try:
        db_tasks = Task.objects.all()
        for t_task in db_tasks:
            #print(f"Task ID: {t_task.id}, Task Name: {t_task.task_name}, Scheduled Time: {t_task.run_at}, Parameters: {t_task.task_params}")
            if t_task.task_name == 'app.tasks.run_device_task':
                t_device_IP = t_task.task_params.split('"')[1]
                t_Scheduled_Time = t_task.run_at
                db_tasks_dic[t_device_IP] = t_Scheduled_Time
        #print(f"db_tasks_dic = {db_tasks_dic}")
    except Exception as e:
        logger.error(f"{now} - Error while fetching device schedules from DB: {str(e)}")    
    now = timezone.now()
    #now = datetime.datetime.now()
    """
    This is the task that runs the batch for the device.
    """
    day_map = {'MON': 0, 'TUE': 1, 'WED': 2, 'THU': 3, 'FRI': 4, 'SAT': 5, 'SUN': 6}
    
    try:
        device = My_Devices.objects.get(IP_Address=t_IP_Address)
        logger.info(f"{now} - Queuing Run_Script_Bkgnd for device: {device.HostName}/{device.IP_Address}")

        Run_Script_Bkgnd_WTF(t_IP_Address)

        # Simulate work: This is where your actual task logic goes
        # Example: Processing a batch task for the device

        # Update last run time after task completes
        #naive_datetime = timezone.now()
        #aware_datetime = timezone.make_aware(naive_datetime, timezone.utc)
        #device.RUN_Last_Run_Time = aware_datetime
        
#        device.RUN_Last_Run_Time = timezone.now()
#        device.save()
        
        # reschedule for next time
        now = timezone.now()
        #now = datetime.datetime.now()
        
        current_day = now.weekday()
        t_day_of_week = device.RUN_Day_of_Week  # e.g., 'MON'
        t_time_of_day = device.RUN_Time_of_Day  # e.g., '00:30'
        t_target_day = day_map[t_day_of_week]
        
        #days_until_target = ((t_target_day - current_day - 1) % 7)+1
        days_until_target = (t_target_day - current_day) % 7
        if days_until_target == 0:
            days_until_target = 7
        next_run_date = now + timedelta(days=days_until_target)
        next_run_datetime = next_run_date.replace(
            hour=int(t_time_of_day.split(":")[0]),
            minute=int(t_time_of_day.split(":")[1]),
            second=0,
            microsecond=0
        )
        run_device_task(device.IP_Address, schedule=next_run_datetime)
        logger.info(f"{now} - auto-re-queuing run_device_task for device: {device.HostName}/{device.IP_Address} @ {next_run_datetime}")
        # if t_IP_Address not in db_tasks_dic.keys():
        #     run_device_task(device.IP_Address, schedule=next_run_datetime)
        #     logger.info(f"{now} - re-re-queuing run_device_task for device: {device.HostName}/{device.IP_Address} @ {next_run_datetime}")
        # else:
        #     logger.info(f"{now} - NOT re-re-queuing run_device_task for device: {device.HostName}@{device.IP_Address}")        
        #     logger.info(f"{now} - already in the Queue!")        

    except My_Devices.DoesNotExist:
        logger.error(f"{now} - Device with IP {t_IP_Address} does not exist.")
    except Exception as e:
        logger.error(f"{now} - Error while executing task for device {t_IP_Address}: {str(e)}")


@background(schedule=5)
def Run_Script_Bkgnd_WTF(t_IP_Address):
    now = timezone.now()
    #now = datetime.datetime.now()
    t_device  = My_Devices.objects.get(IP_Address=t_IP_Address)
    t_hostName = t_device.HostName
    
    t_device.RUN_Last_Run_Time = timezone.now()
    t_device.save()    

    #python_path = Path("./../venv311/Scripts/python.exe")
    python_path = get_python_path()
    script_path = Path("./app/Scripts/ASA_Check_Config.v.8.py")
    output_path = Path("./_Log_FW_").joinpath(t_hostName)
    
    output_path.mkdir(parents=True, exist_ok=True)  # Create directories if not present
    
    out_log_file = output_path / f"{t_hostName}.OutLog.txt"
    out_err_file = output_path / f"{t_hostName}.ErrLog.txt"

    try:
        # Open files for stdout and stderr
        with open(out_log_file, 'w+') as stdout_file, open(out_err_file, 'w+') as stderr_file:
            subprocess.run(
                [str(python_path), str(script_path), '-d', t_hostName],  # Pass arguments separately
                stdout=stdout_file,                     # Redirect stdout to output.log
                stderr=stderr_file,                     # Redirect stderr to error.log
                text=True,                              # Write as text instead of binary
                check=True                              # Raise exception on failure
            )
        logger.info(f"{now} - Task executed successfully for {t_hostName}. Logs saved to {output_path}")
    #except subprocess.CalledProcessError as e:
    #    logger.error(f"{now} Task failed for {t_hostName} with return code {e.returncode}. Check {out_err_file} for details.")
    except Exception as e:
        logger.error(f"{now} - Unexpected error while running task for {t_hostName}: {str(e)}")

       
    
@background()  
def Print_Something():
    print('Print: Hallo Sono TASK in Esecuzione!!!')
    logger.info(f"Logger: @ {timezone.now().time()} - Hallo Sono TASK in Esecuzione!!!") 




from datetime import timedelta
from django.utils.timezone import now
from background_task.models import CompletedTask
    
@background() 
def clean_completed_tasks(days=14):
    now = timezone.now()
    #now = datetime.datetime.now()
    """Delete completed tasks older than the specified number of days."""
    logger.info(f"{now} - checking for completed tasks to delete older than {days} days.")
    cutoff_date = now - timedelta(days=days)
    old_tasks = CompletedTask.objects.filter(run_at__lt=cutoff_date)
    count = old_tasks.count()
    old_tasks.delete()
    logger.info(f"{now} - Deleted {count} completed tasks.")
    
    
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
    
    print(f"Using Python path: {python_path}")
    return python_path