# from django.apps import AppConfig

# class AppConfig(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'app'


        
from django.apps import AppConfig
from django.core.exceptions import AppRegistryNotReady
import logging
import os
from datetime import datetime
from django.utils import timezone
import time

logger = logging.getLogger(__name__)

class AppConfig(AppConfig):
    time.sleep(10) # Sleep for 10 seconds
    name = 'app'  # Replace with your actual app name

    def ready(self):
        if os.environ.get('RUN_MAIN') == 'true':  # Only execute in the main process
            try:
                # Schedule background tasks after app startup
                self.schedule_background_task()
            except AppRegistryNotReady:
                logger.error('AppRegistry is not ready yet. Skipping task scheduling.')

    def schedule_background_task(self):
        #now = datetime.now()
        _now_ =  timezone.localtime(timezone.now())
        # Log when this function is called
        logger.info(f"In schedule_background_task after app startup.")

        # Import tasks inside the method to avoid circular imports
        from app.tasks import check_device_schedules

        #check_device_schedules(schedule=10, repeat=60*30, repeat_until=None) #check every 30 minutes
        # --------controllare non ci sia già una entry per questo processo!!!! -------------
        try:
            from background_task.models import Task
            db_tasks = Task.objects.filter(task_name='app.tasks.check_device_schedules')
            if len (db_tasks) == 0:
                #check_device_schedules(schedule=2, repeat=60*60, repeat_until=None)
                check_device_schedules(schedule=60, repeat=60*10, repeat_until=None)
                logger.info(f"{_now_} Scheduling1 check_device_schedules task after app startup.")
            else:
                db_tasks.delete()
                #check_device_schedules(schedule=2, repeat=60*60, repeat_until=None)
                check_device_schedules(schedule=60, repeat=60*10, repeat_until=None)
                logger.info(f"{_now_} Scheduling2 check_device_schedules task after app startup.")
        except Exception as e:
            logger.error(f"Error while fetching device schedules from DB: {str(e)}")
            
        logger.info("Logger: Background tasks scheduled.")