# myapp/tasks.py
from background_task import background
from models import TaskProgress
import time
import models

@background(schedule=10)
def long_running_task(task_id):
    progress_entry = TaskProgress.objects.create(task_id=task_id)
    
    for i in range(100):
        # Simulate work being done
        time.sleep(1)
        progress_entry.progress = i + 1
        progress_entry.save()
    
    progress_entry.status = "Completed"
    progress_entry.save()