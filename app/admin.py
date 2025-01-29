from django.contrib import admin

# Register your models here.
from .models import Active_Capture
from .models import My_Devices
from .models import ACL_Summary
from .models import Show_NAT_DB
from .models import Global_Settings
from .models import ACL_GROSS
#from .models import Devices_Model

admin.site.register(Active_Capture)
admin.site.register(My_Devices)
admin.site.register(ACL_Summary)
admin.site.register(Show_NAT_DB)
admin.site.register(Global_Settings)
admin.site.register(ACL_GROSS)
#admin.site.register(Devices_Model)