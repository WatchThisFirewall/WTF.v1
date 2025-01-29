
from django.urls import path
from . import views

urlpatterns = [
    #path('index.html', views.index, name='home'),
    
    # path('start-task/', views.start_task, name='start_task'),
    # path('task-status/<int:task_id>/', views.task_status, name='task_status'),
    # path('task-progress/<int:task_id>/', views.task_progress, name='task_progress'),
    #path('run-script/', views.run_script, name='run_script'),
    path('run_scriptASA_Test_Conn/<t_IP_Address>', views.run_scriptASA_Test_Conn, name='run_scriptASA_Test_Conn'),
    path('run_Script_WTF/<t_IP_Address>', views.run_Script_WTF, name='run_Script_WTF'),
    path('run_Script_WTF_Shell/<t_IP_Address>', views.run_Script_WTF_Shell, name='run_Script_WTF_Shell'),
    #path('Test_Streaming/<slug:FW_NAME>/', views.Test_Streaming, name='Test_Streaming'),
    path('test_table/', views.test_table, name='test_table'),
    path('submask_table/', views.submask_table, name='submask_table'),
    path('subnetting/', views.subnetting, name='subnetting'),
    path('wtf_logs', views.wtf_logs, name='wtf_logs'),

    path('', views.index, name='home'),
    path('acl_too_open/<slug:FW_NAME>/', views.acl_too_open, name='acl_too_open'),
    path('capture/<slug:FW_NAME>/', views.capture, name='capture'),
    path('confdiff/<slug:FW_NAME>/', views.confdiff, name='confdiff'),
    path('config_range/<slug:FW_NAME>/', views.config_range, name='config_range'),
    path('dashboard/<str:FW_NAME>/', views.dashboard, name='dashboard'),    
    path('deltahitcnt0acl/<slug:FW_NAME>/', views.deltahitcnt0acl, name='deltahitcnt0acl'),
    path('deltahitcnt0nat/<slug:FW_NAME>/', views.deltahitcnt0nat, name='deltahitcnt0nat'),
    path('drill_down_acls/<slug:FW_NAME>/', views.drill_down_acls, name='drill_down_acls'),
    path('expandedacl/<slug:FW_NAME>/', views.expandedacl, name='expandedacl'),    
    path('inactiveacl/<slug:FW_NAME>/', views.inactiveacl, name='inactiveacl'),
    path('inactivenat/<slug:FW_NAME>/', views.inactivenat, name='inactivenat'),
    #path('inactivenat_txt/<slug:FW_NAME>/', views.inactivenat_txt, name='inactivenat_txt'),
    path('logdisabledacl/<slug:FW_NAME>/', views.logdisabledacl, name='logdisabledacl'),
    path('most_triggered_nat/<slug:FW_NAME>/', views.most_triggered_nat, name='most_triggered_nat'),
    path('nologacl/<slug:FW_NAME>/', views.nologacl, name='nologacl'),
    path('notappacl/<slug:FW_NAME>/', views.notappacl, name='notappacl'),
    path('not_ascii/<slug:FW_NAME>/', views.not_ascii, name='not_ascii'),
    path('objgrpnet_not_applied/<slug:FW_NAME>/', views.objgrpnet_not_applied, name='objgrpnet_not_applied'),
    path('objgrpnet_duplicated/<slug:FW_NAME>/', views.objgrpnet_duplicated, name='objgrpnet_duplicated'),
    path('objgrpsvc_not_applied/<slug:FW_NAME>/', views.objgrpsvc_not_applied, name='objgrpsvc_not_applied'),    
    path('objgrpsvc_duplicated/<slug:FW_NAME>/', views.objgrpsvc_duplicated, name='objgrpsvc_duplicated'),
    path('objnet_not_applied/<slug:FW_NAME>/', views.objnet_not_applied, name='objnet_not_applied'),
    path('objnet_duplicated/<slug:FW_NAME>/', views.objnet_duplicated, name='objnet_duplicated'),
    path('objsvc_not_applied/<slug:FW_NAME>/', views.objsvc_not_applied, name='objsvc_not_applied'),
    path('objsvc_duplicated/<slug:FW_NAME>/', views.objsvc_duplicated, name='objsvc_duplicated'),
    path('redundant_routes/<slug:FW_NAME>/', views.redundant_routes, name='redundant_routes'),
    path('dst_vs_routing/<slug:FW_NAME>/', views.dst_vs_routing, name='dst_vs_routing'),
    path('src_vs_routing/<slug:FW_NAME>/', views.src_vs_routing, name='src_vs_routing'),
    path('use_declared_obj/<slug:FW_NAME>/', views.use_declared_obj, name='use_declared_obj'),
    path('deny_acl_triggered/<slug:FW_NAME>/', views.deny_acl_triggered, name='deny_acl_triggered'),
    path('Most_Hitted_ACL/<slug:FW_NAME>/', views.Most_Hitted_ACL, name='Most_Hitted_ACL'),
    path('unprotected_if/<slug:FW_NAME>/', views.unprotected_if, name='unprotected_if'),
    #settings
    path('delete_device/<t_IP_Address>', views.delete_device, name='delete_device'),
    #path('yourmodel/<int:pk>/delete/', views.delete_yourmodel, name='yourmodel_delete'),
    path('global_settings', views.global_settings, name='global_settings'),
    path('default_credentials', views.default_credentials, name='default_credentials'),
    path('db_settings', views.db_settings, name='db_settings'),
    path('manage_devices', views.manage_devices, name='manage_devices'),
    path('add_device.html', views.add_device, name='add_device'),
    path('edit_device/<t_IP_Address>', views.edit_device, name='edit_device'),
    
    #actions
    
    
    path('Fetching_Config_Spinner/<str:FW_NAME>/', views.get_Fetching_Config_Spinner_status, name='Fetching_Config_Spinner'),
    path('Processing_Conf_Spinner/<str:FW_NAME>/', views.get_Processing_Conf_Spinner_status, name='Processing_Conf_Spinner'),    
]


