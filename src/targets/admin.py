from django.contrib import admin

# Register your models here.
from targets.models import *

admin.site.register(TargetsModel)
admin.site.register(TargetConfigurationsModel)
admin.site.register(SchedulerModel)
admin.site.register(TasksModel)
admin.site.register(TaskStatisticsModel)

