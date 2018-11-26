from django.contrib import admin

# Register your models here.
from systems.models import *

admin.site.register(SystemLog)
admin.site.register(SystemsAlert)
admin.site.register(SystemsEmailNotify)
admin.site.register(SystemsLicense)
admin.site.register(SystemsNetworkConfig)
admin.site.register(SystemsProxy)
admin.site.register(SystemStatistics)

