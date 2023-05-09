from django.contrib import admin
from .models import User 

    
class AccountAdmin(admin.ModelAdmin):
	list_display = ['phone','is_registered']
	search_fields = ('is_registered','phone')
	filter_horizontal = ()
	list_filter = ('phone','is_registered')
	fieldsets = ()
        

admin.site.register(User, AccountAdmin)
