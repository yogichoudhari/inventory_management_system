from django.contrib import admin
from .models import Product, User, Roll, Account, Permission
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display=["id", "user", "phone", "roll", "state", "city", "account", "display_permissions"]
    def display_permissions(self, obj):
        return ', '.join([permission.permission_type+"_"+permission.related_to for permission in obj.permission.all()])
    
    display_permissions.short_description = 'Permissions'
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'category', "brand", "title", "actual_price", "discounted_price", 'quantity', 'in_stock', 'account']
@admin.register(Roll)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'name',]

@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'logo', 'created_at', "updated_at"]

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ['id', "permission_type", 'permission_set', 'related_to']
