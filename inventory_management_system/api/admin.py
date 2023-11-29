from django.contrib import admin
from .models import Product, User, Roll
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display=["id", "user", "phone", "roll", "state", "city", "managed_by"]
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'category', "brand", "title", "actual_price", "discounted_price", 'quantity', 'in_stock']
@admin.register(Roll)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'name',]

# @admin.register(Account)
# class AccountAdmin(admin.ModelAdmin):
#     list_display = ['id', 'name', 'logo', 'created_at', "updated_at"]
