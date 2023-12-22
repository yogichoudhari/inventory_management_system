from django.contrib import admin
from .models import Product, User, Roll, Account, Permission, PaymentLog, Survey
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display=["id", "user", "phone", "roll", "state", "city",
                   "account","stripe_id",
                   "is_verified"]
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'category', "brand", "title", "actual_price",
                     "discounted_price", 'quantity', 'in_stock', 'account', 'created_by']
@admin.register(Roll)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'name',]

@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'logo', 'created_at', "updated_at"]

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ['id', "permission_name", 'permission_set', 'related_to']

@admin.register(PaymentLog)
class PaymentLogAdmin(admin.ModelAdmin):
    list_display = ['id','amount','status','user','customer_stripe_id','created_at','product']

@admin.register(Survey)
class PaymentLogAdmin(admin.ModelAdmin):
    list_display = ['id','survey_id', 'collector_id', 'product']

