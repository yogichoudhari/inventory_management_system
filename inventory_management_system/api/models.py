from django.db import models
from django.contrib.auth.models import User as BuiltInUser
from django.core.exceptions import ValidationError
from indian_cities.dj_city import cities
from django.dispatch import receiver
from django.db.models.signals import post_delete
from django.utils import timezone
import pdb
state_choices = (("Andhra Pradesh","Andhra Pradesh"),
                 ("Arunachal Pradesh ","Arunachal Pradesh "),
                 ("Assam","Assam"),
                 ("Bihar","Bihar"),
                 ("Chhattisgarh","Chhattisgarh"),
                 ("Goa","Goa"),
                 ("Gujarat","Gujarat"),
                 ("Haryana","Haryana"),
                 ("Himachal Pradesh","Himachal Pradesh"),
                 ("Jammu and Kashmir ","Jammu and Kashmir "),
                 ("Jharkhand","Jharkhand"),
                 ("Karnataka","Karnataka"),
                 ("Kerala","Kerala"),
                 ("Madhya Pradesh","Madhya Pradesh"),
                 ("Maharashtra","Maharashtra"),
                 ("Manipur","Manipur"),
                 ("Meghalaya","Meghalaya"),
                 ("Mizoram","Mizoram"),
                 ("Nagaland","Nagaland"),
                 ("Odisha","Odisha"),
                 ("Punjab","Punjab"),
                 ("Rajasthan","Rajasthan"),
                 ("Sikkim","Sikkim"),
                 ("Tamil Nadu","Tamil Nadu"),
                 ("Telangana","Telangana"),
                 ("Tripura","Tripura"),
                 ("Uttar Pradesh","Uttar Pradesh"),
                 ("Uttarakhand","Uttarakhand"),
                 ("West Bengal","West Bengal"),
                 ("Andaman and Nicobar Islands","Andaman and Nicobar Islands"),
                 ("Chandigarh","Chandigarh"),
                 ("Dadra and Nagar Haveli","Dadra and Nagar Haveli"),
                 ("Daman and Diu","Daman and Diu"),
                 ("Lakshadweep","Lakshadweep"),
                 ("Delhi","Delhi"),
                 ("Puducherry","Puducherry"))




class Roll(models.Model):
    roll_choices = (
        ('Admin',"Admin"),
        ("Customer","Customer")
    )
    name = models.CharField(choices=roll_choices, max_length=50)

    def __str__(self):
        return self.name


def phone_validator(value):
    if len(value)>10 or len(value)<10:
        raise ValidationError("phone number should be 10 digit")
    try:
        if type(int(value))==int:
            return value
    except ValueError:
        raise ValidationError("number should be numerical")
    

class Permission(models.Model):
    permission_name = models.CharField(max_length=80,null=False)
    permission_set = models.JSONField(null=False)
    related_to = models.CharField(null=False)
    def __str__(self):
        permission_set  = {k:v for k,v in self.permission_set.items() if v==True}
        return str(permission_set) + "_" +str(self.related_to)
        
class User(models.Model):
    user = models.OneToOneField(BuiltInUser, on_delete=models.CASCADE, related_name="extra_user_fields")
    roll = models.ForeignKey(Roll,on_delete=models.CASCADE)
    phone = models.CharField(validators=[phone_validator],max_length=10,null=False)
    city = models.CharField(choices=cities,max_length=50)
    state = models.CharField(choices=state_choices, max_length=35)
    account = models.ForeignKey('Account',on_delete=models.SET_NULL,related_name='users',null=True)
    permission = models.ManyToManyField(Permission)
    stripe_id = models.CharField(max_length=55,null=True)
    def __str__(self):
        return self.user.username

@receiver(post_delete,sender=User)
def delete_builtin_user(sender,instance,**kwargs):
    instance.user.delete()
class Account(models.Model):
    admin = models.OneToOneField(User,on_delete=models.CASCADE,related_name='related_account')
    name = models.CharField(max_length=33,null=False,blank=False)
    logo = models.BinaryField(null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(null=True,blank=True)
    def save(self,*args,**kwargs):
        if self.created_at:
            self.updated_at = timezone.now()
        super(Account,self).save(*args,**kwargs)
    def __str__(self):
        return self.name

class Product(models.Model):
    category = models.CharField(max_length=100,null=False,blank=False)
    brand = models.CharField(max_length=25,default="")
    title = models.CharField(max_length=250,default="")
    quantity = models.PositiveIntegerField(default=0,null=False,blank=False)
    actual_price = models.PositiveIntegerField(default=99,null=False,blank=False)
    discounted_price = models.PositiveIntegerField(default=99,null=False,blank=False)
    account = models.ForeignKey(Account,on_delete=models.CASCADE)
    created_by = models.ForeignKey(User,on_delete=models.CASCADE,null=False)

    def save(self,*args,**kwargs):
        self.category = self.category.title()
        self.title = self.title.title()
        self.brand = self.brand.title()
        super(Product,self).save(*args,**kwargs)
    def __str__(self):
        return self.category
    
    @property
    def in_stock(self):
        if self.quantity>0:
            return "Available"
        else:
            return "out of stock"


class PaymentLog(models.Model):
    amount = models.PositiveIntegerField()
    customer_stripe_id = models.CharField(max_length=200)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    payment_status_choices = [
        ('success','success'),
        ('failed', 'failed')
    ]
    status = models.CharField(choices=payment_status_choices)
    created_at = models.DateTimeField(auto_now_add=True)