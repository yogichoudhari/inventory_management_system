from rest_framework import serializers
from django.contrib.auth.models import User
from .models import User as CustomUser , Account, Permission
from .models import Product, Roll, state_choices
from indian_cities.dj_city import cities
import re
import pdb
class UserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ["username", "password", "password2", 
                  "first_name", "last_name", "email"]

    def validate(self,attrs):
        username = attrs.get('username')
        regex = "^[A-Za-z]{2,}[0-9^_!@$%^&*()_+{}:\"><?}|][0-9]*"
        username_pattern = re.compile(regex)
        if not re.match(username_pattern,username):
            raise serializers.ValidationError("Invalid username")
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password!=password2:
            raise serializers.ValidationError('password does not match')
        regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
        password_pattern = re.compile(regex)
        if not re.match(password_pattern,password):
            raise serializers.ValidationError("password should be 6-20 charachters alphanumerical")

        return attrs
    
    def create(self,validated_data):
        password = validated_data.get('password')
        validated_data.pop("password2",None)
        if self.context.get('is_admin'):
            user = User.objects.create_superuser(**validated_data)
        else:
            user = super().create(validated_data)
        user.set_password(password)
        user.save()
        return user

class RollSerializer(serializers.Serializer):
    name = serializers.CharField()

class CustomUserSerializer(serializers.ModelSerializer):
    roll = RollSerializer()
    user = UserSerializer()
    class Meta:
        model = CustomUser
        fields = ["user", "phone", "roll", "state", 
                  "city", "account"]

    def validate(self,data):
        state_value = data.get('state')
        city_value = data.get('city')
        for state,city_list in cities:
            if state == state_value:
                for city,_ in city_list:
                    if city==city_value:
                        break
                else:
                    raise serializers.ValidationError("please enter correct city")
        return data

    def create(self,validated_data):
        user_data = validated_data.pop("user")
        roll_name = validated_data.pop("roll")
        account_instance = self.context.get("account")
        try:
            roll_obj = Roll.objects.get(name=roll_name.get('name').capitalize())
        except Exception as e:
            raise serializers.ValidationError("incorrect roll")
        user_serialize = UserSerializer(data=user_data,context={"is_admin":False})
        if user_serialize.is_valid():
            user_instance = user_serialize.save()
        custom_user , created = CustomUser.objects.get_or_create(user=user_instance,
                                                                account=account_instance,
                                                                 roll=roll_obj,
                                                                **validated_data)
        return custom_user

class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "first_name", "last_name", "email"]

    def update(self,instance,validated_data):
        instance.username = validated_data.get('username',instance.username)
        instance.first_name = validated_data.get('first_name',instance.first_name)
        instance.last_name = validated_data.get('last_name',instance.last_name)
        instance.email = validated_data.get('email',instance.email)
        instance.save()
        return instance

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ['name']

    def create(self,validated_data):
        admin = self.context.get('user_obj')
        return Account.objects.create(admin=admin,**validated_data)
    

            
class GrantPermissionSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    permission_set = serializers.JSONField()

    def update(self,instance,validated_data):
        instance.name = validated_data.get('name',instance.name)
        instance.permission_set = validated_data.get('permission_set',instance.permission_set)
        instance.save()
        return instance

    def create(self,validated_data):
        id = validated_data.pop('id')
        user_instance = CustomUser.objects.get(pk=id)
        permission_name = validated_data.get('name')
        try:
            if permission_name == user_instance.permission.name:
                permission_instance = user_instance.permission
                permission_set = permission_instance.permission_set
                permission_set.update(validated_data["permission_set"])
                updated_permission_set = permission_set
                update_permission_serializer = GrantPermissionSerializer(permission_instance,
                                                                         data=updated_permission_set,
                                                                        partial=True)
                if update_permission_serializer.is_valid():
                    permission_instance = update_permission_serializer.save()
                user_instance.permission = permission_instance
                user_instance.save()
                return permission_instance
        except:
            def default_permission_dict():
                return {
                "can_create":False,
                "can_update":False,
                "can_create_or_update":False
            }
            permission_dict = default_permission_dict()
            permission_dict.update(validated_data['permission_set'])
            validated_data['permission_set'] = permission_dict
            permission_instance = Permission.objects.create(**validated_data)
            user_instance.permission = permission_instance
            user_instance.save()
            return permission_instance


        


class UpdateCustomUserSerializer(serializers.ModelSerializer):
    user = UpdateUserSerializer()
    account = AccountSerializer(read_only=True)
    class Meta:
        model = CustomUser
        fields = ["id", "user", "phone", "state", "city", 'account']

    def update(self,instance,validated_data):
        user_data = validated_data.pop("user")
        user_id = self.context.get("user_id")
        user_instance = User.objects.get(pk=user_id)
        user_serializer = UpdateUserSerializer(user_instance,data=user_data,partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
        instance.phone = validated_data.get("phone",instance.phone)
        instance.city = validated_data.get("city",instance.city)
        instance.state = validated_data.get("state",instance.state)
        instance.save()
        return instance
    
class AdminUserSerializer(serializers.ModelSerializer):
    account = AccountSerializer()
    user = UserSerializer()
    roll = RollSerializer()
    class Meta:
        model = CustomUser
        fields = ['user', 'phone', 'roll', 'state', 'city', "account"]
        
    def validate(self,data):
        state_value = data.get('state')
        city_value = data.get('city')
        for state,city_list in cities:
            if state == state_value:
                for city,_ in city_list:
                    if city==city_value:
                        break
                else:
                    raise serializers.ValidationError("please enter correct city")
        return data
    
    def create(self,validated_data):
        user_data = validated_data.pop('user')
        roll_name = validated_data.pop('roll')
        account_data = validated_data.pop('account')
        user_serialize = UserSerializer(data=user_data,context={'is_admin':True})
        roll_obj = Roll.objects.get(name=roll_name.get('name').capitalize())
        if user_serialize.is_valid():
            user_instance = user_serialize.save()
        admin_user , created = CustomUser.objects.get_or_create(user=user_instance,roll=roll_obj,**validated_data)
        account_serialize = AccountSerializer(data=account_data,context={'user_obj':admin_user})
        if account_serialize.is_valid():
            account_instance = account_serialize.save()
            admin_user.account = account_instance
            admin_user.save()
        return admin_user
    

class ProductSerializer(serializers.ModelSerializer):
    in_stock = serializers.SerializerMethodField(read_only=True)
    class Meta:
        model = Product
        exclude = ['account']

    def update(self, instance, validated_data):
        validated_data['quantity']+=instance.quantity
        return super().update(instance, validated_data)
    def create(self,validated_data):
        account_obj = self.context.get('account_obj')
        validated_data["account"] = account_obj
        return super().create(validated_data)
    def get_in_stock(self,obj):
        return obj.in_stock
    

class CheckProductSerializer(serializers.Serializer):
    param = serializers.CharField()

class SearchedProductListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = "__all__"
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError("incorrect username")
        if not user.check_password(password):
            raise serializers.ValidationError("incorrect password entered")
        return attrs
        
    
