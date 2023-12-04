
from rest_framework.response import Response
from django.core.exceptions import ValidationError
from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import IsAdminUser,IsAuthenticated
from rest_framework import status
from .models import Product
from django.contrib.auth.models import User
from .models import User as CustomUser,Account
from django.contrib import auth
from .serializers import (ProductSerializer,CustomUserSerializer,
                          LoginSerializer, UpdateCustomUserSerializer,
                          CheckProductSerializer, SearchedProductListSerializer, 
                          AdminUserSerializer, GrantPermissionSerializer)
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Product, Roll, state_choices
from indian_cities.dj_city import cities
from django.db.models import Q
from django.forms.models import model_to_dict
import stripe
from django.conf import settings
import json
import pdb

# for views responses
STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"  

def get_tokens_for_user(user):

    '''This view is used to create token for user'''
    
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }




@api_view(['POST',"GET"])
@permission_classes([IsAuthenticated,IsAdminUser])
def register(request):
    '''This view function is being used by the admin user to 
    
    register the new user
    '''
    if request.method=="GET":
        states = [state for state,_ in state_choices]
        city = [{state:[c[0] for c in city] for state,city in cities}]
        data = {"states":states,
                "cities":city}
        return Response({"status":STATUS_SUCCESS,"data":data},
                        status=status.HTTP_200_OK)
    if request.method=="POST":
        user_data = request.data
        roll = request.data.get('roll').get('name').capitalize()
        if roll=='Admin' and 'account' in request.data:
            serialized = AdminUserSerializer(data=user_data)
        elif roll!='Admin':
            user_instnace = request.user.extra_user_fields
            account_instance = Account.objects.get(admin=user_instnace)
            serialized = CustomUserSerializer(data=user_data,
                                             context={"user":user_instnace,
                                                      "account":account_instance})
        else:
            return Response({'status':STATUS_FAILED,'message':'provide the account creation info'},
                            status=status.HTTP_400_BAD_REQUEST)
        if serialized.is_valid():
            serialized.save()
            return Response({'status':'success',
                             'message':'user is created Successfully'},
                            status=status.HTTP_201_CREATED)
        else:   
            return Response({"status":STATUS_FAILED,
                             "message":serialized.errors},
                            status=status.HTTP_400_BAD_REQUEST)


    
@api_view(["POST"])
def login(request):
    '''This view function is used for login and when user
    
    user logins he will be provided with the Authentication Token
    '''
    user_data = request.data
    serialized= LoginSerializer(data=user_data)
    if serialized.is_valid():
        username = serialized.data.get('username')
        password = serialized.data.get('password')
        user = auth.authenticate(username=username,
                                 password=password)
        if user is not None:
            auth.login(request,user)
            token = get_tokens_for_user(user)
            return Response({"status":STATUS_SUCCESS,
                             'message':'user logger in successfully',
                             "token":token},
                            content_type='application/json')

    return Response({"status":STATUS_FAILED,
                     "error":serialized.errors})

@api_view(['POST'])
@permission_classes([IsAdminUser,IsAuthenticated])
def grant_permission_to_user(request):
    serialize_permission_data = GrantPermissionSerializer(data=request.data)
    if serialize_permission_data.is_valid():
        serialize_permission_data.save()
        return Response({"status":STATUS_SUCCESS,"message":"permission granted"},
                        status=status.HTTP_201_CREATED)
    else:
        return Response({"status":STATUS_FAILED,"error":serialize_permission_data.errros},
                        status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST',"GET"])
@permission_classes([IsAuthenticated])
def update_user_profile(request):
    if request.method=='GET':
        add_on_fields = request.user.extra_user_fields
        add_on_fields_serialize = UpdateCustomUserSerializer(add_on_fields)
        return Response({"status":STATUS_SUCCESS,
                         "data":add_on_fields_serialize.data},
                        status=status.HTTP_200_OK)
    elif request.method=="POST":
        id = request.data.get('id')
        nested_user_data= request.data.get("user")
        nested_user_id = nested_user_data.get("id")
        user_instance = CustomUser.objects.get(pk=id)
        user_serialize = UpdateCustomUserSerializer(user_instance,
                                                    data=request.data,
                                                    partial=True,
                                                    context={"user_id":nested_user_id})
        if user_serialize.is_valid():
            user_serialize.save()
            return Response({"status":STATUS_SUCCESS,
                             "message":"profile is updated successfully"},
                             status=status.HTTP_201_CREATED)
        else:
            return Response({"status":STATUS_FAILED,
                             "message":user_serialize.errors},
                             status=status.HTTP_400_BAD_REQUEST)




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def product(request,id=None):
    '''Retrieve a single product if id is not None 
    or a list of all products.
    or a list of all products.
    '''
    try:
        user = CustomUser.objects.get(user=request.user)
        account = user.account
        if id is not None:
            product = Product.objects.get(pk=id,account=account)
            serialized= ProductSerializer(product).data
            return Response({"status":STATUS_SUCCESS,"data":serialized},
                            content_type='application/json',
                            status=status.HTTP_200_OK,)
        products = Product.objects.filter(account=account)
        serialized = ProductSerializer(products,many=True).data
        return Response({"status":STATUS_SUCCESS,"data":serialized},
                        content_type='application/json'
                        ,status=status.HTTP_200_OK)
    except Product.DoesNotExist:
        return Response({"status":STATUS_FAILED,
                         "message":"product does not exist"},
                        status=status.HTTP_404_NOT_FOUND)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def check_product(request):
    serialize_param = CheckProductSerializer(data=request.data)
    if serialize_param.is_valid():
        search_param = serialize_param.data.get("param")
        if len(search_param)>=3:
            products = Product.objects.filter(Q(brand__icontains=search_param)|
                                          Q(category__icontains=search_param)|
                                          Q(title__icontains=search_param))
        else:
            products = Product.objects.filter(Q(brand__icontains=search_param)|
                                          Q(category__icontains=search_param))

        product_list= SearchedProductListSerializer(products,many=True).data
        if not products:
            return Response({"status":STATUS_FAILED,"data":[]},
                            status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"status":STATUS_SUCCESS,"data":product_list},
                            status=status.HTTP_200_OK)
    else:
        return Response({"status":STATUS_FAILED,"message":"not available"},
                         status=status.HTTP_404_NOT_FOUND)

@api_view(["PATCH"])
@permission_classes([IsAdminUser])
def update_stock(request):
    '''This view function is for updating the product and can be 
    
    updated by Administrator only.
    '''
    product_id = request.data.get('id')
    try:
        product = Product.objects.get(pk=product_id)
    except Product.DoesNotExist:
        return Response({"status":STATUS_FAILED,
                         "message":"product not found"},
                        status=status.HTTP_404_NOT_FOUND)
    serialized = ProductSerializer(product,data=request.data,
                                   partial=True)
    if serialized.is_valid():
        serialized.save()
        return Response({"status":STATUS_SUCCESS,
                         "message": "product is updated"},
                        status=status.HTTP_200_OK)
    else:
        return Response({"status":STATUS_FAILED,
                         "message":serialized.errors},
                        status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes([IsAdminUser,IsAuthenticated])
def add_product(request):
    user = CustomUser.objects.get(user=request.user)
    account_obj = Account.objects.get(admin=user)

    # many=True is used to check if we are getting list of objects to create
    serialize_product_data = ProductSerializer(data=request.data,
                                               many=type(request.data)==list,
                                               context={'account_obj':account_obj})
    if serialize_product_data.is_valid():
        serialize_product_data.save()
        return Response({"status":STATUS_SUCCESS,
                         "message":"product added successfully"},
                        status=status.HTTP_201_CREATED)
    else:
        return Response({"status":STATUS_FAILED,
                         "error":serialize_product_data.errors},
                        status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET",'POST'])
@permission_classes([IsAuthenticated])
def make_purchase(request, id):  
    if request.method=="GET":
        product_id = id
        user = CustomUser.objects.get(user=request.user)
        account = user.account
        try:
            product = Product.objects.get(pk=product_id,account=account)
        except Product.DoesNotExist:
            return Response({"status":STATUS_FAILED,
                             "message":"product not found"},
                            status=status.HTTP_404_NOT_FOUND)
        quantity = request.data.get("quantity")
        # Check if the product is in stock
        if product.quantity==0:
            # Return a 400 response if the product is out of stock
            return Response({"status":STATUS_FAILED,
                             "message":f"Product is out of stock"},
                            status=status.HTTP_400_BAD_REQUEST)
        elif not product.quantity>=quantity:
            return Response({"status":STATUS_FAILED,
                             "message":f"Only {product.quantity} is in stock"},
                            status=status.HTTP_400_BAD_REQUEST)
        price = product.actual_price*quantity
        discounted_price = product.discounted_price*quantity
        discount = price-discounted_price
        product.quantity = product.quantity-quantity
        product.save()
        data = {"product name":product.brand +" "+product.title,
                "quantity": quantity,
                "discount":discount,
                "total amount":discounted_price,
                "message":f"you have saved {discount} on this order"}
        return Response({"status":STATUS_SUCCESS,"data":data},
                         status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAdminUser,IsAuthenticated])
def users(request):
    user = CustomUser.objects.get(user=request.user)
    account = user.related_account
    users = CustomUser.objects.filter(account=account)
    serialize_instances = UpdateCustomUserSerializer(users,many=True)
    return Response({'status':STATUS_SUCCESS,"data":serialize_instances.data},
                    status=status.HTTP_200_OK)




