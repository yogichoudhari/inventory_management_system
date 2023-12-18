
from rest_framework.response import Response
from django.core.exceptions import ValidationError
from rest_framework.decorators import api_view,permission_classes,authentication_classes
from rest_framework.permissions import IsAdminUser,IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework import status
from .models import Product
from django.contrib.auth.models import User
from .models import User as CustomUser,Account, Permission, PaymentLog
from django.contrib import auth
from .serializers import (ProductSerializer,CustomUserSerializer,
                          LoginSerializer, UpdateCustomUserSerializer,
                          CheckProductSerializer, SearchedProductListSerializer, 
                          AdminUserSerializer,PermissionSerializer, PaymentLogSerializer)
from .models import Product, Roll, state_choices , Survey
from indian_cities.dj_city import cities
from django.db.models import Q
from django.forms.models import model_to_dict
import stripe
from django.conf import settings
import json
import pdb
from decouple import config
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.core.cache import cache
import random
from django.core.mail import send_mail
from .utility_functions import (get_tokens_for_user, generate_otp, otp_temp_storage,
                                send_email,send_otp_via_email)
import logging
import requests
# for views responses

STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"  

# Monkeysurvey Configuration

SM_API_BASE = "https://api.surveymonkey.com"
AUTH_CODE_ENDPOINT = "/oauth/authorize"
ACCESS_TOKEN_ENDPOINT = "/oauth/token"
redirect_uri = "http://localhost:8000/api/survey/oauth/callback"
CLIENT_ID= config("CLIENT_ID")
CLIENT_SECRET = config("CLIENT_SECRET")

#log configuration 
logging.basicConfig(filename="logfile.log",style='{',level=logging.DEBUG,format="{asctime} - {lineno}-- {message}")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
stripe.api_key = config("STRIPE_SECRET_KEY")

@api_view(['POST',"GET"])
def register_admin(request):
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
        serialized = AdminUserSerializer(data=user_data)
        if serialized.is_valid():
            created_user_instance = serialized.save()
            customer_stripe_response = stripe.Customer.create(
                name = created_user_instance.user.username,
                email = created_user_instance.user.email
            )
            created_user_instance.stripe_id = customer_stripe_response.id
            created_user_instance.save()
            send_otp_via_email(created_user_instance)
            return Response({'status':'success',
                             'message':'An email is sent for verification'},
                            status=status.HTTP_201_CREATED)
        else:   
            return Response({"status":STATUS_FAILED,
                             "message":serialized.errors},
                            status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST","GET"])
@permission_classes([IsAuthenticated,IsAdminUser])
def create_user(request):
    if request.method=="GET":
        states = [state for state,_ in state_choices]
        city = [{state:[c[0] for c in city] for state,city in cities}]
        data = {"states":states,
                "cities":city}
        return Response({"status":STATUS_SUCCESS,"data":data},
                        status=status.HTTP_200_OK)
    if request.method=="POST":
        user_data = request.data
        user_instnace = request.user.extra_user_fields
        account_instance = Account.objects.get(admin=user_instnace)
        serialized = CustomUserSerializer(data=user_data,
                    context={"user":user_instnace,"account":account_instance})
        if serialized.is_valid():
            created_user_instance = serialized.save()
            customer_stripe_response = stripe.Customer.create(
                name = created_user_instance.user.username,
                email = created_user_instance.user.email
            )
            created_user_instance.stripe_id = customer_stripe_response.id
            created_user_instance.save()
            return Response({"status":STATUS_SUCCESS,"message":"user is created successfully"},
                            status=status.HTTP_201_CREATED)
        else:   
            return Response({"status":STATUS_FAILED,
                             "message":serialized.errors},
                            status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def resend_otp(request):
    email = request.data.get('email')
    try:
        auth_user = User.objects.get(email=email)
        user = CustomUser.objects.get(user=auth_user)
        send_otp_via_email(user)
    except Exception as e:
        logger.exception(f"an error occured : that email is incorrect")
        return Response({"status":STATUS_FAILED,"error":"user does not exist"},
                        status=status.HTTP_400_BAD_REQUEST)
    return Response({'status':STATUS_SUCCESS,"message":"otp is successfully sent"},
                    status=status.HTTP_200_OK)



@api_view(['POST'])
def verify(request):
    
    otp = request.data.get('otp')
    user_id = cache.get(otp)
    logger.debug(f'Cache keys {cache.keys("*")}')
    try:
        user_instance = CustomUser.objects.get(id=user_id)
        logger.debug(f'Cache keys {cache.keys("*")}')
    except Exception as e:
        logger.debug(f'Cache keys {cache.keys("*")}')
        logger.exception(f'incorret key')
        return Response({"status":STATUS_FAILED,"error":"incorrect otp entered"},
                         status=status.HTTP_400_BAD_REQUEST)
    otp_key = "otp_"+str(user_instance.id)
    if otp_key in cache:
        stored_otp = cache.get(otp_key)
        if otp==stored_otp:
            user_instance.is_verified=True
            user_instance.save()
            cache.delete(otp_key)
            return Response({"status":STATUS_SUCCESS,"message":"user is verified"},
                            status=status.HTTP_200_OK)
        else:
            return Response({"status":STATUS_FAILED,"error":"incorrect otp"},
                           status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"status":STATUS_FAILED,"error":"otp is expired"},
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
        if username!='admin':
            extra_user_fields = CustomUser.objects.get(user=user)
            if user is not None and extra_user_fields.is_verified:
                auth.login(request,user)
                token = get_tokens_for_user(user)
                return Response({"status":STATUS_SUCCESS,
                                 'message':'user logged in successfully',
                                 "token":token},
                                content_type='application/json')
            else:
                return Response({'status':STATUS_FAILED,'error':"user not varified"},
                                status=status.HTTP_403_FORBIDDEN)
        elif username=='admin':
                auth.login(request,user)
                token = get_tokens_for_user(user)
                return Response({"status":STATUS_SUCCESS,
                                 'message':'user logged in successfully',
                                 "token":token},
                                content_type='application/json')                
    return Response({"status":STATUS_FAILED,
                     "error":serialized.errors})

@api_view(['POST'])
@permission_classes([IsAdminUser,IsAuthenticated])
def grant_permission_to_user(request):
    try:
        new_permission_set = request.data.get('permission_set')
        related_to = request.data.get('related_to')
        user_id = request.data.get('user_id')
        admin_user = CustomUser.objects.get(user=request.user)
        account = admin_user.account
        user_set = CustomUser.objects.filter(account=account)
        user_instance= user_set.get(pk=user_id)
        permissions = user_instance.permission.all()
        if permissions:
            for permission in permissions:
                if permission.related_to==related_to:
                    permission_instance=permission
            permission_set = permission_instance.permission_set
            permission_set.update(new_permission_set)
            get_permission_obj = Permission.objects.get(permission_set=permission_set)
            user_instance.permission.set([get_permission_obj])
            user_instance.save()
            return Response({"status":STATUS_SUCCESS,
                             "message":"permission granted"},
                    status=status.HTTP_201_CREATED)
        else:
            permission_instance = Permission.objects.get(permission_set=permission_set,
                                                         related_to=related_to)
            user_instance.permission.set([permission_instance])
            user_instance.save()
            return Response({"status":STATUS_SUCCESS,
                             "message":"permission granted"},
                    status=status.HTTP_201_CREATED)
    except Permission.DoesNotExist:
        return Response({"status":STATUS_FAILED,
                         "errors":"incorrect permission type provided"},
                        status=status.HTTP_400_BAD_REQUEST)
    except CustomUser.DoesNotExist:
        return Response({"status":STATUS_FAILED,
                         "errors":"incorrect user id provided"},
                        status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAdminUser,IsAuthenticated])
def create_permission_set(request):
    serializer_permission = PermissionSerializer(data=request.data)
    if serializer_permission.is_valid():
        serializer_permission.save()
        return Response({"status":STATUS_SUCCESS,
                         "message":"permission set successfully created"},
                        status=status.HTTP_201_CREATED)
    else:
        return Response({"status":STATUS_FAILED,
                         "errors":serializer_permission.errors},
                        status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST',"GET"])
@permission_classes([IsAuthenticated])
def user_profile(request):
    if request.method=='GET':
        add_on_fields = request.user.extra_user_fields
        add_on_fields_serialize = UpdateCustomUserSerializer(add_on_fields)
        return Response({"status":STATUS_SUCCESS,
                         "data":add_on_fields_serialize.data},
                        status=status.HTTP_200_OK)
    if request.method=="POST":
        id = request.data.get('id')
        nested_user_data= request.data.get("user")
        nested_user_id = nested_user_data.get("id")
        user_instance = CustomUser.objects.get(pk=id)
        user_serialize = UpdateCustomUserSerializer(user_instance,
                        data=request.data,partial=True,
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
@cache_page(120)
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
def check_product(request,param):
    user = CustomUser.objects.get(user=request.user)
    account = user.account
    serialize_param = CheckProductSerializer(data=param)
    if serialize_param.is_valid():
        search_param = serialize_param.data.get("param")
        if len(search_param)>=3:
            products = Product.objects.filter(Q(brand__icontains=search_param)|
                                          Q(category__icontains=search_param)|
                                          Q(title__icontains=search_param),
                                          account=account)
        else:
            products = Product.objects.filter(Q(brand__icontains=search_param)|
                                          Q(category__icontains=search_param),
                                          account=account)

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
def update_stock(request):
    '''This view function is for updating the product and can be 
    
    updated by Administrator only.
    '''
    if not request.user.is_superuser and request.user.is_authenticated:
        user = CustomUser.objects.get(user=request.user)
        try:
            permissions = user.permission.all()
            for permission in permissions:
                if permission.related_to=="Product":
                    permission_instance = permission  
            permission = permission_instance.permission_set.get('can_create')   
        except:
            logger.exception(f"{request.user.username} does not have permissions")
            return Response({"status":STATUS_FAILED,
                             "error":"user do not have permission to update"},
                            status=status.HTTP_403_FORBIDDEN)
        if not permission:
            return Response({"status":STATUS_FAILED,
                             "error":"user do not have permission to update"},
                            status=status.HTTP_403_FORBIDDEN)
    product_id = request.data.get('id')
    try:
        product = Product.objects.get(pk=product_id)
    except Product.DoesNotExist:
        logger.exception(f"product {product_id} does not exist in product table")
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
def add_product(request):
    pdb.set_trace()
    if not request.user.is_superuser and request.user.is_authenticated:
        user_instance = CustomUser.objects.get(user=request.user)
        try:
            permissions = user_instance.permission.all()
            for permission in permissions:
                if permission.related_to=="Product":
                    permission_instance = permission
            permission = permission_instance.permission_set.get('can_create')
        except:
            return Response({"status":STATUS_FAILED,
                             "error":"user do not have permission to add product"},
                            status=status.HTTP_403_FORBIDDEN)
        if not permission:
            return Response({"status":STATUS_FAILED,
                             "error":"user do not have permission to product"},
                            status=status.HTTP_403_FORBIDDEN)

    user_instance = CustomUser.objects.get(user=request.user)
    serialize_product_data = ProductSerializer(data=request.data,
                                               many=type(request.data)==list,
                                               context={'user_instance':user_instance})
    if serialize_product_data.is_valid():
        product = serialize_product_data.save()
        product_id = product.id
        url = "https://api.surveymonkey.com/v3/surveys"
        access_token = cache.get('access_token')
        headers = {
	    'accept': "application/json",
	    'Authorization': f"Bearer {access_token}",
		'Content-type':"application/json"
	    }
        survey_payload = {
          "title": " Product Quality Survey",
          "pages": [
            {
              "questions": [
              {
            "headings": [
                {
                    "heading": "which star would you like to give this product??"
                }
            ],
            "position": 1,
            "family": "matrix",
            "subtype": "rating",
            "display_options": {
                "display_type": "emoji",
                "display_subtype": "star"
            },
            "forced_ranking": False,
            "answers":{
            "rows": [
              {
                "visible": True,
                "text": "",
                "position": 1
              }
            ],
            "choices": [
              {
                "weight": 1,
                "text": ""
              },
              {
                "weight": 2,
                "text": ""
              },
              {
                "weight": 3,
                "text": ""
              },
              {
                "weight": 4,
                "text": ""
              },
              {
                "weight": 5,
                "text": ""
              }
            ]
          }
        }
              ]
            }
          ]
        }


        survey_res = requests.post(url,json=survey_payload,headers=headers)
        survey_id = survey_res.json().get("id")
        collector_creation_end_point = f"/{survey_id}/collectors"
        url = url+collector_creation_end_point
        collector_payload = {
  			"type": "weblink",
  			"name": "My Collector",
  			"thank_you_page": {
  			  "is_enabled": True,
  			  "message": "Thank you for taking this survey."
  			},
  			"thank_you_message": "Thank you for taking this survey.",
            "allow_multiple_responses": True,
		}
        collector_res = requests.post(url=url,json=collector_payload,headers=headers)
        collector_id = collector_res.json().get("id")
        Survey.objects.create(survey_id=survey_id,collector_id=collector_id,product=product)
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
        user_id = user.id
        account = user.account
        try:
            product = Product.objects.get(pk=product_id,account=account)
        except Product.DoesNotExist:
            logger.exception(f"{product_id} is not associated with {account.name}")
            return Response({"status":STATUS_FAILED,
                             "message":"product not found"},
                            status=status.HTTP_404_NOT_FOUND)
        quantity = request.data.get("quantity")
        if product.quantity==0:
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
        customer_stripe_id =user.stripe_id
        user_instance_dict = model_to_dict(user)
        session = stripe.checkout.Session.create(
        line_items=[
            {"price_data":{
                "currency":"inr",
                "product_data":{
                    "name":product.category,
                    "description":product.title,
                },
                "unit_amount":int(product.discounted_price*100)
            },
            "quantity":quantity}
        ],
        metadata={
                "product_id":product_id,
                "product_quantity":quantity,
                "user_id":user_id
            },
        mode="payment",
        customer=customer_stripe_id,
        success_url="http://127.0.0.1:8000/api/payment-success/{CHECKOUT_SESSION_ID}",
        cancel_url="http://127.0.0.1:8000/api/payment-failed/{CHECKOUT_SESSION_ID}"
        )
        payment_url = session.url
        if session.payment_status!="unpaid":
            data = {"product name":product.brand +" "+product.title,
                    "quantity": quantity,
                    "discount":discount,
                    "total amount":discounted_price,
                    "message":f"you have saved {discount} on this order"}
            
        return Response({"status":STATUS_SUCCESS,"url":payment_url},
                         status=status.HTTP_200_OK)

@api_view(["GET"])
def payment_success(request,session_id):
    session = stripe.checkout.Session.retrieve(session_id)
    customer = stripe.Customer.retrieve(session.customer)
    if session["payment_status"]=="paid":
        product = Product.objects.get(pk=session.metadata.get('product_id'))
        product.quantity = product.quantity-int(session.metadata.get("product_quantity"))
        total_amount = session.amount_total/100
        if product.quantity==0:
            email = product.created_by.user.email
            subject = "Inventory Product Stock Notification"
            product_dict = model_to_dict(product)
            product_dict["account"] = product.account.name
            context = product_dict
            send_email(subject,email,"inventory_stock_email.html",context)
        product.save()
        user_instance = CustomUser.objects.get(id=session.metadata.get('user_id'))
        PaymentLog.objects.create(amount=total_amount,customer_stripe_id=session.customer,
                                user=user_instance,status=STATUS_SUCCESS,product=product)
        return Response({"status":STATUS_SUCCESS,
                     "message":f"your payment of {total_amount} is successfully done"},
                    status=status.HTTP_200_OK)

@api_view(["GET"])
def payment_failed(request,session_id):
    session = stripe.checkout.Session.retrieve(session_id)
    customer = stripe.Customer.retrieve(session.customer)
    if session['payment_status']=="unpaid":
        total_amount = session.amount_total/100
        user_instance = CustomUser.objects.get(id=session.metadata.get('user_id'))
        PaymentLog.objects.create(amount=total_amount,customer_stripe_id=session.customer,
                                user=user_instance,status=STATUS_FAILED,product=product)
        return Response({"status":STATUS_FAILED,
                         "message":f"payment of {total_amount} was unsuccessfull"},
                        status=status.HTTP_400_BAD_REQUEST)
    
@api_view(["POST","GET"])
@permission_classes([IsAuthenticated])
def product_feedback(request,product_id):
    product_id = product_id
    user = CustomUser.objects.get(user=request.user)
    product = Product.objects.get(id=product_id)
    access_token = cache.get('access_token')
    headers = {
	'accept': "application/json",
	'Authorization': f"Bearer {access_token}"
	}
    if request.method=="POST":
        try:
            product_log = PaymentLog.objects.filter(product=product,user=user).last()
        except:
            return Response({"status":STATUS_FAILED,'error':"product needs to be purchased first in order to review it"},
                            status=status.HTTP_400_BAD_REQUEST)
        survey_obj = Survey.objects.get(product=product)
        collector_id = survey_obj.collector_id
        endpoint_url = f"/v3/collectors/{collector_id}"
        url = SM_API_BASE + endpoint_url
        collector = requests.get(url=url,headers=headers)
        collector_url = collector.json().get('url')
        return Response({"status":STATUS_SUCCESS,'url':collector_url},
                    status=status.HTTP_200_OK)
    elif request.method=="GET":
        user = CustomUser.objects.get(user=request.user)
        if request.user.is_superuser and user.account==product.account:
            survey_obj = Survey.objects.get(product=product)
            survey_id = survey_obj.survey_id
            endpoint_url = f"/v3/surveys/{survey_id}"
            url = SM_API_BASE + endpoint_url
            survey_res = requests.get(url=url,headers=headers)
            analyze_url = survey_res.json().get("analyze_url")
            return Response({"status":STATUS_SUCCESS,"url":analyze_url},
                            status=status.HTTP_200_OK)
        elif not request.user.is_superuser:
            return Response({"status":STATUS_FAILED,"error":"user does not have permission"},
                            status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({"status":STATUS_FAILED,"url":None},
                            status=status.HTTP_404_NOT_FOUND)

@api_view(["GET"])
@permission_classes([IsAdminUser,IsAuthenticated])
def users(request):
    user = CustomUser.objects.get(user=request.user)
    account = user.related_account
    users = CustomUser.objects.filter(account=account)
    serialize_instances = UpdateCustomUserSerializer(users,many=True)
    return Response({'status':STATUS_SUCCESS,"data":serialize_instances.data},
                    status=status.HTTP_200_OK)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def payment_history(request):
    user = CustomUser.objects.get(user=request.user)
    payment_history_instances = PaymentLog.objects.filter(user=user)
    serialize_payments_log = PaymentLogSerializer(payment_history_instances,
                                                  many=True)
    payment_history_list = serialize_payments_log.data
    return Response({"status":STATUS_SUCCESS,"data":payment_history_list},
                    status=status.HTTP_200_OK)


