from django.shortcuts import render , redirect
from rest_framework.decorators import api_view
from urllib.parse import urlencode,urlsplit,parse_qs
from rest_framework.response import Response
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAdminUser,IsAuthenticated
from rest_framework import status
import pdb
import requests
import json
from decouple import config
import http.client
from django.core.cache import cache
from datetime import timedelta
import http.client
SM_API_BASE = "https://api.surveymonkey.com"
AUTH_CODE_ENDPOINT = "/oauth/authorize"
ACCESS_TOKEN_ENDPOINT = "/oauth/token"
redirect_uri = "http://localhost:8000/api/survey/oauth/callback"
CLIENT_ID= config("CLIENT_ID")
CLIENT_SECRET = config("CLIENT_SECRET")


@api_view(["GET"])
def oauth_dialog(request):
	url_params = urlencode({
		"redirect_uri": redirect_uri,
		"client_id": CLIENT_ID,
		"response_type": "code"
	})

	auth_dialog_uri = SM_API_BASE + AUTH_CODE_ENDPOINT + "?" + url_params
	return redirect(auth_dialog_uri)

@api_view(['GET'])
def get_oauth_code(request):
	code = request.query_params.get("code")
	access_token = exchange_code_for_token(code)
	return Response({"access_token":access_token})
	

def exchange_code_for_token(auth_code):
	data = {
		"client_secret": CLIENT_SECRET,
		"code": auth_code,
		"redirect_uri": redirect_uri,
		"client_id": CLIENT_ID,
		"grant_type": "authorization_code"
	}
	access_token_uri = SM_API_BASE + ACCESS_TOKEN_ENDPOINT
	access_token_response = requests.post(access_token_uri, data=data)
	access_json = access_token_response.json()

	if "access_token" in access_json:
		cache.set('access_token',access_json['access_token'],timeout=None)
		return access_json["access_token"]
	else:
		print(access_json)
		return None


@api_view(['GET','POST'])
@permission_classes([IsAuthenticated,IsAdminUser])
def surveys(request):
	url = "https://api.surveymonkey.com/v3/surveys"
	access_token = cache.get('access_token')
	headers = {
	    'accept': "application/json",
	    'Authorization': f"Bearer {access_token}",
		'Content-type':"application/json"
	    }
	if request.method=="GET":
		res = requests.get(url, headers=headers)
		return Response({"status":"success","data":res.json()})
	elif request.method=="POST":
		pdb.set_trace()
		survey_payload = request.data
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
		}

		collector_res = requests.post(url=url,json=collector_payload,headers=headers)
		colllector_id = collector_res.json().get("id")
		return Response({"status":"success","message":"your survey successfully created"},
				  status=status.HTTP_200_OK)

