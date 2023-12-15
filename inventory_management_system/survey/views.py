from django.shortcuts import render , redirect
from rest_framework.decorators import api_view
from urllib.parse import urlencode,urlsplit,parse_qs
from rest_framework.response import Response
import pdb
import requests
import json
from decouple import config


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
		return access_json["access_token"]
	else:
		print(access_json)
		return None
