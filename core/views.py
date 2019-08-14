from django.shortcuts import render

# Create your views here.
# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

import json
import requests
import base64
import binascii

from django.contrib.auth import authenticate, get_user_model
from django.middleware.csrf import CsrfViewMiddleware
from django.utils.six import text_type
from django.utils.translation import ugettext_lazy as _

from rest_framework import HTTP_HEADER_ENCODING, exceptions
from django.utils.six import text_type

ding_token = 'xxxxxxxxxxxxxxxxx'
api_url = "https://oapi.dingtalk.com/robot/send?access_token=" + ding_token


class Custom_TokenAuthentication(TokenAuthentication):
	def authenticate(self, request):
		auth = request.META.get('HTTP_TOKEN', b'')
		# if isinstance(auth, text_type):
		#    auth = auth.encode(HTTP_HEADER_ENCODING)
		auth = auth.split('_')

		if not auth or auth[0].lower() != bytes.decode(self.keyword.lower().encode()):
			return None

		if len(auth) == 1:
			msg = _('Invalid token header. No credentials provided.')
			raise exceptions.AuthenticationFailed(msg)
		elif len(auth) > 2:
			msg = _('Invalid token header. Token string should not contain spaces.')
			raise exceptions.AuthenticationFailed(msg)

		try:
			token = auth[1]
		except UnicodeError:
			msg = _('Invalid token header. Token string should not contain invalid characters.')
			raise exceptions.AuthenticationFailed(msg)

		return self.authenticate_credentials(token)


def msg(text, senderId, nickname):
	senders = senderId.split()
	text = '%s 您好！您发送的内容为%s' % (nickname, text)
	headers = {'Content-Type': 'application/json;charset=utf-8'}
	json_text = {
		"msgtype": "text",
		"text": {
			"content": text
		},
		"at": {
			"atDingtalkIds": senders,
			"isAtAll": False
		}
	}
	print(requests.post(api_url, json.dumps(json_text), headers=headers).content)


class HelloView(APIView):
	authentication_classes = (Custom_TokenAuthentication,)
	permission_classes = (IsAuthenticated,)

	def get(self, request):
		content = {'message': 'Hello, World!'}
		return Response(content)

	def post(self, request):
		data = request.data
		text = data['text']['content']
		senderId = data['senderId']
		nickname = data['senderNick']
		msg(text, senderId, nickname)
		return Response('ok')
