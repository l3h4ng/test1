# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from rest_framework import status
from django.http import HttpResponse
from rest_framework.renderers import JSONRenderer
from django.conf import settings


class JSONResponse(HttpResponse):
    """
    An HttpResponse that renders its content into JSON.
    """

    def __init__(self, data, **kwargs):
        content = JSONRenderer().render(data)
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)


def custom_exception_handler(exc, context):
    data_respone = {'status': 'error'}
    if hasattr(exc, 'detail'):
        data_respone['error'] = exc.detail
    try:
        data_respone['exception'] = str(exc)
    except Exception as ex:
        pass
    if hasattr(exc, 'status_code'):
        return JSONResponse(data_respone, status=exc.status_code)
    else:
        return JSONResponse(data_respone, status=status.HTTP_404_NOT_FOUND)


def custom400(request):
    return JSONResponse({'status': 'error', 'error': 'The bad request'},
                        status=status.HTTP_400_BAD_REQUEST)


def custom403(request):
    return JSONResponse({'status': 'error', 'error': 'You do not have permission to perform this action'},
                        status=status.HTTP_403_FORBIDDEN)


def custom404(request):
    return JSONResponse({'status': 'error', 'error': 'The resource was not found'},
                        status=status.HTTP_404_NOT_FOUND)


def custom500(request):
    return JSONResponse({'status': 'error', 'error': 'A server error occurred'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
