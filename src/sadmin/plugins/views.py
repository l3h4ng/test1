# Create your views here.
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework.renderers import JSONRenderer

from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticated, IsOneUserScanner
from sadmin.plugins.models import PluginsModel
from sadmin.plugins.serializers import PluginSerializers, PluginsLicenseSerializerInfo


# Create your views here.



# # Plugin Group
# class PluginsGrouspList(generics.ListCreateAPIView):
#     queryset = PluginsGroupModel.objects.all()
#     serializer_class = PluginsGroupSerializerInfo
#     authentication_classes = (OneTokenAuthentication,)
#     permission_classes = (IsOneUserAuthenticated,)
#     renderer_classes = (JSONRenderer,)
#     filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
#
#
# class PluginsGroupDetails(generics.RetrieveUpdateDestroyAPIView):
#     queryset = PluginsGroupModel.objects.all()
#     serializer_class = PluginsGroupSerializerInfo
#     authentication_classes = (OneTokenAuthentication,)
#     permission_classes = (IsOneUserAuthenticated,)
#     renderer_classes = (JSONRenderer,)
#     filter_backends = (filters.SearchFilter, DjangoFilterBackend,)

class PluginsList(generics.ListCreateAPIView):
    queryset = PluginsModel.objects.all()
    serializer_class = PluginSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'enabled', 'required',)


class PluginDetails(generics.RetrieveUpdateDestroyAPIView):
    queryset = PluginsModel.objects.all()
    serializer_class = PluginSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)

# Plugin License
class PluginLicensesList(generics.ListCreateAPIView):
    serializer_class = PluginsLicenseSerializerInfo
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('plugin', 'name', 'activated')


class PluginLicenseDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PluginsLicenseSerializerInfo
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserScanner,)
    renderer_classes = (JSONRenderer,)
