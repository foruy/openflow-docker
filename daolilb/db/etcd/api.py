import json
import etcd

from daolicontroller.db.api import BaseDriver
from daolicontroller.exceptions import KeyNotFound

class EtcdDriver(BaseDriver):
	def __init__(self, host='127.0.0.1', port=4001):
		self.client = etcd.Client(host=host, port=port)

	def write(self, key, val):
		self.client.write(k, val)

	def write_dir(self, key):
		self.client.write(k, None, dir=True)

	def read(self, key, dir=False):
		try:
			return self.client.read(key)
		except etcd.EtcdKeyNotFound:
			raise KeyNotFound(key=key)

	def delete(self, key):
		self.client.delete(key, recursive=True)

	def gateways(self):
		obj = self.read('/daolinet/gateways', dir=True)
		results = [json.loads(c.value) for c in obj.children]
		return dict([(r['DatapathID'],r) for r in results])

	def gateway(self, dpid):
		obj = self.read('/daolinet/gateways/%s' % dpid)
		return {dpid: json.loads(obj.value)}

        def services(self):
                obj = self.read('/daolinet/services', dir=True)
                return [json.loads(c.value) for c in obj.children]

	def service_get(self, port):
		obj = self.read('/daolinet/services/%s' % port)
		return json.loads(obj.value)
