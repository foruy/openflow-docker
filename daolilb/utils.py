import netaddr
import random
import socket
import sys
import traceback

import six.moves.urllib.parse as urlparse

def gethostname():
    return socket.gethostname()

def get_shortened_ipv6(address):
    addr = netaddr.IPAddress(address, version=6)
    return str(addr.ipv6())

def get_long_ip(address):
    return netaddr.IPAddress(address).value

def replace_url(url, host=None, port=None, path=None):
    o = urlparse.urlparse(url)
    _host = o.hostname
    _port = o.port
    _path = o.path

    if host is not None:
        _host = host

    if port is not None:
        _port = port

    netloc = _host

    if _port is not None:
        netloc = ':'.join([netloc, str(_port)])

    if path is not None:
        _path = path

    return '%s://%s%s' % (o.scheme, netloc, _path)

def generate_seq():
    return random.randint(1000000000, 4294967296)

def import_class(import_str):
	"""Returns a class from a string including module and class."""
	mod_str, _sep, class_str = import_str.rpartition('.')

	__import__(mod_str)
	try:
		return getattr(sys.modules[mod_str], class_str)
	except AttributeError:
		raise ImportError('Class %s cannot be found (%s)' %
				  (class_str,
				   traceback.format_exception(*sys.exc_info())))

def import_object_ns(name_space, import_str, *args, **kwargs):
	"""Tries to import object from default namespace."""
	import_value = "%s.%s" % (name_space, import_str)
	try:
		return import_class(import_value)(*args, **kwargs)
	except ImportError:
		return import_class(import_str)(*args, **kwargs)
