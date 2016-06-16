"""Base class of database driver."""

class BaseDriver(object):

	def write(self, key, val):
		raise NotImplementedError()

	def read(self):
		raise NotImplementedError()

	def delete(self):
		raise NotImplementedError()
