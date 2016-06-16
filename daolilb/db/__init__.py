from daolicontroller import utils

DEFAULT_DB_DRIVER = 'daolicontroller.db.etcd'

class DBase(object):
	def __init__(self, db_driver=None, **kwargs):
		if not db_driver:
			db_driver = DEFAULT_DB_DRIVER

		self.db = utils.import_object_ns(db_driver, 'DB', **kwargs)
