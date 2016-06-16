
class OPFException(Exception):
    message = "An unknown exception occurred."

    def __init__(self, msg=None, **kwargs):
        self.kwargs = kwargs

        if not msg:
            msg = self.message

            try:
                msg = msg % kwargs
            except Exception:
                # at least get the core message out if something happened
                msg = self.message

        super(OPFException, self).__init__(msg)

    def format_message(self):
        return self.args[0]

class DevicePortNotFound(OPFException):
    message = 'no such network device %(device)s'

class KeyNotFound(OPFException):
    message = 'Key not found: %(key)s'

class IPAddressNotMatch(OPFException):
    message = 'IP address %(address)s do not match'

class NotFound(OPFException):
    message = "Resource could not be found."

class ContainerNotFound(NotFound):
    message = "Container %(container)s could not be found."

class FixedIpNotFound(NotFound):
    message = "No fixed IP associated with id %(id)s."

class FixedIpNotFoundForInstance(FixedIpNotFound):
    message = "Instance %(instance_uuid)s has zero fixed ips."

class Invalid(OPFException):
    message = "Unacceptable parameters."

class InvalidUUID(Invalid):
    message = "Expected a uuid but received %(uuid)s."

class InvalidIpAddressError(Invalid):
    message = "%(address)s is not a valid IP v4/6 address."
