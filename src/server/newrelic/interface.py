import zlib
import sys
import socket
import os
import types
import json
import logging

try:
    import http.client as httplib
except ImportError:
    import httplib

_logger = logging.getLogger(__name__)

# Python 3 compatibility helpers.

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY3:
    def b(s):
        return s.encode('latin-1')
else:
    def b(s):
        return s

# Helpers for json encoding and decoding.

def json_encode(obj, **kwargs):
    _kwargs = {}

    if type(b'') is type(''):
        _kwargs['encoding'] = 'latin-1'

    def _encode(o):
        if isinstance(o, bytes):
            return o.decode('latin-1')
        elif isinstance(o, types.GeneratorType):
            return list(o)
        elif hasattr(o, '__iter__'):
            return list(iter(o))
        raise TypeError(repr(o) + ' is not JSON serializable')

    _kwargs['default'] = _encode
    _kwargs['separators'] = (',', ':')

    _kwargs.update(kwargs)

    return json.dumps(obj, **_kwargs)

def json_decode(s, **kwargs):
    return json.loads(s, **kwargs)

# Platform plugin interface.

class Interface(object):

    class NetworkInterfaceException(Exception): pass
    class DiscardDataForRequest(NetworkInterfaceException): pass
    class RetryDataForRequest(NetworkInterfaceException): pass
    class ServerIsUnavailable(RetryDataForRequest): pass

    USER_AGENT = 'ModWsgi-PythonPlugin/%s (Python %s %s)' % (
             '1.0.0', sys.version.split()[0], sys.platform)

    HOST = 'platform-api.newrelic.com'
    URL = '/platform/v1/metrics'

    def __init__(self, license_key):
        self.license_key = license_key

    def send_request(self, payload=()):
        headers = {}
        config = {}

        license_key = self.license_key

        if not self.license_key:
            license_key = 'INVALID LICENSE KEY'

        headers['User-Agent'] = self.USER_AGENT
        headers['Content-Encoding'] = 'identity'
        headers['X-License-Key'] = license_key

        try:
            data = json_encode(payload)

        except Exception as exc:
            _logger.exception('Error encoding data for JSON payload '
                    'with payload of %r.', payload)

            raise Interface.DiscardDataForRequest(str(exc))

        if len(data) > 64*1024:
            headers['Content-Encoding'] = 'deflate'
            level = (len(data) < 2000000) and 1 or 9
            data = zlib.compress(b(data), level)

        try:
            connection = httplib.HTTPSConnection(self.HOST, timeout=30.0)
            connection.request('POST', self.URL, data, headers)
            response = connection.getresponse()
            content = response.read()

        except httplib.HTTPException as exc:
            raise Interface.RetryDataForRequest(str(exc))

        finally:
            connection.close()

        if response.status != 200:
            _logger.debug('Received a non 200 HTTP response from the data '
                    'collector where headers=%r, status=%r and content=%r.',
                    headers, response.status, content)

        if response.status == 400:
            if headers['Content-Encoding'] == 'deflate':
                data = zlib.decompress(data)

            _logger.error('Data collector is indicating that a bad '
                    'request has been submitted for headers of %r and '
                    'payload of %r with response of %r.', headers, data,
                    content)

            raise Interface.DiscardDataForRequest()

        elif response.status == 403:
            _logger.error('Data collector is indicating that the license '
                    'key %r is not valid.', license_key)

            raise Interface.DiscardDataForRequest()

        elif response.status == 413:
            _logger.warning('Data collector is indicating that a request '
                    'was received where the request content size was over '
                    'the maximum allowed size limit. The length of the '
                    'request content was %d.', len(data))

            raise Interface.DiscardDataForRequest()

        elif response.status in  (503, 504):
            _logger.warning('Data collector is unavailable.')

            raise Interface.ServerIsUnavailable()

        elif response.status != 200:
            _logger.warning('An unexpected HTTP response was received '
                    'from the data collector of %r. The payload for '
                    'the request was %r.', respnse.status, payload)

            raise Interface.DiscardDataForRequest()

        try:
            if PY3:
                content = content.decode('UTF-8')

            result = json_decode(content)

        except Exception as exc:
            _logger.exception('Error decoding data for JSON payload '
                    'with payload of %r.', content)

            raise Interface.DiscardDataForRequest(str(exc))

        if 'status' in result:
            return result['status']

        error_message = result['error']

        raise Interface.DiscardDataForRequest(error_message)

    def send_metrics(self, name, guid, version, duration, metrics):
        agent = {}
        agent['host'] = socket.gethostname()
        agent['pid'] = os.getpid()
        agent['version'] = version or '0.0.0.'

        component = {}
        component['name'] = name
        component['guid'] = guid
        component['duration'] = duration
        component['metrics'] = metrics

        payload = {}
        payload['agent'] = agent
        payload['components'] = [component]

        return self.send_request(payload)
