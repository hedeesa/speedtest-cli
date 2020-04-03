#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2012 Matt Martz
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import re
import csv
import sys
import math
import errno
import signal
import socket
import timeit
import datetime
import platform
import threading
import xml.parsers.expat

try:
    import gzip
    GZIP_BASE = gzip.GzipFile
except ImportError:
    gzip = None
    GZIP_BASE = object

__version__ = '2.1.2'


class FakeShutdownEvent(object):
    """Class to fake a threading.Event.isSet so that users of this module
    are not required to register their own threading.Event()
    """

    @staticmethod
    def isSet():
        "Dummy method to always return false"""
        return False


# Some global variables we use
DEBUG = False
_GLOBAL_DEFAULT_TIMEOUT = object()
PY25PLUS = sys.version_info[:2] >= (2, 5)
PY26PLUS = sys.version_info[:2] >= (2, 6)
PY32PLUS = sys.version_info[:2] >= (3, 2)

# Begin import game to handle Python 2 and Python 3
try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        json = None

try:
    import xml.etree.ElementTree as ET
    try:
        from xml.etree.ElementTree import _Element as ET_Element
    except ImportError:
        pass
except ImportError:
    from xml.dom import minidom as DOM
    from xml.parsers.expat import ExpatError
    ET = None

try:
    from urllib2 import (urlopen, Request, HTTPError, URLError,
                         AbstractHTTPHandler, ProxyHandler,
                         HTTPDefaultErrorHandler, HTTPRedirectHandler,
                         HTTPErrorProcessor, OpenerDirector)
except ImportError:
    from urllib.request import (urlopen, Request, HTTPError, URLError,
                                AbstractHTTPHandler, ProxyHandler,
                                HTTPDefaultErrorHandler, HTTPRedirectHandler,
                                HTTPErrorProcessor, OpenerDirector)

try:
    from httplib import HTTPConnection, BadStatusLine
except ImportError:
    from http.client import HTTPConnection, BadStatusLine

try:
    from httplib import HTTPSConnection
except ImportError:
    try:
        from http.client import HTTPSConnection
    except ImportError:
        HTTPSConnection = None

try:
    from httplib import FakeSocket
except ImportError:
    FakeSocket = None

try:
    from Queue import Queue
except ImportError:
    from queue import Queue

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

try:
    from urlparse import parse_qs
except ImportError:
    try:
        from urllib.parse import parse_qs
    except ImportError:
        from cgi import parse_qs

try:
    from hashlib import md5
except ImportError:
    from md5 import md5

try:
    from argparse import ArgumentParser as ArgParser
    from argparse import SUPPRESS as ARG_SUPPRESS
    PARSER_TYPE_INT = int
    PARSER_TYPE_STR = str
    PARSER_TYPE_FLOAT = float
except ImportError:
    from optparse import OptionParser as ArgParser
    from optparse import SUPPRESS_HELP as ARG_SUPPRESS
    PARSER_TYPE_INT = 'int'
    PARSER_TYPE_STR = 'string'
    PARSER_TYPE_FLOAT = 'float'

try:
    from cStringIO import StringIO
    BytesIO = None
except ImportError:
    try:
        from StringIO import StringIO
        BytesIO = None
    except ImportError:
        from io import StringIO, BytesIO

try:
    import __builtin__
except ImportError:
    import builtins
    from io import TextIOWrapper, FileIO

    class _Py3Utf8Output(TextIOWrapper):
        """UTF-8 encoded wrapper around stdout for py3, to override
        ASCII stdout
        """
        def __init__(self, f, **kwargs):
            buf = FileIO(f.fileno(), 'w')
            super(_Py3Utf8Output, self).__init__(
                buf,
                encoding='utf8',
                errors='strict'
            )

        def write(self, s):
            super(_Py3Utf8Output, self).write(s)
            self.flush()

    _py3_print = getattr(builtins, 'print')
    try:
        _py3_utf8_stdout = _Py3Utf8Output(sys.stdout)
        _py3_utf8_stderr = _Py3Utf8Output(sys.stderr)
    except OSError:
        # sys.stdout/sys.stderr is not a compatible stdout/stderr object
        # just use it and hope things go ok
        _py3_utf8_stdout = sys.stdout
        _py3_utf8_stderr = sys.stderr

    def to_utf8(v):
        """No-op encode to utf-8 for py3"""
        return v

    def print_(*args, **kwargs):
        """Wrapper function for py3 to print, with a utf-8 encoded stdout"""
        if kwargs.get('file') == sys.stderr:
            kwargs['file'] = _py3_utf8_stderr
        else:
            kwargs['file'] = kwargs.get('file', _py3_utf8_stdout)
        _py3_print(*args, **kwargs)
else:
    del __builtin__

    def to_utf8(v):
        """Encode value to utf-8 if possible for py2"""
        try:
            return v.encode('utf8', 'strict')
        except AttributeError:
            return v

    def print_(*args, **kwargs):
        """The new-style print function for Python 2.4 and 2.5.

        Taken from https://pypi.python.org/pypi/six/

        Modified to set encoding to UTF-8 always, and to flush after write
        """
        fp = kwargs.pop("file", sys.stdout)
        if fp is None:
            return

        def write(data):
            if not isinstance(data, basestring):
                data = str(data)
            # If the file has an encoding, encode unicode with it.
            encoding = 'utf8'  # Always trust UTF-8 for output
            if (isinstance(fp, file) and
                    isinstance(data, unicode) and
                    encoding is not None):
                errors = getattr(fp, "errors", None)
                if errors is None:
                    errors = "strict"
                data = data.encode(encoding, errors)
            fp.write(data)
            fp.flush()
        want_unicode = False
        sep = kwargs.pop("sep", None)
        if sep is not None:
            if isinstance(sep, unicode):
                want_unicode = True
            elif not isinstance(sep, str):
                raise TypeError("sep must be None or a string")
        end = kwargs.pop("end", None)
        if end is not None:
            if isinstance(end, unicode):
                want_unicode = True
            elif not isinstance(end, str):
                raise TypeError("end must be None or a string")
        if kwargs:
            raise TypeError("invalid keyword arguments to print()")
        if not want_unicode:
            for arg in args:
                if isinstance(arg, unicode):
                    want_unicode = True
                    break
        if want_unicode:
            newline = unicode("\n")
            space = unicode(" ")
        else:
            newline = "\n"
            space = " "
        if sep is None:
            sep = space
        if end is None:
            end = newline
        for i, arg in enumerate(args):
            if i:
                write(sep)
            write(arg)
        write(end)

if PY32PLUS:
    etree_iter = ET.Element.iter
elif PY25PLUS:
    etree_iter = ET_Element.getiterator

if PY26PLUS:
    thread_is_alive = threading.Thread.is_alive
else:
    thread_is_alive = threading.Thread.isAlive


# Exception "constants" to support Python 2 through Python 3
try:
    import ssl
    try:
        CERT_ERROR = (ssl.CertificateError,)
    except AttributeError:
        CERT_ERROR = tuple()

    HTTP_ERRORS = (
        (HTTPError, URLError, socket.error, ssl.SSLError, BadStatusLine) +
        CERT_ERROR
    )
except ImportError:
    ssl = None
    HTTP_ERRORS = (HTTPError, URLError, socket.error, BadStatusLine)


class SpeedtestException(Exception):
    """Base exception for this module"""


class SpeedtestCLIError(SpeedtestException):
    """Generic exception for raising errors during CLI operation"""


class SpeedtestHTTPError(SpeedtestException):
    """Base HTTP exception for this module"""


class SpeedtestConfigError(SpeedtestException):
    """Configuration XML is invalid"""


class SpeedtestServersError(SpeedtestException):
    """Servers XML is invalid"""


class ConfigRetrievalError(SpeedtestHTTPError):
    """Could not retrieve config.php"""


class ServersRetrievalError(SpeedtestHTTPError):
    """Could not retrieve speedtest-servers.php"""


class InvalidServerIDType(SpeedtestException):
    """Server ID used for filtering was not an integer"""


class NoMatchedServers(SpeedtestException):
    """No servers matched when filtering"""


class SpeedtestMiniConnectFailure(SpeedtestException):
    """Could not connect to the provided speedtest mini server"""


class InvalidSpeedtestMiniServer(SpeedtestException):
    """Server provided as a speedtest mini server does not actually appear
    to be a speedtest mini server
    """


class ShareResultsConnectFailure(SpeedtestException):
    """Could not connect to speedtest.net API to POST results"""


class ShareResultsSubmitFailure(SpeedtestException):
    """Unable to successfully POST results to speedtest.net API after
    connection
    """


class SpeedtestUploadTimeout(SpeedtestException):
    """testlength configuration reached during upload
    Used to ensure the upload halts when no additional data should be sent
    """


class SpeedtestBestServerFailure(SpeedtestException):
    """Unable to determine best server"""


class SpeedtestMissingBestServer(SpeedtestException):
    """get_best_server not called or not able to determine best server"""


def create_connection(address, timeout=_GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    An host of '' or port 0 tells the OS to use the default.

    Largely vendored from Python 2.7, modified to work with Python 2.4
    """

    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not _GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(float(timeout))
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock

        except socket.error:
            err = get_exception()
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


class SpeedtestHTTPConnection(HTTPConnection):
    """Custom HTTPConnection to support source_address across
    Python 2.4 - Python 3
    """
    def __init__(self, *args, **kwargs):
        source_address = kwargs.pop('source_address', None)
        timeout = kwargs.pop('timeout', 10)

        self._tunnel_host = None

        HTTPConnection.__init__(self, *args, **kwargs)

        self.source_address = source_address
        self.timeout = timeout

    def connect(self):
        """Connect to the host and port specified in __init__."""
        try:
            self.sock = socket.create_connection(
                (self.host, self.port),
                self.timeout,
                self.source_address
            )
        except (AttributeError, TypeError):
            self.sock = create_connection(
                (self.host, self.port),
                self.timeout,
                self.source_address
            )

        if self._tunnel_host:
            self._tunnel()


if HTTPSConnection:
    class SpeedtestHTTPSConnection(HTTPSConnection):
        """Custom HTTPSConnection to support source_address across
        Python 2.4 - Python 3
        """
        default_port = 443

        def __init__(self, *args, **kwargs):
            source_address = kwargs.pop('source_address', None)
            timeout = kwargs.pop('timeout', 10)

            self._tunnel_host = None

            HTTPSConnection.__init__(self, *args, **kwargs)

            self.timeout = timeout
            self.source_address = source_address

        def connect(self):
            "Connect to a host on a given (SSL) port."
            try:
                self.sock = socket.create_connection(
                    (self.host, self.port),
                    self.timeout,
                    self.source_address
                )
            except (AttributeError, TypeError):
                self.sock = create_connection(
                    (self.host, self.port),
                    self.timeout,
                    self.source_address
                )

            if self._tunnel_host:
                self._tunnel()

            if ssl:
                try:
                    kwargs = {}
                    if hasattr(ssl, 'SSLContext'):
                        if self._tunnel_host:
                            kwargs['server_hostname'] = self._tunnel_host
                        else:
                            kwargs['server_hostname'] = self.host
                    self.sock = self._context.wrap_socket(self.sock, **kwargs)
                except AttributeError:
                    self.sock = ssl.wrap_socket(self.sock)
                    try:
                        self.sock.server_hostname = self.host
                    except AttributeError:
                        pass
            elif FakeSocket:
                # Python 2.4/2.5 support
                try:
                    self.sock = FakeSocket(self.sock, socket.ssl(self.sock))
                except AttributeError:
                    raise SpeedtestException(
                        'This version of Python does not support HTTPS/SSL '
                        'functionality'
                    )
            else:
                raise SpeedtestException(
                    'This version of Python does not support HTTPS/SSL '
                    'functionality'
                )


def _build_connection(connection, source_address, timeout, context=None):
    """Cross Python 2.4 - Python 3 callable to build an ``HTTPConnection`` or
    ``HTTPSConnection`` with the args we need

    Called from ``http(s)_open`` methods of ``SpeedtestHTTPHandler`` or
    ``SpeedtestHTTPSHandler``
    """
    def inner(host, **kwargs):
        kwargs.update({
            'source_address': source_address,
            'timeout': timeout
        })
        if context:
            kwargs['context'] = context
        return connection(host, **kwargs)
    return inner


class SpeedtestHTTPHandler(AbstractHTTPHandler):
    """Custom ``HTTPHandler`` that can build a ``HTTPConnection`` with the
    args we need for ``source_address`` and ``timeout``
    """
    def __init__(self, debuglevel=0, source_address=None, timeout=10):
        AbstractHTTPHandler.__init__(self, debuglevel)
        self.source_address = source_address
        self.timeout = timeout

    def http_open(self, req):
        return self.do_open(
            _build_connection(
                SpeedtestHTTPConnection,
                self.source_address,
                self.timeout
            ),
            req
        )

    http_request = AbstractHTTPHandler.do_request_


class SpeedtestHTTPSHandler(AbstractHTTPHandler):
    """Custom ``HTTPSHandler`` that can build a ``HTTPSConnection`` with the
    args we need for ``source_address`` and ``timeout``
    """
    def __init__(self, debuglevel=0, context=None, source_address=None,
                 timeout=10):
        AbstractHTTPHandler.__init__(self, debuglevel)
        self._context = context
        self.source_address = source_address
        self.timeout = timeout

    def https_open(self, req):
        return self.do_open(
            _build_connection(
                SpeedtestHTTPSConnection,
                self.source_address,
                self.timeout,
                context=self._context,
            ),
            req
        )

    https_request = AbstractHTTPHandler.do_request_


def build_opener(source_address=None, timeout=10):
    """Function similar to ``urllib2.build_opener`` that will build
    an ``OpenerDirector`` with the explicit handlers we want,
    ``source_address`` for binding, ``timeout`` and our custom
    `User-Agent`
    """

    printer('Timeout set to %d' % timeout, debug=True)

    if source_address:
        source_address_tuple = (source_address, 0)
        printer('Binding to source address: %r' % (source_address_tuple,),
                debug=True)
    else:
        source_address_tuple = None

    handlers = [
        ProxyHandler(),
        SpeedtestHTTPHandler(source_address=source_address_tuple,
                             timeout=timeout),
        SpeedtestHTTPSHandler(source_address=source_address_tuple,
                              timeout=timeout),
        HTTPDefaultErrorHandler(),
        HTTPRedirectHandler(),
        HTTPErrorProcessor()
    ]

    opener = OpenerDirector()
    opener.addheaders = [('User-agent', build_user_agent())]

    for handler in handlers:
        opener.add_handler(handler)

    return opener


class GzipDecodedResponse(GZIP_BASE):
    """A file-like object to decode a response encoded with the gzip
    method, as described in RFC 1952.

    Largely copied from ``xmlrpclib``/``xmlrpc.client`` and modified
    to work for py2.4-py3
    """
    def __init__(self, response):
        # response doesn't support tell() and read(), required by
        # GzipFile
        if not gzip:
            raise SpeedtestHTTPError('HTTP response body is gzip encoded, '
                                     'but gzip support is not available')
        IO = BytesIO or StringIO
        self.io = IO()
        while 1:
            chunk = response.read(1024)
            if len(chunk) == 0:
                break
            self.io.write(chunk)
        self.io.seek(0)
        gzip.GzipFile.__init__(self, mode='rb', fileobj=self.io)

    def close(self):
        try:
            gzip.GzipFile.close(self)
        finally:
            self.io.close()


def get_exception():
    """Helper function to work with py2.4-py3 for getting the current
    exception in a try/except block
    """
    return sys.exc_info()[1]


def distance(origin, destination):
    """Determine distance between 2 sets of [lat,lon] in km"""

    lat1, lon1 = origin
    lat2, lon2 = destination
    radius = 6371  # km

    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) * math.sin(dlat / 2) +
         math.cos(math.radians(lat1)) *
         math.cos(math.radians(lat2)) * math.sin(dlon / 2) *
         math.sin(dlon / 2))
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    d = radius * c

    return d


def build_user_agent():
    """Build a Mozilla/5.0 compatible User-Agent string"""

    ua_tuple = (
        'Mozilla/5.0',
        '(%s; U; %s; en-us)' % (platform.platform(),
                                platform.architecture()[0]),
        'Python/%s' % platform.python_version(),
        '(KHTML, like Gecko)',
        'speedtest-cli/%s' % __version__
    )
    user_agent = ' '.join(ua_tuple)
    printer('User-Agent: %s' % user_agent, debug=True)
    return user_agent


def build_request(url, data=None, headers=None, bump='0', secure=False):
    """Build a urllib2 request object

    This function automatically adds a User-Agent header to all requests

    """

    if not headers:
        headers = {}

    if url[0] == ':':
        scheme = ('http', 'https')[bool(secure)]
        schemed_url = '%s%s' % (scheme, url)
    else:
        schemed_url = url

    if '?' in url:
        delim = '&'
    else:
        delim = '?'

    # WHO YOU GONNA CALL? CACHE BUSTERS!
    final_url = '%s%sx=%s.%s' % (schemed_url, delim,
                                 int(timeit.time.time() * 1000),
                                 bump)

    headers.update({
        'Cache-Control': 'no-cache',
    })

    printer('%s %s' % (('GET', 'POST')[bool(data)], final_url),
            debug=True)

    return Request(final_url, data=data, headers=headers)


def catch_request(request, opener=None):
    """Helper function to catch common exceptions encountered when
    establishing a connection with a HTTP/HTTPS request

    """

    if opener:
        _open = opener.open
    else:
        _open = urlopen

    try:
        uh = _open(request)
        if request.get_full_url() != uh.geturl():
            printer('Redirected to %s' % uh.geturl(), debug=True)
        return uh, False
    except HTTP_ERRORS:
        e = get_exception()
        return None, e


def get_response_stream(response):
    """Helper function to return either a Gzip reader if
    ``Content-Encoding`` is ``gzip`` otherwise the response itself

    """

    try:
        getheader = response.headers.getheader
    except AttributeError:
        getheader = response.getheader

    if getheader('content-encoding') == 'gzip':
        return GzipDecodedResponse(response)

    return response


def get_attributes_by_tag_name(dom, tag_name):
    """Retrieve an attribute from an XML document and return it in a
    consistent format

    Only used with xml.dom.minidom, which is likely only to be used
    with python versions older than 2.5
    """
    elem = dom.getElementsByTagName(tag_name)[0]
    return dict(list(elem.attributes.items()))


def print_dots(shutdown_event):
    """Built in callback function used by Thread classes for printing
    status
    """
    def inner(current, total, start=False, end=False):
        if shutdown_event.isSet():
            return

        sys.stdout.write('.')
        if current + 1 == total and end is True:
            sys.stdout.write('\n')
        sys.stdout.flush()
    return inner


def do_nothing(*args, **kwargs):
    pass


class HTTPDownloader(threading.Thread):
    """Thread class for retrieving a URL"""

    def __init__(self, i, request, start, timeout, opener=None,
                 shutdown_event=None):
        threading.Thread.__init__(self)
        self.request = request
        self.result = [0]
        self.starttime = start
        self.timeout = timeout
        self.i = i
        if opener:
            self._opener = opener.open
        else:
            self._opener = urlopen

        if shutdown_event:
            self._shutdown_event = shutdown_event
        else:
            self._shutdown_event = FakeShutdownEvent()

    def run(self):
        try:
            if (timeit.default_timer() - self.starttime) <= self.timeout:
                f = self._opener(self.request)
                while (not self._shutdown_event.isSet() and
                        (timeit.default_timer() - self.starttime) <=
                        self.timeout):
                    self.result.append(len(f.read(10240)))
                    if self.result[-1] == 0:
                        break
                f.close()
        except IOError:
            pass


class HTTPUploaderData(object):
    """File like object to improve cutting off the upload once the timeout
    has been reached
    """

    def __init__(self, length, start, timeout, shutdown_event=None):
        self.length = length
        self.start = start
        self.timeout = timeout

        if shutdown_event:
            self._shutdown_event = shutdown_event
        else:
            self._shutdown_event = FakeShutdownEvent()

        self._data = None

        self.total = [0]

    def pre_allocate(self):
        chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        multiplier = int(round(int(self.length) / 36.0))
        IO = BytesIO or StringIO
        try:
            self._data = IO(
                ('content1=%s' %
                 (chars * multiplier)[0:int(self.length) - 9]
                 ).encode()
            )
        except MemoryError:
            raise SpeedtestCLIError(
                'Insufficient memory to pre-allocate upload data. Please '
                'use --no-pre-allocate'
            )

    @property
    def data(self):
        if not self._data:
            self.pre_allocate()
        return self._data

    def read(self, n=10240):
        if ((timeit.default_timer() - self.start) <= self.timeout and
                not self._shutdown_event.isSet()):
            chunk = self.data.read(n)
            self.total.append(len(chunk))
            return chunk
        else:
            raise SpeedtestUploadTimeout()

    def __len__(self):
        return self.length


class HTTPUploader(threading.Thread):
    """Thread class for putting a URL"""

    def __init__(self, i, request, start, size, timeout, opener=None,
                 shutdown_event=None):
        threading.Thread.__init__(self)
        self.request = request
        self.request.data.start = self.starttime = start
        self.size = size
        self.result = None
        self.timeout = timeout
        self.i = i

        if opener:
            self._opener = opener.open
        else:
            self._opener = urlopen

        if shutdown_event:
            self._shutdown_event = shutdown_event
        else:
            self._shutdown_event = FakeShutdownEvent()

    def run(self):
        request = self.request
        try:
            if ((timeit.default_timer() - self.starttime) <= self.timeout and
                    not self._shutdown_event.isSet()):
                try:
                    f = self._opener(request)
                except TypeError:
                    # PY24 expects a string or buffer
                    # This also causes issues with Ctrl-C, but we will concede
                    # for the moment that Ctrl-C on PY24 isn't immediate
                    request = build_request(self.request.get_full_url(),
                                            data=request.data.read(self.size))
                    f = self._opener(request)
                f.read(11)
                f.close()
                self.result = sum(self.request.data.total)
            else:
                self.result = 0
        except (IOError, SpeedtestUploadTimeout):
            self.result = sum(self.request.data.total)


class SpeedtestResults(object):
    """Class for holding the results of a speedtest, including:

    Download speed
    Upload speed
    Ping/Latency to test server
    Data about server that the test was run against

    Additionally this class can return a result data as a dictionary or CSV,
    as well as submit a POST of the result data to the speedtest.net API
    to get a share results image link.
    """

    def __init__(self, download=0, upload=0, ping=0, server=None, client=None,
                 opener=None, secure=False):
        self.download = download
        self.upload = upload
        self.ping = ping
        if server is None:
            self.server = {}
        else:
            self.server = server
        self.client = client or {}

        self._share = None
        self.timestamp = '%sZ' % datetime.datetime.utcnow().isoformat()
        self.bytes_received = 0
        self.bytes_sent = 0

        if opener:
            self._opener = opener
        else:
            self._opener = build_opener()

        self._secure = secure

    def __repr__(self):
        return repr(self.dict())

    def share(self):
        """POST data to the speedtest.net API to obtain a share results
        link
        """

        if self._share:
            return self._share

        download = int(round(self.download / 1000.0, 0))
        ping = int(round(self.ping, 0))
        upload = int(round(self.upload / 1000.0, 0))

        # Build the request to send results back to speedtest.net
        # We use a list instead of a dict because the API expects parameters
        # in a certain order
        api_data = [
            'recommendedserverid=%s' % self.server['id'],
            'ping=%s' % ping,
            'screenresolution=',
            'promo=',
            'download=%s' % download,
            'screendpi=',
            'upload=%s' % upload,
            'testmethod=http',
            'hash=%s' % md5(('%s-%s-%s-%s' %
                             (ping, upload, download, '297aae72'))
                            .encode()).hexdigest(),
            'touchscreen=none',
            'startmode=pingselect',
            'accuracy=1',
            'bytesreceived=%s' % self.bytes_received,
            'bytessent=%s' % self.bytes_sent,
            'serverid=%s' % self.server['id'],
        ]

        headers = {'Referer': 'http://c.speedtest.net/flash/speedtest.swf'}
        request = build_request('://www.speedtest.net/api/api.php',
                                data='&'.join(api_data).encode(),
                                headers=headers, secure=self._secure)
        f, e = catch_request(request, opener=self._opener)
        if e:
            raise ShareResultsConnectFailure(e)

        response = f.read()
        code = f.code
        f.close()

        if int(code) != 200:
            raise ShareResultsSubmitFailure('Could not submit results to '
                                            'speedtest.net')

        qsargs = parse_qs(response.decode())
        resultid = qsargs.get('resultid')
        if not resultid or len(resultid) != 1:
            raise ShareResultsSubmitFailure('Could not submit results to '
                                            'speedtest.net')

        self._share = 'http://www.speedtest.net/result/%s.png' % resultid[0]

        return self._share

    def dict(self):
        """Return dictionary of result data"""

        return {
            'download': self.download,
            'upload': self.upload,
            'ping': self.ping,
            'server': self.server,
            'timestamp': self.timestamp,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'share': self._share,
            'client': self.client,
        }

    @staticmethod
    def csv_header(delimiter=','):
        """Return CSV Headers"""

        row = ['Server ID', 'Sponsor', 'Server Name', 'Timestamp', 'Distance',
               'Ping', 'Download', 'Upload', 'Share', 'IP Address']
        out = StringIO()
        writer = csv.writer(out, delimiter=delimiter, lineterminator='')
        writer.writerow([to_utf8(v) for v in row])
        return out.getvalue()

    def csv(self, delimiter=','):
        """Return data in CSV format"""

        data = self.dict()
        out = StringIO()
        writer = csv.writer(out, delimiter=delimiter, lineterminator='')
        row = [data['server']['id'], data['server']['sponsor'],
               data['server']['name'], data['timestamp'],
               data['server']['d'], data['ping'], data['download'],
               data['upload'], self._share or '', self.client['ip']]
        writer.writerow([to_utf8(v) for v in row])
        return out.getvalue()

    def json(self, pretty=False):
        """Return data in JSON format"""

        kwargs = {}
        if pretty:
            kwargs.update({
                'indent': 4,
                'sort_keys': True
            })
        return json.dumps(self.dict(), **kwargs)


class Speedtest(object):
    """Class for performing standard speedtest.net testing operations"""

    def __init__(self, config=None, source_address=None, timeout=10,
                 secure=False, shutdown_event=None):
        self.config = {}

        self._source_address = source_address
        self._timeout = timeout
        self._opener = build_opener(source_address, timeout)

        self._secure = secure

        if shutdown_event:
            self._shutdown_event = shutdown_event
        else:
            self._shutdown_event = FakeShutdownEvent()

        self.get_config()
        if config is not None:
            self.config.update(config)

        self.servers = {}
        self.closest = []
        self._best = {}

        self.results = SpeedtestResults(
            client=self.config['client'],
            opener=self._opener,
            secure=secure,
        )

    @property
    def best(self):
        if not self._best:
            self.get_best_server()
        return self._best

    def get_config(self):
        """Download the speedtest.net configuration and return only the data
        we are interested in
        """

        headers = {}
        if gzip:
            headers['Accept-Encoding'] = 'gzip'
        request = build_request('://www.speedtest.net/speedtest-config.php',
                                headers=headers, secure=self._secure)
        uh, e = catch_request(request, opener=self._opener)
        if e:
            raise ConfigRetrievalError(e)
        configxml_list = []

        stream = get_response_stream(uh)

        while 1:
            try:
                configxml_list.append(stream.read(1024))
            except (OSError, EOFError):
                raise ConfigRetrievalError(get_exception())
            if len(configxml_list[-1]) == 0:
                break
        stream.close()
        uh.close()

        if int(uh.code) != 200:
            return None

        configxml = ''.encode().join(configxml_list)

        printer('Config XML:\n%s' % configxml, debug=True)

        try:
            try:
                root = ET.fromstring(configxml)
            except ET.ParseError:
                e = get_exception()
                raise SpeedtestConfigError(
                    'Malformed speedtest.net configuration: %s' % e
                )
            server_config = root.find('server-config').attrib
            download = root.find('download').attrib
            upload = root.find('upload').attrib
            # times = root.find('times').attrib
            client = root.find('client').attrib

        except AttributeError:
            try:
                root = DOM.parseString(configxml)
            except ExpatError:
                e = get_exception()
                raise SpeedtestConfigError(
                    'Malformed speedtest.net configuration: %s' % e
                )
            server_config = get_attributes_by_tag_name(root, 'server-config')
            download = get_attributes_by_tag_name(root, 'download')
            upload = get_attributes_by_tag_name(root, 'upload')
            # times = get_attributes_by_tag_name(root, 'times')
            client = get_attributes_by_tag_name(root, 'client')

        ignore_servers = list(
            map(int, server_config['ignoreids'].split(','))
        )

        ratio = int(upload['ratio'])
        upload_max = int(upload['maxchunkcount'])
        up_sizes = [32768, 65536, 131072, 262144, 524288, 1048576, 7340032]
        sizes = {
            'upload': up_sizes[ratio - 1:],
            ## download just 2 files
            'download': [350, 1500]
        }

        size_count = len(sizes['upload'])

        upload_count = int(math.ceil(upload_max / size_count))

        counts = {
            'upload': upload_count,
            ## download each file once
            'download': int(1)
        }

        threads = {
            'upload': int(upload['threads']),
            'download': int(server_config['threadcount']) * 2
        }

        length = {
            'upload': int(upload['testlength']),
            'download': int(download['testlength'])
        }

        self.config.update({
            'client': client,
            'ignore_servers': ignore_servers,
            'sizes': sizes,
            'counts': counts,
            'threads': threads,
            'length': length,
            'upload_max': upload_count * size_count
        })

        try:
            self.lat_lon = (float(client['lat']), float(client['lon']))
        except ValueError:
            raise SpeedtestConfigError(
                'Unknown location: lat=%r lon=%r' %
                (client.get('lat'), client.get('lon'))
            )

        printer('Config:\n%r' % self.config, debug=True)

        return self.config

    def get_servers(self, servers=None, exclude=None):
        #FR and NL
        self.servers={3969.3221224270524: [{'url': 'http://speedtest.duocast.net:8080/speedtest/upload.php', 'lat': '53.2194', 'lon': '6.5665', 'name': 'Groningen', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Duocast BV', 'id': '14904', 'host': 'speedtest.duocast.net:8080', 'd': 3969.3221224270524}], 3969.2945737470313: [{'url': 'http://speedtest.cj2.nl:8080/speedtest/upload.php', 'lat': '53.2178', 'lon': '6.5664', 'name': 'Groningen', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'CJ2 Hosting B.V.', 'id': '3200', 'host': 'speedtest.cj2.nl:8080', 'd': 3969.2945737470313}, {'url': 'http://speedtest1.osso.network:8080/speedtest/upload.php', 'lat': '53.2178', 'lon': '6.5664', 'name': 'Groningen', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'OSSO Network BV', 'id': '6247', 'url2': 'http://speedtest1.osso.nl/speedtest/upload.php', 'host': 'speedtest1.osso.network:8080', 'd': 3969.2945737470313}], 3970.342910714104: [{'url': 'http://speedtest.init3.nl:8080/speedtest/upload.php', 'lat': '53.2167', 'lon': '6.5500', 'name': 'Groningen', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'INIT3 B.V.', 'id': '13130', 'host': 'speedtest.init3.nl:8080', 'd': 3970.342910714104}], 3946.710214524841: [{'url': 'http://speedtest.skv.gr:8080/speedtest/upload.php', 'lat': '53.1063', 'lon': '6.8751', 'name': 'Veendam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'SKV', 'id': '14730', 'host': 'speedtest.skv.gr:8080', 'd': 3946.710214524841}],4082.1366719075436: [{'url': 'http://speedtest.kabeltex.nl:8080/speedtest/upload.php', 'lat': '53.0546', 'lon': '4.7997', 'name': 'Den Burg', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Kabeltex B.V.', 'id': '21726', 'host': 'speedtest.kabeltex.nl:8080', 'd': 4082.1366719075436}],3982.9170960393017: [{'url': 'http://speedtest.mpl.hugeserver.com:8080/speedtest/upload.php', 'lat': '52.7000', 'lon': '6.2000', 'name': 'Meppel', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'HugeServer Networks, LLC', 'id': '11985', 'host': 'speedtest.mpl.hugeserver.com:8080', 'd': 3982.9170960393017}],4057.684268035329: [{'url': 'http://speedtest.artofautomation.net:8080/speedtest/upload.php', 'lat': '52.6423', 'lon': '5.0602', 'name': 'Hoorn', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Art Of Automation B.V.', 'id': '13920', 'host': 'speedtest.artofautomation.net:8080', 'd': 4057.684268035329}],3952.8048200045287: [{'url': 'http://speedtest.qonnected.net:8080/speedtest/upload.php', 'lat': '52.5754', 'lon': '6.6167', 'name': 'Hardenberg', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Qonnected B.V.', 'id': '12057', 'host': 'speedtest.qonnected.net:8080', 'd': 3952.8048200045287}],4011.977044391298: [{'url': 'http://ooklaspeedtest.solcon.nl:8080/speedtest/upload.php', 'lat': '52.5333', 'lon': '5.7167', 'name': 'Dronten', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Solcon', 'id': '1747', 'url2': 'http://ooklaspeedtest2.solcon.nl/speedtest/upload.php', 'host': 'ooklaspeedtest.solcon.nl:8080', 'd': 4011.977044391298}, {'url': 'http://spt01.sdhd.hosting:8080/speedtest/upload.php', 'lat': '52.5333', 'lon': '5.7167', 'name': 'Dronten', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'SDHD Hosts', 'id': '19919', 'host': 'spt01.sdhd.hosting:8080', 'd': 4011.977044391298}, {'url': 'http://sp1.turbohost.nl:8080/speedtest/upload.php', 'lat': '52.5333', 'lon': '5.7167', 'name': 'Dronten', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Turbohost', 'id': '27316', 'host': 'sp1.turbohost.nl:8080', 'd': 4011.977044391298}, {'url': 'http://snelheidstest.weserve.nl:8080/speedtest/upload.php', 'lat': '52.5333', 'lon': '5.7167', 'name': 'Dronten', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Weserve B.V.', 'id': '31530', 'host': 'snelheidstest.weserve.nl:8080', 'd': 4011.977044391298}],3987.2317363293832: [{'url': 'http://speedtest.eqzw1.qonnected.net:8080/speedtest/upload.php', 'lat': '52.5168', 'lon': '6.0830', 'name': 'Zwolle', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Qonnected B.V.', 'id': '31339', 'host': 'speedtest.eqzw1.qonnected.net:8080', 'd': 3987.2317363293832}],4081.207571105142: [{'url': 'http://amsterdam.layeredserver.com:8080/speedtest/upload.php', 'lat': '52.3874', 'lon': '4.6462', 'name': 'Haarlem', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'LayeredServer', 'id': '30267', 'host': 'amsterdam.layeredserver.com:8080', 'd': 4081.207571105142}],4010.4275727023164: [{'url': 'http://speed.suitit.nl:8080/speedtest/upload.php', 'lat': '51.4381', 'lon': '5.4752', 'name': 'Eindhoven', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'SuitIT', 'id': '19461', 'host': 'speed.suitit.nl:8080', 'd': 4010.4275727023164}],4116.520066870229: [{'url': 'http://speedtest.maxista.nl:8080/speedtest/upload.php', 'lat': '51.3127', 'lon': '3.9117', 'name': 'Zaamslag', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Maxista', 'id': '31320', 'host': 'speedtest.maxista.nl:8080', 'd': 4116.520066870229}],4122.389979134935: [{'url': 'http://speedtest1.skylinq.nl:8080/speedtest/upload.php', 'lat': '51.5030', 'lon': '3.8595', 'name': 'Goes', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Skylinq', 'id': '10915', 'url2': 'http://speedtest2.skylinq.nl/speedtest/upload.php', 'host': 'speedtest1.skylinq.nl:8080', 'd': 4122.389979134935}], 4139.063550051049: [{'url': 'http://speedtest.zeelandnet.nl:8080/speedtest/upload.php', 'lat': '51.5000', 'lon': '3.6167', 'name': 'Middelburg', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'DELTA', 'id': '11433', 'host': 'speedtest.zeelandnet.nl:8080', 'd': 4139.063550051049}], 4073.1063351075313: [{'url': 'http://speedtest.alb-dp1.qweb.net:8080/speedtest/upload.php', 'lat': '51.8667', 'lon': '4.6500', 'name': 'Alblasserdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Qweb | Full-Service Hosting', 'id': '1208', 'host': 'speedtest.alb-dp1.qweb.net:8080', 'd': 4073.1063351075313}], 4013.226961822053: [{'url': 'http://speedtest.trined.nl:8080/speedtest/upload.php', 'lat': '51.5655', 'lon': '5.4620', 'name': 'Sint-Oedenrode', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'TriNed B.V.', 'id': '13883', 'host': 'speedtest.trined.nl:8080', 'd': 4013.226961822053}], 4085.3876247769604: [{'url': 'http://speedtestB.kpn.com:8080/speedtest/upload.php', 'lat': '51.9217', 'lon': '4.4811', 'name': 'Rotterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'KPN', 'id': '26998', 'host': 'speedtestB.kpn.com:8080', 'd': 4085.3876247769604}, {'url': 'http://eu.speedtest.i3d.net:8080/speedtest/upload.php', 'lat': '51.9217', 'lon': '4.4811', 'name': 'Rotterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'i3D.net', 'id': '21509', 'host': 'eu.speedtest.i3d.net:8080', 'd': 4085.3876247769604}], 3963.4740201158634: [{'url': 'http://speedtest.novoserve.com:8080/speedtest/upload.php', 'lat': '51.9650', 'lon': '6.2883', 'name': 'Doetinchem', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'NovoServe', 'id': '8997', 'url2': 'http://185.80.232.130/speedtest/upload.php', 'host': 'speedtest.novoserve.com:8080', 'd': 3963.4740201158634}], 3988.936031974343: [{'url': 'http://speedtest.breedbandarnhem.nl:8080/speedtest/upload.php', 'lat': '51.9833', 'lon': '5.9167', 'name': 'Arnhem', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Breedband Arnhem', 'id': '5252', 'url2': 'http://speedtest.breedbandarnhem.net/speedtest/upload.php', 'host': 'speedtest.breedbandarnhem.nl:8080', 'd': 3988.936031974343}, {'url': 'http://speedtest.dt-it.nl:8080/speedtest/upload.php', 'lat': '51.9833', 'lon': '5.9167', 'name': 'Arnhem', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'DT-IT', 'id': '6147', 'url2': 'http://speedtest.dt-it.com/speedtest/upload.php', 'host': 'speedtest.dt-it.nl:8080', 'd': 3988.936031974343}], 4085.6573409603907: [{'url': 'http://speedtest.damecon.com:8080/speedtest/upload.php', 'lat': '51.9244', 'lon': '4.4777', 'name': 'Rotterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Damecon B.V.', 'id': '21103', 'host': 'speedtest.damecon.com:8080', 'd': 4085.6573409603907}], 4105.161268026478: [{'url': 'http://speedtest.caiw.net:8080/speedtest/upload.php', 'lat': '51.9931', 'lon': '4.2050', 'name': 'Naaldwijk', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Caiway', 'id': '14850', 'host': 'speedtest.caiw.net:8080', 'd': 4105.161268026478}, {'url': 'http://speedtest.worldstream.nl:8080/speedtest/upload.php', 'lat': '51.9931', 'lon': '4.2050', 'name': 'Naaldwijk', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'WorldStream B.V.', 'id': '6554', 'url2': 'http://217.23.0.8/upload.php', 'host': 'speedtest.worldstream.nl:8080', 'd': 4105.161268026478}], 4040.6944038494858: [{'url': 'http://speedtest.extremehosting.nl:8080/speedtest/upload.php', 'lat': '52.0278', 'lon': '5.1630', 'name': 'Houten', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'eXtreme Hosting', 'id': '24998', 'host': 'speedtest.extremehosting.nl:8080', 'd': 4040.6944038494858}], 4006.9261230248203: [{'url': 'http://snelheid.routit.net:8080/speedtest/upload.php', 'lat': '52.0402', 'lon': '5.6649', 'name': 'Ede', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'RoutIT BV', 'id': '12372', 'host': 'snelheid.routit.net:8080', 'd': 4006.9261230248203}], 4099.762052557789: [{'url': 'http://speedtest.glasnet.nl:8080/speedtest/upload.php', 'lat': '52.0705', 'lon': '4.3007', 'name': 'Den Haag', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Glasnet', 'id': '26476', 'host': 'speedtest.glasnet.nl:8080', 'd': 4099.762052557789}], 4027.560685925166: [{'url': 'http://sp1.jonaz.nl:8080/speedtest/upload.php', 'lat': '52.1525', 'lon': '5.3869', 'name': 'Amersfoort', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Jonaz B.V.', 'id': '10644', 'host': 'sp1.jonaz.nl:8080', 'd': 4027.560685925166}, {'url': 'http://speedtest.extraip.com:8080/speedtest/upload.php', 'lat': '52.1525', 'lon': '5.3869', 'name': 'Amersfoort', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'ExtraIP', 'id': '26425', 'host': 'speedtest.extraip.com:8080', 'd': 4027.560685925166}],
4012.5780580984137: [{'url': 'http://speedtest.sitbv.nl:8080/speedtest/upload.php', 'lat': '52.1833', 'lon': '5.6167', 'name': 'Voorthuizen', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'SIT Internetdiensten B.V.', 'id': '2641', 'url2': 'http://speedtest.sitbv.net/speedtest/upload.php', 'host': 'speedtest.sitbv.nl:8080', 'd': 4012.5780580984137}],3926.8883519119927: [{'url': 'http://ookla.snt.utwente.nl:8080/speedtest/upload.php', 'lat': '52.2167', 'lon': '6.9000', 'name': 'Enschede', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Studenten Net Twente', 'id': '24887', 'host': 'ookla.snt.utwente.nl:8080', 'd': 3926.8883519119927}],3989.5900538374053: [{'url': 'http://speedtest3.solcon.nl:8080/speedtest/upload.php', 'lat': '52.2167', 'lon': '5.9667', 'name': 'Apeldoorn', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Solcon Internetdiensten N.V.', 'id': '4601', 'url2': 'http://speedtest3.solcon.net/speedtest/upload.php', 'host': 'speedtest3.solcon.nl:8080', 'd': 3989.5900538374053}], 4078.462449412178: [{'url': 'http://speedtest.korton.net:8080/speedtest/upload.php', 'lat': '52.3000', 'lon': '4.6667', 'name': 'Hoofddorp', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Korton Group BV', 'id': '5124', 'url2': 'http://speedtest2.korton.net/speedtest/upload.php', 'host': 'speedtest.korton.net:8080', 'd': 4078.462449412178}], 4015.431730397841: [{'url': 'http://speedtest.flexyz.com:8080/speedtest/upload.php', 'lat': '52.3500', 'lon': '5.6167', 'name': 'Harderwijk', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Flexyz', 'id': '22507', 'host': 'speedtest.flexyz.com:8080', 'd': 4015.431730397841}, {'url': 'http://sp1.matrixdata.nl:8080/speedtest/upload.php', 'lat': '52.3500', 'lon': '5.6167', 'name': 'Harderwijk', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Matrix DATA', 'id': '7095', 'url2': 'http://sp2.matrixdata.nl/speedtest/upload.php', 'host': 'sp1.matrixdata.nl:8080', 'd': 4015.431730397841}], 4042.559801605288: [{'url': 'http://speedtest.redhosting.nl:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '5.2167', 'name': 'Almere', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Redhosting', 'id': '7214', 'url2': 'http://speedtest2.redhosting.nl/upload.php', 'host': 'speedtest.redhosting.nl:8080', 'd': 4042.559801605288}], 4081.4722654147804: [{'url': 'http://speedtest.yisp.nl:8080/speedtest/upload.php', 'lat': '52.3803', 'lon': '4.6406', 'name': 'Haarlem', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'YISP B.V.', 'id': '24477', 'host': 'speedtest.yisp.nl:8080', 'd': 4081.4722654147804}, {'url': 'http://speedtest.ams1.nl.leaseweb.net:8080/speedtest/upload.php', 'lat': '52.3803', 'lon': '4.6406', 'name': 'Haarlem', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'LeaseWeb', 'id': '3587', 'url2': 'http://s2.speedtest.ams1.nl.leaseweb.net/speedtest/upload.php', 'host': 'speedtest.ams1.nl.leaseweb.net:8080', 'd': 4081.4722654147804}], 4064.300397590959: [{'url': 'http://speednld.phoenixnap.com:8080/speedtest/upload.php', 'lat': '52.3727', 'lon': '4.8944', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'PhoenixNAP Global IT Services', 'id': '28922', 'host': 'speednld.phoenixnap.com:8080', 'd': 4064.300397590959}], 4063.6066180935604: [{'url': 'http://speedtest3.serverius.net:8080/speedtest/upload.php', 'lat': '52.3680', 'lon': '4.9036', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Serverius Connectivity', 'id': '20005', 'host': 'speedtest3.serverius.net:8080', 'd': 4063.6066180935604}], 4064.2063586886597: [{'url': 'http://speedtest.xs4all.nl:8080/speedtest/upload.php', 'lat': '52.3702', 'lon': '4.8952', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'XS4ALL Internet BV', 'id': '13218', 'host': 'speedtest.xs4all.nl:8080', 'd': 4064.2063586886597}], 4063.827499033275: [{'url': 'http://speedtest.tele2.nl:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Tele2 Netherlands B.V.', 'id': '5972', 'url2': 'http://speedtest-4g.tele2.nl/speedtest/upload.php', 'host': 'speedtest.tele2.nl:8080', 'd': 4063.827499033275}, {'url': 'http://mirror.nforce.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'NFOrce Entertainment B.V.', 'id': '3386', 'url2': 'http://host2.speedtest.nforce.com/speedtest/upload.php', 'host': 'mirror.nforce.com:8080', 'd': 4063.827499033275}, {'url': 'http://nl.speedtest.vietpn.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'SUPER VPN VIETPN.COM', 'id': '19149', 'host': 'nl.speedtest.vietpn.com:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.vanciscloud.nl:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Vancis', 'id': '11365', 'host': 'speedtest.vanciscloud.nl:8080', 'd': 4063.827499033275}, {'url': 'http://lg-ams.fdcservers.net:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'fdcservers.net', 'id': '9913', 'url2': 'http://speedtest.ams2-c.fdcservers.net/speedtest/upload.php', 'host': 'lg-ams.fdcservers.net:8080', 'd': 4063.827499033275}, {'url': 'http://ams-eq6-tptest1.31173.se:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': '31173 Services AB', 'id': '23094', 'host': 'ams-eq6-tptest1.31173.se:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.tilaa.net:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Tilaa B.V.', 'id': '9182', 'url2': 'http://speedtest2.tilaa.net/upload.php', 'host': 'speedtest.tilaa.net:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest2.usenet.farm:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Usenet.Farm', 'id': '22400', 'host': 'speedtest2.usenet.farm:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.sdnbucks.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Sdnbucks B.V.', 'id': '18404', 'host': 'speedtest.sdnbucks.com:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.eu.kamatera.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'KamaTera INC', 'id': '11611', 'host': 'speedtest.eu.kamatera.com:8080', 'd': 4063.827499033275}, {'url': 'http://nl.altushost.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'AltusHost B.V.', 'id': '5211', 'url2': 'http://nl.altushost.net/speedtest/upload.php', 'host': 'nl.altushost.com:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.mkbwebhoster.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'MKBWebhoster B.V.', 'id': '13040', 'host': 'speedtest.mkbwebhoster.com:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.xsnews.nl:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'XS News B.V.', 'id': '29076', 'host': 'speedtest.xsnews.nl:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.hostsailor.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Host Sailor LTD', 'id': '13291', 'host': 'speedtest.hostsailor.com:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.host-palace.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'HostPalace Web Solution Private Limited', 'id': '26542', 'host': 'speedtest.host-palace.com:8080', 'd': 4063.827499033275}, {'url': 'http://SpeedtestA.kpn.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'KPN', 'id': '26996', 'host': 'SpeedtestA.kpn.com:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.claranet.nl:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Claranet Benelux B.V.', 'id': '30847', 'host': 'speedtest.claranet.nl:8080', 'd': 4063.827499033275}, {'url': 'http://noc.tanhost.com:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Tanhost - NL', 'id': '29652', 'host': 'noc.tanhost.com:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest.as61349.net:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'MaxiTEL Telecom', 'id': '26764', 'host': 'speedtest.as61349.net:8080', 'd': 4063.827499033275}, {'url': 'http://5-252-165-254.nip.io:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'rixCloud, Inc', 'id': '30688', 'host': '5-252-165-254.nip.io:8080', 'd': 4063.827499033275}, {'url': 'http://speedtest01.nikhef.qonnected.net:8080/speedtest/upload.php', 'lat': '52.3667', 'lon': '4.9000', 'name': 'Amsterdam', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Qonnected B.V.', 'id': '31337', 'host': 'speedtest01.nikhef.qonnected.net:8080', 'd': 4063.827499033275}], 3934.5568209244625: [{'url': 'http://speedtest.previder.nl:8080/speedtest/upload.php', 'lat': '52.2667', 'lon': '6.8000', 'name': 'Hengelo', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Previder BV', 'id': '5302', 'url2': 'http://speedtest.previder.net/speedtest/upload.php', 'host': 'speedtest.previder.nl:8080', 'd': 3934.5568209244625}],11806.674371655745: [{'url': 'http://speedtest.uts.cw:8080/speedtest/upload.php', 'lat': '12.1167', 'lon': '-68.9333', 'name': 'Willemstad', 'country': 'Netherlands Antilles', 'cc': 'AN', 'sponsor': 'UTS', 'id': '12872', 'host': 'speedtest.uts.cw:8080', 'd': 11806.674371655745}, {'url': 'http://speedtest.digicelabc.net:8080/speedtest/upload.php', 'lat': '12.1167', 'lon': '-68.9333', 'name': 'Willemstad', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Digicel Curacao', 'id': '5794', 'url2': 'http://186.190.233.45/upload.php', 'host': 'speedtest.digicelabc.net:8080', 'd': 11806.674371655745}], 3977.802846755756: [{'url': 'http://speedtest01.daxisweb.net:8080/speedtest/upload.php', 'lat': '52.2661', 'lon': '6.1552', 'name': 'Deventer', 'country': 'Netherlands', 'cc': 'NL', 'sponsor': 'Daxis Web', 'id': '11066', 'host': 'speedtest01.daxisweb.net:8080', 'd': 3977.802846755756}],
6306.780729067895: [{'url': 'http://reunion3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '-20.8907', 'lon': '55.4551', 'name': 'Saint-Denis La Réunion', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '24492', 'host': 'reunion3.speedtest.orange.fr:8080', 'd': 6306.780729067895}], 3987.6186569912948: [{'url': 'http://marseille.testdebit.info:8080/speedtest/upload.php', 'lat': '43.2964', 'lon': '5.3700', 'name': 'Marseille', 'country': 'France', 'cc': 'FR', 'sponsor': 'TestDebit.info', 'id': '4036', 'host': 'marseille.testdebit.info:8080', 'd': 3987.6186569912948}, {'url': 'http://marseille3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '43.2964', 'lon': '5.3700', 'name': 'Marseille', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '29545', 'host': 'marseille3.speedtest.orange.fr:8080', 'd': 3987.6186569912948}], 4300.6056863410395: [{'url': 'http://speedtest1.fullsave.com:8080/speedtest/upload.php', 'lat': '43.6047', 'lon': '1.4442', 'name': 'Toulouse', 'country': 'France', 'cc': 'FR', 'sponsor': 'FullSave', 'id': '29032', 'host': 'speedtest1.fullsave.com:8080', 'd': 4300.6056863410395}], 3832.3847834316207: [{'url': 'http://62.210.85.110:8080/speedtest/upload.php', 'lat': '43.7028', 'lon': '7.2692', 'name': 'Nice', 'country': 'France', 'cc': 'FR', 'sponsor': 'DFOX', 'id': '8195', 'host': '62.210.85.110:8080', 'd': 3832.3847834316207}], 4447.749038791915: [{'url': 'http://bordeaux.lafibre.info:8080/speedtest/upload.php', 'lat': '44.8378', 'lon': '-0.5792', 'name': 'Bordeaux', 'country': 'France', 'cc': 'FR', 'sponsor': 'LaFibre.info', 'id': '21415', 'host': 'bordeaux.lafibre.info:8080', 'd': 4447.749038791915}, {'url': 'http://bordeaux3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '44.8378', 'lon': '-0.5792', 'name': 'Bordeaux', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '29542', 'host': 'bordeaux3.speedtest.orange.fr:8080', 'd': 4447.749038791915}], 3950.953416125216: [{'url': 'http://speedtest.alpesys.fr:8080/speedtest/upload.php', 'lat': '45.1885', 'lon': '5.7245', 'name': 'Grenoble', 'country': 'France', 'cc': 'FR', 'sponsor': 'Alpesys', 'id': '25041', 'host': 'speedtest.alpesys.fr:8080', 'd': 3950.953416125216}], 3935.4663189735734: [{'url': 'http://speedtest.rochodc.com:8080/speedtest/upload.php', 'lat': '45.5646', 'lon': '5.9178', 'name': 'Chambéry', 'country': 'France', 'cc': 'FR', 'sponsor': 'Rocho DataCenter', 'id': '11457', 'host': 'speedtest.rochodc.com:8080', 'd': 3935.4663189735734}],
4019.4932550588205: [{'url': 'http://lyon.lafibre.info:8080/speedtest/upload.php', 'lat': '45.7669', 'lon': '4.8342', 'name': 'Lyon', 'country': 'France', 'cc': 'FR', 'sponsor': 'LaFibre.info', 'id': '2023', 'host': 'lyon.lafibre.info:8080', 'd': 4019.4932550588205}, {'url': 'http://lyon3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '45.7669', 'lon': '4.8342', 'name': 'Lyon', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '24394', 'host': 'lyon3.speedtest.orange.fr:8080', 'd': 4019.4932550588205}, {'url': 'http://cor2.speedtest.mire.sfr.net:8080/speedtest/upload.php', 'lat': '45.7669', 'lon': '4.8342', 'name': 'Lyon', 'country': 'France', 'cc': 'FR', 'sponsor': 'SFR', 'id': '27852', 'host': 'cor2.speedtest.mire.sfr.net:8080', 'd': 4019.4932550588205}], 3836.336780496433: [{'url': 'http://testdebitpublic.vialis.net:8080/speedtest/upload.php', 'lat': '48.0794', 'lon': '7.3585', 'name': 'Colmar', 'country': 'France', 'cc': 'FR', 'sponsor': 'Vialis', 'id': '24059', 'host': 'testdebitpublic.vialis.net:8080', 'd': 3836.336780496433}], 4506.9644944868705: [{'url': 'http://rennes3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '48.1173', 'lon': '-1.6778', 'name': 'Rennes', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '23282', 'host': 'rennes3.speedtest.orange.fr:8080', 'd': 4506.9644944868705}, {'url': 'http://speedtest.ibloopro.fr:8080/speedtest/upload.php', 'lat': '48.1173', 'lon': '-1.6778', 'name': 'Rennes', 'country': 'France', 'cc': 'FR', 'sponsor': 'iBlooPro', 'id': '31656', 'host': 'speedtest.ibloopro.fr:8080', 'd': 4506.9644944868705}], 3812.532033878701: [{'url': 'http://strasbourg3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '48.5844', 'lon': '7.7486', 'name': 'Strasbourg', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '29543', 'host': 'strasbourg3.speedtest.orange.fr:8080', 'd': 3812.532033878701}], 4215.00669012271: [{'url': 'http://massy.testdebit.info:8080/speedtest/upload.php', 'lat': '48.7309', 'lon': '2.2713', 'name': 'Massy', 'country': 'France', 'cc': 'FR', 'sponsor': 'TestDebit.info', 'id': '2231', 'host': 'massy.testdebit.info:8080', 'd': 4215.00669012271}], 4234.872050887798: [{'url': 'http://tng1.speedtest.mire.sfr.net:8080/speedtest/upload.php', 'lat': '48.7767', 'lon': '2.0018', 'name': 'Trappes', 'country': 'France', 'cc': 'FR', 'sponsor': 'SFR', 'id': '31993', 'host': 'tng1.speedtest.mire.sfr.net:8080', 'd': 4234.872050887798}], 4206.2603153903165: [{'url': 'http://st1.online.net:8080/speedtest/upload.php', 'lat': '48.7875', 'lon': '2.3928', 'name': 'Vitry-sur-Seine', 'country': 'France', 'cc': 'FR', 'sponsor': 'ONLINE S.A.S.', 'id': '5022', 'url2': 'http://st2.online.net/speedtest/speedtest/upload.php', 'host': 'st1.online.net:8080', 'd': 4206.2603153903165}], 4209.87261712758: [{'url': 'http://speedtest.naitways.net:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'Naitways', 'id': '16476', 'host': 'speedtest.naitways.net:8080', 'd': 4209.87261712758}, {'url': 'http://montsouris3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '24215', 'host': 'montsouris3.speedtest.orange.fr:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest.mire.sfr.net:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'SFR SAS', 'id': '12746', 'host': 'speedtest.mire.sfr.net:8080', 'd': 4209.87261712758}, {'url': 'http://sp01.SiriusMediaGroup.com:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'Sirius Media Group', 'id': '10676', 'url2': 'http://sp2.siriushd.net/upload.php', 'host': 'sp01.SiriusMediaGroup.com:8080', 'd': 4209.87261712758}, {'url': 'http://par.speedtest.gtt.net:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'GTT.net', 'id': '24386', 'host': 'par.speedtest.gtt.net:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest-ookla-prod-001-par.ff.avast.com:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'CCleaner', 'id': '16676', 'host': 'speedtest-ookla-prod-001-par.ff.avast.com:8080', 'd': 4209.87261712758}, {'url': 'http://lg.par-c.fdcservers.net:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'fdcservers.net', 'id': '6027', 'url2': 'http://speedtest.par-c.fdcservers.net/speedtest/upload.php', 'host': 'lg.par-c.fdcservers.net:8080', 'd': 4209.87261712758}, {'url': 'http://debit-th2-1.stella-telecom.fr:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'PARIS', 'country': 'France', 'cc': 'FR', 'sponsor': 'Stella Telecom', 'id': '26387', 'host': 'debit-th2-1.stella-telecom.fr:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest.sewan.fr:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'SEWAN', 'id': '24130', 'host': 'speedtest.sewan.fr:8080', 'd': 4209.87261712758}, {'url': 'http://perf.keyyo.net:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'KEYYO', 'id': '27961', 'host': 'perf.keyyo.net:8080', 'd': 4209.87261712758}, {'url': 'http://speed1.harrylafranc.fr:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'HarryLafranc', 'id': '10176', 'url2': 'http://speed2.harrylafranc.fr/upload.php', 'host': 'speed1.harrylafranc.fr:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest-paris.colocationix.de:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'ColocationIX 10G', 'id': '28994', 'host': 'speedtest-paris.colocationix.de:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest1-fr.truphone.com:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'Truphone', 'id': '31835', 'host': 'speedtest1-fr.truphone.com:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest2-fr.truphone.com:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'Truphone', 'id': '31836', 'host': 'speedtest2-fr.truphone.com:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest.mediactive.fr:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'MEDIACTIVE', 'id': '31895', 'host': 'speedtest.mediactive.fr:8080', 'd': 4209.87261712758}, {'url': 'http://speedperf.axione.fr:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'Axione', 'id': '28308', 'host': 'speedperf.axione.fr:8080', 'd': 4209.87261712758}, {'url': 'http://speedtest.telerys.net:8080/speedtest/upload.php', 'lat': '48.8742', 'lon': '2.3470', 'name': 'Paris', 'country': 'France', 'cc': 'FR', 'sponsor': 'Telerys', 'id': '31725', 'host': 'speedtest.telerys.net:8080', 'd': 4209.87261712758}], 4216.362971801067: [{'url': 'http://speedtest.stella-telecom.fr:8080/speedtest/upload.php', 'lat': '48.9006', 'lon': '2.2593', 'name': 'Courbevoie', 'country': 'France', 'cc': 'FR', 'sponsor': 'Stella Telecom', 'id': '14821', 'host': 'speedtest.stella-telecom.fr:8080', 'd': 4216.362971801067}],
4217.755227202114: [{'url': 'http://puteaux3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '48.8847', 'lon': '2.2396', 'name': 'Puteaux', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '23884', 'host': 'puteaux3.speedtest.orange.fr:8080', 'd': 4217.755227202114}], 3822.3481893076514: [{'url': 'http://testdebit.laregie.fr:8080/speedtest/upload.php', 'lat': '48.9335', 'lon': '7.6676', 'name': 'Reichshoffen', 'country': 'France', 'cc': 'FR', 'sponsor': 'La Regie', 'id': '14043', 'host': 'testdebit.laregie.fr:8080', 'd': 3822.3481893076514}], 4213.050420119095: [{'url': 'http://speedtest-1.netw.fr:8080/speedtest/upload.php', 'lat': '48.9045', 'lon': '2.3048', 'name': 'Clichy', 'country': 'France', 'cc': 'FR', 'sponsor': 'Networth Telecom', 'id': '28073', 'host': 'speedtest-1.netw.fr:8080', 'd': 4213.050420119095}], 4190.378392875099: [{'url': 'http://mit1.speedtest.mire.sfr.net:8080/speedtest/upload.php', 'lat': '48.9854', 'lon': '2.6192', 'name': 'Mitry', 'country': 'France', 'cc': 'FR', 'sponsor': 'SFR', 'id': '27984', 'host': 'mit1.speedtest.mire.sfr.net:8080', 'd': 4190.378392875099}],3889.191696286259: [{'url': 'http://testdebithom.enes.fr:8080/speedtest/upload.php', 'lat': '49.1252', 'lon': '6.7756', 'name': 'Hombourg-Haut', 'country': 'France', 'cc': 'FR', 'sponsor': 'Enes', 'id': '21268', 'host': 'testdebithom.enes.fr:8080', 'd': 3889.191696286259}],3934.70759673973: [{'url': 'http://bpwoippy.vialis.net:8080/speedtest/upload.php', 'lat': '49.1509', 'lon': '6.1509', 'name': 'Woippy', 'country': 'France', 'cc': 'FR', 'sponsor': 'Vialis', 'id': '13661', 'host': 'bpwoippy.vialis.net:8080', 'd': 3934.70759673973}] , 3881.1950008500594: [{'url': 'http://testdebit.fibragglo.fr:8080/speedtest/upload.php', 'lat': '49.1865', 'lon': '6.8953', 'name': 'Forbach', 'country': 'France', 'cc': 'FR', 'sponsor': 'Fibragglo', 'id': '16232', 'host': 'testdebit.fibragglo.fr:8080', 'd': 3881.1950008500594}], 3939.8561173443263: [{'url': 'http://speedtest.ornethd.net:8080/speedtest/upload.php', 'lat': '49.2513', 'lon': '6.0934', 'name': 'Rombas', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORNE THD', 'id': '17349', 'host': 'speedtest.ornethd.net:8080', 'd': 3939.8561173443263}], 3934.485297782718: [{'url': 'http://testdebit.telehagondange.fr:8080/speedtest/upload.php', 'lat': '49.2542', 'lon': '6.1681', 'name': 'Hagondange', 'country': 'France', 'cc': 'FR', 'sponsor': 'Enes Hag', 'id': '31081', 'host': 'testdebit.telehagondange.fr:8080', 'd': 3934.485297782718}], 4088.9371034859787: [{'url': 'http://reims.testdebit.info:8080/speedtest/upload.php', 'lat': '49.2628', 'lon': '4.0347', 'name': 'Reims', 'country': 'France', 'cc': 'FR', 'sponsor': 'Ikoula', 'id': '5813', 'host': 'reims.testdebit.info:8080', 'd': 4088.9371034859787}, {'url': 'http://speedtest.hexanet.fr:8080/speedtest/upload.php', 'lat': '49.2628', 'lon': '4.0347', 'name': 'Reims', 'country': 'FR', 'cc': 'FR', 'sponsor': 'Hexanet', 'id': '17225', 'host': 'speedtest.hexanet.fr:8080', 'd': 4088.9371034859787}], 3943.907575092757: [{'url': 'http://testdebit.regivision.fr:8080/speedtest/upload.php', 'lat': '49.3422', 'lon': '6.0499', 'name': 'Nilvange', 'country': 'France', 'cc': 'FR', 'sponsor': 'Regivision', 'id': '31082', 'host': 'testdebit.regivision.fr:8080', 'd': 3943.907575092757}], 3900.2049915682373: [{'url': 'http://testdebit.falckhargarten.fr:8080/speedtest/upload.php', 'lat': '49.2259', 'lon': '6.6383', 'name': 'Falck', 'country': 'France', 'cc': 'FR', 'sponsor': 'REFO Falck', 'id': '21216', 'host': 'testdebit.falckhargarten.fr:8080', 'd': 3900.2049915682373}], 3895.7943236651995: [{'url': 'http://testdebitcreutz.enes.fr:8080/speedtest/upload.php', 'lat': '49.2050', 'lon': '6.6962', 'name': 'Creutzwald', 'country': 'France', 'cc': 'FR', 'sponsor': 'Enes', 'id': '24052', 'host': 'testdebitcreutz.enes.fr:8080', 'd': 3895.7943236651995}],
4165.41340935434: [{'url': 'http://douai.lafibre.info:8080/speedtest/upload.php', 'lat': '50.3714', 'lon': '3.0800', 'name': 'Douai', 'country': 'France', 'cc': 'FR', 'sponsor': 'LaFibre.info', 'id': '4010', 'host': 'douai.lafibre.info:8080', 'd': 4165.41340935434}], 4237.409035335153: [{'url': 'http://speedtest-gra.as16276.ovh:8080/speedtest/upload.php', 'lat': '50.9871', 'lon': '2.1255', 'name': 'Gravelines', 'country': 'France', 'cc': 'FR', 'sponsor': 'OVH Cloud', 'id': '25985', 'host': 'speedtest-gra.as16276.ovh:8080', 'd': 4237.409035335153}, {'url': 'http://speedfrance.dewdrive.com:8080/speedtest/upload.php', 'lat': '50.9871', 'lon': '2.1255', 'name': 'Gravelines', 'country': 'France', 'cc': 'FR', 'sponsor': 'dewDrive - Cloud Backup', 'id': '30413', 'host': 'speedfrance.dewdrive.com:8080', 'd': 4237.409035335153}], 4161.85397109676: [{'url': 'http://speedtestfr.mirrors.ro:8080/speedtest/upload.php', 'lat': '50.7000', 'lon': '3.1700', 'name': 'Roubaix', 'country': 'France', 'cc': 'FR', 'sponsor': 'ITDATA TELECOM SRL', 'id': '29243', 'host': 'speedtestfr.mirrors.ro:8080', 'd': 4161.85397109676}, {'url': 'http://my.roo.ru:8080/speedtest/upload.php', 'lat': '50.7000', 'lon': '3.1700', 'name': 'Roubaix', 'country': 'France', 'cc': 'FR', 'sponsor': 'deDiCorp Inc', 'id': '31761', 'host': 'my.roo.ru:8080', 'd': 4161.85397109676}], 4169.1512378235075: [{'url': 'http://speedtest.eurafibre.fr:8080/speedtest/upload.php', 'lat': '50.6292', 'lon': '3.0573', 'name': 'Lille', 'country': 'FR', 'cc': 'FR', 'sponsor': 'Eurafibre', 'id': '16913', 'host': 'speedtest.eurafibre.fr:8080', 'd': 4169.1512378235075}, {'url': 'http://lille3.speedtest.orange.fr:8080/speedtest/upload.php', 'lat': '50.6292', 'lon': '3.0573', 'name': 'Lille', 'country': 'France', 'cc': 'FR', 'sponsor': 'ORANGE FRANCE', 'id': '29544', 'host': 'lille3.speedtest.orange.fr:8080', 'd': 4169.1512378235075}], 3961.9815310544504: [{'url': 'http://testdebit.riv54.fr:8080/speedtest/upload.php', 'lat': '49.5285', 'lon': '5.8252', 'name': 'Saulnes', 'country': 'France', 'cc': 'FR', 'sponsor': 'RIV54', 'id': '14372', 'host': 'testdebit.riv54.fr:8080', 'd': 3961.9815310544504}], 3919.1013980799: [{'url': 'http://speedtest01.via-numerica.net:8080/speedtest/upload.php', 'lat': '46.1364', 'lon': '6.1331', 'name': 'Archamps', 'country': 'France', 'cc': 'FR', 'sponsor': 'Via Numérica', 'id': '3596', 'url2': 'http://speedtest01.as44494.net/speedtest/upload.php', 'host': 'speedtest01.via-numerica.net:8080', 'd': 3919.1013980799}], 4015.683064286323: [{'url': 'http://lyo1.speedtest.mire.sfr.net:8080/speedtest/upload.php', 'lat': '45.6996', 'lon': '4.8845', 'name': 'Venissieux', 'country': 'France', 'cc': 'FR', 'sponsor': 'SFR', 'id': '30993', 'host': 'lyo1.speedtest.mire.sfr.net:8080', 'd': 4015.683064286323}]}
        
        return self.servers

    def set_mini_server(self, server):
        """Instead of querying for a list of servers, set a link to a
        speedtest mini server
        """

        urlparts = urlparse(server)

        name, ext = os.path.splitext(urlparts[2])
        if ext:
            url = os.path.dirname(server)
        else:
            url = server

        request = build_request(url)
        uh, e = catch_request(request, opener=self._opener)
        if e:
            raise SpeedtestMiniConnectFailure('Failed to connect to %s' %
                                              server)
        else:
            text = uh.read()
            uh.close()

        extension = re.findall('upload_?[Ee]xtension: "([^"]+)"',
                               text.decode())
        if not extension:
            for ext in ['php', 'asp', 'aspx', 'jsp']:
                try:
                    f = self._opener.open(
                        '%s/speedtest/upload.%s' % (url, ext)
                    )
                except Exception:
                    pass
                else:
                    data = f.read().strip().decode()
                    if (f.code == 200 and
                            len(data.splitlines()) == 1 and
                            re.match('size=[0-9]', data)):
                        extension = [ext]
                        break
        if not urlparts or not extension:
            raise InvalidSpeedtestMiniServer('Invalid Speedtest Mini Server: '
                                             '%s' % server)

        self.servers = [{
            'sponsor': 'Speedtest Mini',
            'name': urlparts[1],
            'd': 0,
            'url': '%s/speedtest/upload.%s' % (url.rstrip('/'), extension[0]),
            'latency': 0,
            'id': 0
        }]

        return self.servers

    def get_closest_servers(self, limit=5):
        """Limit servers to the closest speedtest.net servers based on
        geographic distance
        """

        if not self.servers:
            self.get_servers()

        for d in sorted(self.servers.keys()):
            for s in self.servers[d]:
                self.closest.append(s)
                if len(self.closest) == limit:
                    break
            else:
                continue
            break

        printer('Closest Servers:\n%r' % self.closest, debug=True)
        return self.closest

    def get_best_server(self, servers=None):
        """Perform a speedtest.net "ping" to determine which speedtest.net
        server has the lowest latency
        """

        if not servers:
            if not self.closest:
                servers = self.get_closest_servers()
            servers = self.closest

        if self._source_address:
            source_address_tuple = (self._source_address, 0)
        else:
            source_address_tuple = None

        user_agent = build_user_agent()

        results = {}
        for server in servers:
            cum = []
            url = os.path.dirname(server['url'])
            stamp = int(timeit.time.time() * 1000)
            latency_url = '%s/latency.txt?x=%s' % (url, stamp)
            for i in range(0, 3):
                this_latency_url = '%s.%s' % (latency_url, i)
                printer('%s %s' % ('GET', this_latency_url),
                        debug=True)
                urlparts = urlparse(latency_url)
                try:
                    if urlparts[0] == 'https':
                        h = SpeedtestHTTPSConnection(
                            urlparts[1],
                            source_address=source_address_tuple
                        )
                    else:
                        h = SpeedtestHTTPConnection(
                            urlparts[1],
                            source_address=source_address_tuple
                        )
                    headers = {'User-Agent': user_agent}
                    path = '%s?%s' % (urlparts[2], urlparts[4])
                    start = timeit.default_timer()
                    h.request("GET", path, headers=headers)
                    r = h.getresponse()
                    total = (timeit.default_timer() - start)
                except HTTP_ERRORS:
                    e = get_exception()
                    printer('ERROR: %r' % e, debug=True)
                    cum.append(3600)
                    continue

                text = r.read(9)
                if int(r.status) == 200 and text == 'test=test'.encode():
                    cum.append(total)
                else:
                    cum.append(3600)
                h.close()

            avg = round((sum(cum) / 6) * 1000.0, 3)
            results[avg] = server

        try:
            fastest = sorted(results.keys())[0]
        except IndexError:
            raise SpeedtestBestServerFailure('Unable to connect to servers to '
                                             'test latency.')
        best = results[fastest]
        best['latency'] = fastest

        self.results.ping = fastest
        self.results.server = best

        self._best.update(best)
        printer('Best Server:\n%r' % best, debug=True)
        return best

    def download(self, callback=do_nothing, threads=None):
        """Test download speed against speedtest.net

        A ``threads`` value of ``None`` will fall back to those dictated
        by the speedtest.net configuration
        """

        urls = []
        for size in self.config['sizes']['download']:
            for _ in range(0, self.config['counts']['download']):
                urls.append('%s/random%sx%s.jpg' %
                            (os.path.dirname(self.best['url']), size, size))
       
        request_count = len(urls)
        requests = []
        for i, url in enumerate(urls):
            requests.append(
                build_request(url, bump=i, secure=self._secure)
            )

        max_threads = threads or self.config['threads']['download']
        in_flight = {'threads': 0}

        def producer(q, requests, request_count):
            for i, request in enumerate(requests):
                thread = HTTPDownloader(
                    i,
                    request,
                    start,
                    self.config['length']['download'],
                    opener=self._opener,
                    shutdown_event=self._shutdown_event
                )
                while in_flight['threads'] >= max_threads:
                    timeit.time.sleep(0.001)
                thread.start()
                q.put(thread, True)
                in_flight['threads'] += 1
                callback(i, request_count, start=True)

        finished = []

        def consumer(q, request_count):
            _is_alive = thread_is_alive
            while len(finished) < request_count:
                thread = q.get(True)
                while _is_alive(thread):
                    thread.join(timeout=0.001)
                in_flight['threads'] -= 1
                finished.append(sum(thread.result))
                callback(thread.i, request_count, end=True)

        q = Queue(max_threads)
        prod_thread = threading.Thread(target=producer,
                                       args=(q, requests, request_count))
        cons_thread = threading.Thread(target=consumer,
                                       args=(q, request_count))
        start = timeit.default_timer()
        prod_thread.start()
        cons_thread.start()
        _is_alive = thread_is_alive
        while _is_alive(prod_thread):
            prod_thread.join(timeout=0.001)
        while _is_alive(cons_thread):
            cons_thread.join(timeout=0.001)

        stop = timeit.default_timer()
        self.results.bytes_received = sum(finished)
        self.results.download = (
            (self.results.bytes_received / (stop - start)) * 8.0
        )
        if self.results.download > 100000:
            self.config['threads']['upload'] = 8
        return self.results.download

    def upload(self, callback=do_nothing, pre_allocate=True, threads=None):
        """Test upload speed against speedtest.net

        A ``threads`` value of ``None`` will fall back to those dictated
        by the speedtest.net configuration
        """

        sizes = []

        for size in self.config['sizes']['upload']:
            for _ in range(0, self.config['counts']['upload']):
                sizes.append(size)

        # request_count = len(sizes)
        request_count = self.config['upload_max']

        requests = []
        for i, size in enumerate(sizes):
            # We set ``0`` for ``start`` and handle setting the actual
            # ``start`` in ``HTTPUploader`` to get better measurements
            data = HTTPUploaderData(
                size,
                0,
                self.config['length']['upload'],
                shutdown_event=self._shutdown_event
            )
            if pre_allocate:
                data.pre_allocate()

            headers = {'Content-length': size}
            requests.append(
                (
                    build_request(self.best['url'], data, secure=self._secure,
                                  headers=headers),
                    size
                )
            )

        max_threads = threads or self.config['threads']['upload']
        in_flight = {'threads': 0}

        def producer(q, requests, request_count):
            for i, request in enumerate(requests[:request_count]):
                thread = HTTPUploader(
                    i,
                    request[0],
                    start,
                    request[1],
                    self.config['length']['upload'],
                    opener=self._opener,
                    shutdown_event=self._shutdown_event
                )
                while in_flight['threads'] >= max_threads:
                    timeit.time.sleep(0.001)
                thread.start()
                q.put(thread, True)
                in_flight['threads'] += 1
                callback(i, request_count, start=True)

        finished = []

        def consumer(q, request_count):
            _is_alive = thread_is_alive
            while len(finished) < request_count:
                thread = q.get(True)
                while _is_alive(thread):
                    thread.join(timeout=0.001)
                in_flight['threads'] -= 1
                finished.append(thread.result)
                callback(thread.i, request_count, end=True)

        q = Queue(threads or self.config['threads']['upload'])
        prod_thread = threading.Thread(target=producer,
                                       args=(q, requests, request_count))
        cons_thread = threading.Thread(target=consumer,
                                       args=(q, request_count))
        start = timeit.default_timer()
        prod_thread.start()
        cons_thread.start()
        _is_alive = thread_is_alive
        while _is_alive(prod_thread):
            prod_thread.join(timeout=0.1)
        while _is_alive(cons_thread):
            cons_thread.join(timeout=0.1)

        stop = timeit.default_timer()
        self.results.bytes_sent = sum(finished)
        self.results.upload = (
            (self.results.bytes_sent / (stop - start)) * 8.0
        )
        return self.results.upload


def ctrl_c(shutdown_event):
    """Catch Ctrl-C key sequence and set a SHUTDOWN_EVENT for our threaded
    operations
    """
    def inner(signum, frame):
        shutdown_event.set()
        printer('\nCancelling...', error=True)
        sys.exit(0)
    return inner


def version():
    """Print the version"""

    printer('speedtest-cli %s' % __version__)
    printer('Python %s' % sys.version.replace('\n', ''))
    sys.exit(0)


def csv_header(delimiter=','):
    """Print the CSV Headers"""

    printer(SpeedtestResults.csv_header(delimiter=delimiter))
    sys.exit(0)


def parse_args():
    """Function to handle building and parsing of command line arguments"""
    description = (
        'Command line interface for testing internet bandwidth using '
        'speedtest.net.\n'
        '------------------------------------------------------------'
        '--------------\n'
        'https://github.com/sivel/speedtest-cli')

    parser = ArgParser(description=description)
    # Give optparse.OptionParser an `add_argument` method for
    # compatibility with argparse.ArgumentParser
    try:
        parser.add_argument = parser.add_option
    except AttributeError:
        pass
    parser.add_argument('--no-download', dest='download', default=True,
                        action='store_const', const=False,
                        help='Do not perform download test')
    parser.add_argument('--no-upload', dest='upload', default=True,
                        action='store_const', const=False,
                        help='Do not perform upload test')
    parser.add_argument('--single', default=False, action='store_true',
                        help='Only use a single connection instead of '
                             'multiple. This simulates a typical file '
                             'transfer.')
    parser.add_argument('--bytes', dest='units', action='store_const',
                        const=('byte', 8), default=('bit', 1),
                        help='Display values in bytes instead of bits. Does '
                             'not affect the image generated by --share, nor '
                             'output from --json or --csv')
    parser.add_argument('--share', action='store_true',
                        help='Generate and provide a URL to the speedtest.net '
                             'share results image, not displayed with --csv')
    parser.add_argument('--simple', action='store_true', default=False,
                        help='Suppress verbose output, only show basic '
                             'information')
    parser.add_argument('--csv', action='store_true', default=False,
                        help='Suppress verbose output, only show basic '
                             'information in CSV format. Speeds listed in '
                             'bit/s and not affected by --bytes')
    parser.add_argument('--csv-delimiter', default=',', type=PARSER_TYPE_STR,
                        help='Single character delimiter to use in CSV '
                             'output. Default ","')
    parser.add_argument('--csv-header', action='store_true', default=False,
                        help='Print CSV headers')
    parser.add_argument('--json', action='store_true', default=False,
                        help='Suppress verbose output, only show basic '
                             'information in JSON format. Speeds listed in '
                             'bit/s and not affected by --bytes')
    parser.add_argument('--list', action='store_true',
                        help='Display a list of speedtest.net servers '
                             'sorted by distance')
    parser.add_argument('--server', type=PARSER_TYPE_INT, action='append',
                        help='Specify a server ID to test against. Can be '
                             'supplied multiple times')
    parser.add_argument('--exclude', type=PARSER_TYPE_INT, action='append',
                        help='Exclude a server from selection. Can be '
                             'supplied multiple times')
    parser.add_argument('--mini', help='URL of the Speedtest Mini server')
    parser.add_argument('--source', help='Source IP address to bind to')
    parser.add_argument('--timeout', default=10, type=PARSER_TYPE_FLOAT,
                        help='HTTP timeout in seconds. Default 10')
    parser.add_argument('--secure', action='store_true',
                        help='Use HTTPS instead of HTTP when communicating '
                             'with speedtest.net operated servers')
    parser.add_argument('--no-pre-allocate', dest='pre_allocate',
                        action='store_const', default=True, const=False,
                        help='Do not pre allocate upload data. Pre allocation '
                             'is enabled by default to improve upload '
                             'performance. To support systems with '
                             'insufficient memory, use this option to avoid a '
                             'MemoryError')
    parser.add_argument('--version', action='store_true',
                        help='Show the version number and exit')
    parser.add_argument('--debug', action='store_true',
                        help=ARG_SUPPRESS, default=ARG_SUPPRESS)

    options = parser.parse_args()
    if isinstance(options, tuple):
        args = options[0]
    else:
        args = options
    return args


def validate_optional_args(args):
    """Check if an argument was provided that depends on a module that may
    not be part of the Python standard library.

    If such an argument is supplied, and the module does not exist, exit
    with an error stating which module is missing.
    """
    optional_args = {
        'json': ('json/simplejson python module', json),
        'secure': ('SSL support', HTTPSConnection),
    }

    for arg, info in optional_args.items():
        if getattr(args, arg, False) and info[1] is None:
            raise SystemExit('%s is not installed. --%s is '
                             'unavailable' % (info[0], arg))


def printer(string, quiet=False, debug=False, error=False, **kwargs):
    """Helper function print a string with various features"""

    if debug and not DEBUG:
        return

    if debug:
        if sys.stdout.isatty():
            out = '\033[1;30mDEBUG: %s\033[0m' % string
        else:
            out = 'DEBUG: %s' % string
    else:
        out = string

    if error:
        kwargs['file'] = sys.stderr

    if not quiet:
        print_(out, **kwargs)


def shell():
    """Run the full speedtest.net test"""

    global DEBUG
    shutdown_event = threading.Event()

    signal.signal(signal.SIGINT, ctrl_c(shutdown_event))

    args = parse_args()

    # Print the version and exit
    if args.version:
        version()

    if not args.download and not args.upload:
        raise SpeedtestCLIError('Cannot supply both --no-download and '
                                '--no-upload')

    if len(args.csv_delimiter) != 1:
        raise SpeedtestCLIError('--csv-delimiter must be a single character')

    if args.csv_header:
        csv_header(args.csv_delimiter)

    validate_optional_args(args)

    debug = getattr(args, 'debug', False)
    if debug == 'SUPPRESSHELP':
        debug = False
    if debug:
        DEBUG = True

    if args.simple or args.csv or args.json:
        quiet = True
    else:
        quiet = False

    if args.csv or args.json:
        machine_format = True
    else:
        machine_format = False

    # Don't set a callback if we are running quietly
    if quiet or debug:
        callback = do_nothing
    else:
        callback = print_dots(shutdown_event)

    printer('Retrieving speedtest.net configuration...', quiet)
    try:
        speedtest = Speedtest(
            source_address=args.source,
            timeout=args.timeout,
            secure=args.secure
        )
    except (ConfigRetrievalError,) + HTTP_ERRORS:
        printer('Cannot retrieve speedtest configuration', error=True)
        raise SpeedtestCLIError(get_exception())

    if args.list:
        try:
            speedtest.get_servers()
        except (ServersRetrievalError,) + HTTP_ERRORS:
            printer('Cannot retrieve speedtest server list', error=True)
            raise SpeedtestCLIError(get_exception())

        for _, servers in sorted(speedtest.servers.items()):
            for server in servers:
                line = ('%(id)5s) %(sponsor)s (%(name)s, %(country)s) '
                        '[%(d)0.2f km]' % server)
                try:
                    printer(line)
                except IOError:
                    e = get_exception()
                    if e.errno != errno.EPIPE:
                        raise
        sys.exit(0)

    printer('Testing from %(isp)s (%(ip)s)...' % speedtest.config['client'],
            quiet)

    if not args.mini:
        printer('Retrieving speedtest.net server list...', quiet)
        try:
            speedtest.get_servers(servers=args.server, exclude=args.exclude)
        except NoMatchedServers:
            raise SpeedtestCLIError(
                'No matched servers: %s' %
                ', '.join('%s' % s for s in args.server)
            )
        except (ServersRetrievalError,) + HTTP_ERRORS:
            printer('Cannot retrieve speedtest server list', error=True)
            raise SpeedtestCLIError(get_exception())
        except InvalidServerIDType:
            raise SpeedtestCLIError(
                '%s is an invalid server type, must '
                'be an int' % ', '.join('%s' % s for s in args.server)
            )

        if args.server and len(args.server) == 1:
            printer('Retrieving information for the selected server...', quiet)
        else:
            printer('Selecting best server based on ping...', quiet)
        speedtest.get_best_server()
    elif args.mini:
        speedtest.get_best_server(speedtest.set_mini_server(args.mini))

    results = speedtest.results

    printer('Hosted by %(sponsor)s (%(name)s) [%(d)0.2f km]: '
            '%(latency)s ms' % results.server, quiet)

    if args.download:
        printer('Testing download speed', quiet,
                end=('', '\n')[bool(debug)])
        speedtest.download(
            callback=callback,
            threads=(None, 1)[args.single]
        )
        printer('Download: %0.2f M%s/s' %
                ((results.download / 1000.0 / 1000.0) / args.units[1],
                 args.units[0]),
                quiet)
    else:
        printer('Skipping download test', quiet)

    if args.upload:
        printer('Testing upload speed', quiet,
                end=('', '\n')[bool(debug)])
        speedtest.upload(
            callback=callback,
            pre_allocate=args.pre_allocate,
            threads=(None, 1)[args.single]
        )
        printer('Upload: %0.2f M%s/s' %
                ((results.upload / 1000.0 / 1000.0) / args.units[1],
                 args.units[0]),
                quiet)
    else:
        printer('Skipping upload test', quiet)

    printer('Results:\n%r' % results.dict(), debug=True)

    if not args.simple and args.share:
        results.share()

    if args.simple:
        printer('Ping: %s ms\nDownload: %0.2f M%s/s\nUpload: %0.2f M%s/s' %
                (results.ping,
                 (results.download / 1000.0 / 1000.0) / args.units[1],
                 args.units[0],
                 (results.upload / 1000.0 / 1000.0) / args.units[1],
                 args.units[0]))
    elif args.csv:
        printer(results.csv(delimiter=args.csv_delimiter))
    elif args.json:
        printer(results.json())

    if args.share and not machine_format:
        printer('Share results: %s' % results.share())


def main():
    try:
        shell()
    except KeyboardInterrupt:
        printer('\nCancelling...', error=True)
    except (SpeedtestException, SystemExit):
        e = get_exception()
        # Ignore a successful exit, or argparse exit
        if getattr(e, 'code', 1) not in (0, 2):
            msg = '%s' % e
            if not msg:
                msg = '%r' % e
            raise SystemExit('ERROR: %s' % msg)


if __name__ == '__main__':
    main()
