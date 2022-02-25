from __future__ import (absolute_import, print_function, division)
import io
import urllib.request, urllib.parse, urllib.error
import time
import traceback
from . import odict, tcp


class ClientConn(object):

    def __init__(self, address):
        self.address = tcp.Address.wrap(address)


class Flow(object):

    def __init__(self, address, request):
        self.client_conn = ClientConn(address)
        self.request = request


class Request(object):

    def __init__(self, scheme, method, path, headers, content):
        self.scheme, self.method, self.path = scheme, method, path
        self.headers, self.content = headers, content


def date_time_string():
    """Return the current date and time formatted for a message header."""
    WEEKS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    MONTHS = [
        None,
        'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
    ]
    now = time.time()
    year, month, day, hh, mm, ss, wd, y_, z_ = time.gmtime(now)
    s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
        WEEKS[wd],
        day, MONTHS[month], year,
        hh, mm, ss
    )
    return s


class WSGIAdaptor(object):

    def __init__(self, app, domain, port, sversion):
        self.app, self.domain, self.port, self.sversion = app, domain, port, sversion

    def make_environ(self, flow, errsoc, **extra):
        if '?' in flow.request.path:
            path_info, query = flow.request.path.split('?', 1)
        else:
            path_info = flow.request.path
            query = ''
        environ = {
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': flow.request.scheme,
            'wsgi.input': io.StringIO(flow.request.content),
            'wsgi.errors': errsoc,
            'wsgi.multithread': True,
            'wsgi.multiprocess': False,
            'wsgi.run_once': False,
            'SERVER_SOFTWARE': self.sversion,
            'REQUEST_METHOD': flow.request.method,
            'SCRIPT_NAME': '',
            'PATH_INFO': urllib.parse.unquote(path_info),
            'QUERY_STRING': query,
            'CONTENT_TYPE': flow.request.headers.get('Content-Type', [''])[0],
            'CONTENT_LENGTH': flow.request.headers.get('Content-Length', [''])[0],
            'SERVER_NAME': self.domain,
            'SERVER_PORT': str(self.port),
            # FIXME: We need to pick up the protocol read from the request.
            'SERVER_PROTOCOL': "HTTP/1.1",
        }
        environ.update(extra)
        if flow.client_conn.address:
            environ["REMOTE_ADDR"], environ[
                "REMOTE_PORT"] = flow.client_conn.address()

        for key, value in list(flow.request.headers.items()):
            key = 'HTTP_' + key.upper().replace('-', '_')
            if key not in ('HTTP_CONTENT_TYPE', 'HTTP_CONTENT_LENGTH'):
                environ[key] = value
        return environ

    def error_page(self, soc, headers_sent, s):
        """
            Make a best-effort attempt to write an error page. If headers are
            already sent, we just bung the error into the page.
        """
        c = b"""
            <html>
                <h1>Internal Server Error</h1>
                <pre>%s"</pre>
            </html>
        """ % s
        if not headers_sent:
            soc.write(b"HTTP/1.1 500 Internal Server Error\r\n")
            soc.write(b"Content-Type: text/html\r\n")
            soc.write(b"Content-Length: %s\r\n" % len(c))
            soc.write(b"\r\n")
        soc.write(c)

    def serve(self, request, soc, **env):
        state = dict(
            response_started=False,
            headers_sent=False,
            status=None,
            headers=None
        )

        def write(data):
            if not state["headers_sent"]:
                soc.write(b"HTTP/1.1 %s\r\n" % state["status"].encode("utf-8"))
                h = state["headers"]
                if 'server' not in h:
                    h[b"Server"] = [self.sversion.encode("utf-8")]
                if 'date' not in h:
                    h[b"Date"] = [date_time_string().encode("utf-8")]
                soc.write(h.format())
                soc.write(b"\r\n")
                state["headers_sent"] = True
            if data:
                if hasattr(data, 'encode'):
                    soc.write(data.encode('utf-8'))
                else:
                    soc.write(data)
            soc.flush()

        def start_response(status, headers, exc_info=None):
            if exc_info:
                try:
                    if state["headers_sent"]:
                        raise exc_info[0](exc_info[1]).with_traceback(exc_info[2])
                finally:
                    exc_info = None
            elif state["status"]:
                raise AssertionError('Response already started')
            state["status"] = status
            state["headers"] = odict.ODictCaseless(headers)
            return write

        errs = io.BytesIO()
        try:
            dataiter = self.app(
                self.make_environ(request, errs, **env), start_response
            )
            for i in dataiter:
                write(i)
            if not state["headers_sent"]:
                write(b"")
        except Exception:
            try:
                s = traceback.format_exc()
                errs.write(s.encode("utf-8"))
                self.error_page(soc, state["headers_sent"], s.encode('utf-8'))
            except Exception:    # pragma: no cover
                pass
        return errs.getvalue()
