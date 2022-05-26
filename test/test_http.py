import io
import textwrap
import binascii
from netlib import http, odict, tcp
from . import tutils, tservers


def test_httperror():
    e = http.HttpError(404, "Not found")
    assert str(e)


def test_has_chunked_encoding():
    h = odict.ODictCaseless()
    assert not http.has_chunked_encoding(h)
    h["transfer-encoding"] = ["chunked"]
    assert http.has_chunked_encoding(h)


def test_read_chunked():

    h = odict.ODictCaseless()
    h["transfer-encoding"] = ["chunked"]
    s = io.BytesIO(b"1\r\na\r\n0\r\n")

    tutils.raises(
        "malformed chunked body",
        http.read_http_body,
        s, h, None, "GET", None, True
    )

    s = io.BytesIO(b"1\r\na\r\n0\r\n\r\n")
    assert http.read_http_body(s, h, None, "GET", None, True) == b"a"

    s = io.BytesIO(b"\r\n\r\n1\r\na\r\n0\r\n\r\n")
    assert http.read_http_body(s, h, None, "GET", None, True) == b"a"

    s = io.BytesIO(b"\r\n")
    tutils.raises(
        "closed prematurely",
        http.read_http_body,
        s, h, None, "GET", None, True
    )

    s = io.BytesIO(b"1\r\nfoo")
    tutils.raises(
        "malformed chunked body",
        http.read_http_body,
        s, h, None, "GET", None, True
    )

    s = io.BytesIO(b"foo\r\nfoo")
    tutils.raises(
        http.HttpError,
        http.read_http_body,
        s, h, None, "GET", None, True
    )

    s = io.BytesIO(b"5\r\naaaaa\r\n0\r\n\r\n")
    tutils.raises("too large", http.read_http_body, s, h, 2, "GET", None, True)


def test_connection_close():
    h = odict.ODictCaseless()
    assert http.connection_close((1, 0), h)
    assert not http.connection_close((1, 1), h)

    h["connection"] = ["keep-alive"]
    assert not http.connection_close((1, 1), h)

    h["connection"] = ["close"]
    assert http.connection_close((1, 1), h)


def test_get_header_tokens():
    h = odict.ODictCaseless()
    assert http.get_header_tokens(h, "foo") == []
    h["foo"] = ["bar"]
    assert http.get_header_tokens(h, "foo") == ["bar"]
    h["foo"] = ["bar, voing"]
    assert http.get_header_tokens(h, "foo") == ["bar", "voing"]
    h["foo"] = ["bar, voing", "oink"]
    assert http.get_header_tokens(h, "foo") == ["bar", "voing", "oink"]


def test_read_http_body_request():
    h = odict.ODictCaseless()
    r = io.StringIO("testing")
    assert http.read_http_body(r, h, None, "GET", None, True) == b""


def test_read_http_body_response():
    h = odict.ODictCaseless()
    s = tcp.Reader(io.BytesIO(b"testing"))
    assert http.read_http_body(s, h, None, "GET", 200, False) == b"testing"


def test_read_http_body():
    # test default case
    h = odict.ODictCaseless()
    h[b"content-length"] = [7]
    s = io.BytesIO(b"testing")
    assert http.read_http_body(s, h, None, "GET", 200, False) == b"testing"

    # test content length: invalid header
    h[b"content-length"] = ["foo"]
    s = io.BytesIO(b"testing")
    tutils.raises(
        http.HttpError,
        http.read_http_body,
        s, h, None, "GET", 200, False
    )

    # test content length: invalid header #2
    h[b"content-length"] = [-1]
    s = io.BytesIO(b"testing")
    tutils.raises(
        http.HttpError,
        http.read_http_body,
        s, h, None, "GET", 200, False
    )

    # test content length: content length > actual content
    h[b"content-length"] = [5]
    s = io.BytesIO(b"testing")
    tutils.raises(
        http.HttpError,
        http.read_http_body,
        s, h, 4, "GET", 200, False
    )

    # test content length: content length < actual content
    s = io.BytesIO(b"testing")
    assert len(http.read_http_body(s, h, None, "GET", 200, False)) == 5

    # test no content length: limit > actual content
    h = odict.ODictCaseless()
    s = tcp.Reader(io.BytesIO(b"testing"))
    assert len(http.read_http_body(s, h, 100, "GET", 200, False)) == 7

    # test no content length: limit < actual content
    s = tcp.Reader(io.BytesIO(b"testing"))
    tutils.raises(
        http.HttpError,
        http.read_http_body,
        s, h, 4, "GET", 200, False
    )

    # test chunked
    h = odict.ODictCaseless()
    h["transfer-encoding"] = ["chunked"]
    s = tcp.Reader(io.BytesIO(b"5\r\naaaaa\r\n0\r\n\r\n"))
    assert http.read_http_body(s, h, 100, "GET", 200, False) == b"aaaaa"


def test_expected_http_body_size():
    # gibber in the content-length field
    h = odict.ODictCaseless()
    h[b"content-length"] = ["foo"]
    assert http.expected_http_body_size(h, False, "GET", 200) is None
    # negative number in the content-length field
    h = odict.ODictCaseless()
    h[b"content-length"] = ["-7"]
    assert http.expected_http_body_size(h, False, "GET", 200) is None
    # explicit length
    h = odict.ODictCaseless()
    h[b"content-length"] = ["5"]
    assert http.expected_http_body_size(h, False, "GET", 200) == 5
    # no length
    h = odict.ODictCaseless()
    assert http.expected_http_body_size(h, False, "GET", 200) == -1
    # no length request
    h = odict.ODictCaseless()
    assert http.expected_http_body_size(h, True, "GET", None) == 0


def test_parse_http_protocol():
    assert http.parse_http_protocol(b"HTTP/1.1") == (1, 1)
    assert http.parse_http_protocol(b"HTTP/0.0") == (0, 0)
    assert not http.parse_http_protocol(b"HTTP/a.1")
    assert not http.parse_http_protocol(b"HTTP/1.a")
    assert not http.parse_http_protocol(b"foo/0.0")
    assert not http.parse_http_protocol(b"HTTP/x")


def test_parse_init_connect():
    assert http.parse_init_connect(b"CONNECT host.com:443 HTTP/1.0")
    assert not http.parse_init_connect(b"C\xfeONNECT host.com:443 HTTP/1.0")
    assert not http.parse_init_connect(b"CONNECT \0host.com:443 HTTP/1.0")
    assert not http.parse_init_connect(b"CONNECT host.com:444444 HTTP/1.0")
    assert not http.parse_init_connect(b"bogus")
    assert not http.parse_init_connect(b"GET host.com:443 HTTP/1.0")
    assert not http.parse_init_connect(b"CONNECT host.com443 HTTP/1.0")
    assert not http.parse_init_connect(b"CONNECT host.com:443 foo/1.0")
    assert not http.parse_init_connect(b"CONNECT host.com:foo HTTP/1.0")


def test_parse_init_proxy():
    u = b"GET http://foo.com:8888/test HTTP/1.1"
    m, s, h, po, pa, httpversion = http.parse_init_proxy(u)
    assert m == b"GET"
    assert s == b"http"
    assert h == b"foo.com"
    assert po == 8888
    assert pa == b"/test"
    assert httpversion == (1, 1)

    u = b"G\xfeET http://foo.com:8888/test HTTP/1.1"
    assert not http.parse_init_proxy(u)

    assert not http.parse_init_proxy(b"invalid")
    assert not http.parse_init_proxy(b"GET invalid HTTP/1.1")
    assert not http.parse_init_proxy(b"GET http://foo.com:8888/test foo/1.1")


def test_parse_init_http():
    u = b"GET /test HTTP/1.1"
    m, u, httpversion = http.parse_init_http(u)
    assert m == b"GET"
    assert u == b"/test"
    assert httpversion == (1, 1)

    u = b"G\xfeET /test HTTP/1.1"
    assert not http.parse_init_http(u)

    assert not http.parse_init_http(b"invalid")
    assert not http.parse_init_http(b"GET invalid HTTP/1.1")
    assert not http.parse_init_http(b"GET /test foo/1.1")
    assert not http.parse_init_http(b"GET /test\xc0 HTTP/1.1")


class TestReadHeaders:

    def _read(self, data, verbatim=False):
        if not verbatim:
            data = textwrap.dedent(data.decode("utf-8"))
            data = data.strip().encode("utf-8")
        s = io.BytesIO(data)
        return http.read_headers(s)

    def test_read_simple(self):
        data = b"""
            Header: one
            Header2: two
            \r\n
        """
        h = self._read(data)
        assert h.lst == [[b"Header", b"one"], [b"Header2", b"two"]]

    def test_read_multi(self):
        data = b"""
            Header: one
            Header: two
            \r\n
        """
        h = self._read(data)
        assert h.lst == [[b"Header", b"one"], [b"Header", b"two"]]

    def test_read_continued(self):
        data = b"""
            Header: one
            \ttwo
            Header2: three
            \r\n
        """
        h = self._read(data)
        assert h.lst == [[b"Header", b"one\r\n two"], [b"Header2", b"three"]]

    def test_read_continued_err(self):
        data = b"\tfoo: bar\r\n"
        assert self._read(data, True) is None

    def test_read_err(self):
        data = b"""
            foo
        """
        assert self._read(data) is None


class NoContentLengthHTTPHandler(tcp.BaseHandler):

    def handle(self):
        self.wfile.write(b"HTTP/1.1 200 OK\r\n\r\nbar\r\n\r\n")
        self.wfile.flush()

class TestReadResponseNoContentLength(tservers.ServerTestBase):

    handler = NoContentLengthHTTPHandler

    def test_no_content_length(self):
        c = tcp.TCPClient(("127.0.0.1", self.port))
        c.connect()
        resp = http.read_response(c.rfile, "GET", None)
        assert resp.content == b"bar\r\n\r\n"


def test_read_response():
    def tst(data, method, limit, include_body=True):
        data = textwrap.dedent(data).encode("utf-8")
        r = io.BytesIO(data)
        return http.read_response(
            r, method, limit, include_body=include_body
        )

    tutils.raises("server disconnect", tst, "", "GET", None)
    tutils.raises("invalid server response", tst, "foo", "GET", None)
    data = """
        HTTP/1.1 200 OK
    """
    assert tst(data, b"GET", None) == (
        (1, 1), 200, b'OK', odict.ODictCaseless(), b''
    )
    data = """
        HTTP/1.1 200
    """
    assert tst(data, "GET", None) == (
        (1, 1), 200, b'', odict.ODictCaseless(), b''
    )
    data = """
        HTTP/x 200 OK
    """
    tutils.raises("invalid http version", tst, data, "GET", None)
    data = """
        HTTP/1.1 xx OK
    """
    tutils.raises("invalid server response", tst, data, "GET", None)

    data = """
        HTTP/1.1 100 CONTINUE

        HTTP/1.1 200 OK
    """
    assert tst(data, "GET", None) == (
        (1, 1), 100, b'CONTINUE', odict.ODictCaseless(), b''
    )

    data = """
        HTTP/1.1 200 OK
        Content-Length: 3

        foo
    """
    assert tst(data, "GET", None)[4] == b'foo'
    assert tst(data, "HEAD", None)[4] == b''

    data = """
        HTTP/1.1 200 OK
        \tContent-Length: 3

        foo
    """
    tutils.raises("invalid headers", tst, data, "GET", None)

    data = """
        HTTP/1.1 200 OK
        Content-Length: 3

        foo
    """
    assert tst(data, "GET", None, include_body=False)[4] is None


def test_parse_url():
    assert not http.parse_url("")

    u = b"http://foo.com:8888/test"
    s, h, po, pa = http.parse_url(u)
    assert s == b"http"
    assert h == b"foo.com"
    assert po == 8888
    assert pa == b"/test"

    s, h, po, pa = http.parse_url(b"http://foo/bar")
    assert s == b"http"
    assert h == b"foo"
    assert po == 80
    assert pa == b"/bar"

    s, h, po, pa = http.parse_url(b"http://user:pass@foo/bar")
    assert s == b"http"
    assert h == b"foo"
    assert po == 80
    assert pa == b"/bar"

    s, h, po, pa = http.parse_url(b"http://foo")
    assert pa == b"/"

    s, h, po, pa = http.parse_url(b"https://foo")
    assert po == 443

    assert not http.parse_url(b"https://foo:bar")
    assert not http.parse_url(b"https://foo:")

    # Invalid IDNA
    assert not http.parse_url(b"http://\xfafoo")
    # Invalid PATH
    assert not http.parse_url(b"http:/\xc6/localhost:56121")
    # Null byte in host
    assert not http.parse_url(b"http://foo\0")
    # Port out of range
    assert not http.parse_url(b"http://foo:999999")
    # Invalid IPv6 URL - see http://www.ietf.org/rfc/rfc2732.txt
    assert not http.parse_url(b'http://lo[calhost')


def test_parse_http_basic_auth():
    vals = (b"basic", b"foo", b"bar")
    assert http.parse_http_basic_auth(
        http.assemble_http_basic_auth(*vals)
    ) == vals
    assert not http.parse_http_basic_auth(b"")
    assert not http.parse_http_basic_auth(b"foo bar")
    v = b"basic " + binascii.b2a_base64(b"foo")
    assert not http.parse_http_basic_auth(v)


def test_get_request_line():
    r = io.BytesIO(b"\nfoo")
    assert http.get_request_line(r) == b"foo"
    assert not http.get_request_line(r)


class TestReadRequest():

    def tst(self, data, **kwargs):
        r = io.BytesIO(data)
        return http.read_request(r, **kwargs)

    def test_invalid(self):
        tutils.raises(
            "bad http request",
            self.tst,
            b"xxx"
        )
        tutils.raises(
            "bad http request line",
            self.tst,
            b"get /\xff HTTP/1.1"
        )
        tutils.raises(
            "invalid headers",
            self.tst,
            b"get / HTTP/1.1\r\nfoo"
        )
        tutils.raises(
            tcp.NetLibDisconnect,
            self.tst,
            b"\r\n"
        )

    def test_asterisk_form_in(self):
        v = self.tst(b"OPTIONS * HTTP/1.1")
        assert v.form_in == "relative"
        assert v.method == "OPTIONS"

    def test_absolute_form_in(self):
        tutils.raises(
            "Bad HTTP request line",
            self.tst,
            b"GET oops-no-protocol.com HTTP/1.1"
        )
        v = self.tst(b"GET http://address:22/ HTTP/1.1")
        assert v.form_in == "absolute"
        assert v.port == 22
        assert v.host == "address"
        assert v.scheme == "http"

    def test_connect(self):
        tutils.raises(
            "Bad HTTP request line",
            self.tst,
            b"CONNECT oops-no-port.com HTTP/1.1"
        )
        v = self.tst(b"CONNECT foo.com:443 HTTP/1.1")
        assert v.form_in == "authority"
        assert v.method == "CONNECT"
        assert v.port == 443
        assert v.host == "foo.com"

    def test_expect(self):
        w = io.BytesIO()
        r = io.BytesIO(
            b"GET / HTTP/1.1\r\n"
            b"Content-Length: 3\r\n"
            b"Expect: 100-continue\r\n\r\n"
            b"foobar",
        )
        v = http.read_request(r, wfile=w)
        assert w.getvalue() == b"HTTP/1.1 100 Continue\r\n\r\n"
        assert v.content == b"foo"
        assert r.read(3) == b"bar"
