import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
import requests
from tabulate import tabulate  # for beutiful printing
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
import itertools
import testString

dictt = {'content-type': 'text/html'}
first_request = 0
my_csrf_tokes = []
same = 0
diff = 0

def colortext(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


# shallow_compare is faster but less accurate
# for more good measure send in the "shallow_compare" ="False"
def compare_res(res_original, res_modified, shallow_compare):
    global same, diff
    if dictt['content-type'].find('text/html') != -1:
        soup1 = BeautifulSoup(res_original, "lxml")  # if you pass a string remove the open function
        soup2 = BeautifulSoup(res_modified, "lxml")  # if you pass a string remove the open function
        collection1 = soup1.stripped_strings
        collection2 = soup2.stripped_strings
        if shallow_compare is False:
            l1 = list(collection1)
            l2 = list(collection2)
            l1_size = len(l1)
            l2_size = len(l2)
            if l1_size < l2_size:
                for item in l1:
                    max_similar = -(1.0)
                    for i in l2:
                        if similar(i, item) == 1.0:
                            item2 = i
                            max_similar = 1
                            break
                        if max_similar == -1 and similar(i, item) > 0.8:
                            item2 = i
                            max_similar = similar(i, item)
                        elif similar(i, item) > max_similar and similar(i, item) > 0.8:
                            item2 = i
                    if max_similar != -1:
                        same += 1
                        l2.remove(item2)
                    else:
                        diff += 1
            else:
                for item in l2:
                    max_similar = -(1.0)
                    for i in l1:
                        if similar(i, item) == 1.0:
                            item2 = i
                            max_similar = 1
                            break
                        if max_similar == -1 and similar(i, item) > 0.8:
                            item2 = i
                            max_similar = similar(i, item)
                        elif similar(i, item) > max_similar:
                            item2 = i
                    if max_similar != -1:
                        same += 1
                        l1.remove(item2)
                    else:
                        diff += 1
            if diff == 0:
                return 1  # we got a match
            elif same > diff:
                return (diff/same)*100  # suspected
            else:
                return 0  # we didnt got a match
        else:
            for (str1, str2) in itertools.izip_longest(collection1, collection2):
                if similar(str1, str2) > 0.6:
                    same += 1
                else:
                    diff += 1
            if diff == 0:
                return 1  # we got a match
            elif same > diff:
                return (diff/same)*100  # suspected
            else:
                return 0  # we didnt got a match

    else:
        rate = similar(res_modified, res_original)
        if rate > 0.9:
            return 1  # we got a match
        elif rate > 0.6:
            return rate*100  # suspected
        else:
            return 0  # we didnt got a match.


def get_html_only(res):
    return res[res.find('<html'):res.find('</html>')]


def similar(a, b):
    if a is None or b is None:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


modified_header_static = {}
class AuthorizationCMain():

    @staticmethod
    def dict_to_lower(dictionary):
            d = {}
            for key in dictionary:
                d[str(key).lower()] = dictionary[key]
            return d

    # 0,3=bypass ,1,4 =unknown ,2,5 =enforce( the same and not bypass)
    def check_bypass(self, url, original_header, modified_header, command, res_body, params={}):
        global modified_header_static, first_request, my_csrf_tokes

        def del_cookie(mhwc):
            try:
                del mhwc['cookie']
            except:
                pass

        def replace_cookie(src, dest):
            for key in src:
                dest[str(key).lower()] = src[key]

        def check_response(r1, r2, r3):
            status_without = ''
            statusModify = ''
            if r1.status_code == r3.status_code:
                if len(r1.content) == len(r3.content):
                    status_without = colortext(31, ' BYPASS')
                else:
                    c_ = compare_res(r1.content, r3.content, True)  # TODO: possible added: filters support's
                    if c_ == 0:
                        status_without = colortext(32, ' OK')
                    elif c_ == 1:
                        status_without = colortext(31, ' BYPASS')
                    else:
                        status_without = colortext(33, ' SUSPECTED' + str(c_) + '%rate diffrent')
            else:
                status_without = colortext(32, ' OK')
            # the check am self
            if r1.status_code == r2.status_code:
                if len(r1.content) == len(r2.content):
                    statusModify = colortext(31, ' BYPASS')
                else:
                    # TODO: posiible added: filters supprot's
                    c_ = compare_res(r1.content, r2.content, True)
                    if c_ == 0:
                        statusModify = colortext(32, ' OK')
                    elif c_ == 1:
                        statusModify = colortext(31, ' BYPASS')
                    else:
                        statusModify = colortext(33, ' SUSPECTED' + str(c_) + '%rate diffrent')
            else:
                statusModify = colortext(32, ' OK')
            return [status_without, statusModify]

         # if this is the first time , we need to add the tokens to the list.

        if first_request == 0:
            first_request += 1

            _modified_header = AuthorizationCMain.dict_to_lower(original_header.copy())  # taking care of the header
            _modified_header_without_cookie = AuthorizationCMain.dict_to_lower(original_header.copy())  # for check without 'Cookies'

            del_cookie(_modified_header_without_cookie)  # remove the cookie from the req
            replace_cookie(modified_header, _modified_header)  # replace with user supplied cookies.

            if command == 'POST':
                r11 = requests.post(url, headers=original_header, data=params)
                r21 = requests.post(url, headers=_modified_header, data=params)
                r31 = requests.post(url, headers=_modified_header_without_cookie, data=params)
            else:
                r11 = requests.get(url, headers=original_header, params=params)
                r21 = requests.get(url, headers=_modified_header, params=params)
                r31 = requests.get(url, headers=_modified_header_without_cookie, params=params)

            array_of_tokens = testString.find_diff_str(r11.content, res_body)
            if array_of_tokens is None:
                first_request -= 1
            else:
                my_csrf_tokes.append(array_of_tokens)
            return check_response(r11, r21, r31)  # check for by pass in the result and print it.
        else:

            _modified_header = AuthorizationCMain.dict_to_lower(original_header.copy())  # taking care of the header
            _modified_header_without_cookie = AuthorizationCMain.dict_to_lower(original_header.copy())  # for check without 'Cookies'

            del_cookie(_modified_header_without_cookie)  # remove the cookie from the req
            replace_cookie(modified_header, _modified_header)  # replace with user supplied cookies.

            i = 0  # flag , did we find any match in tokens.
            for arr in my_csrf_tokes:
                for key, value in params.iteritems():
                    if value == arr[0]:
                        params[key] = arr[1]
                        i += 1
                        if command == 'POST':
                            r11 = requests.post(url, headers=original_header, data=params)
                            r21 = requests.post(url, headers=_modified_header, data=params)
                            r31 = requests.post(url, headers=_modified_header_without_cookie, data=params)
                        else:
                            r11 = requests.get(url, headers=original_header, params=params)
                            r21 = requests.get(url, headers=_modified_header, params=params)
                            r31 = requests.get(url, headers=_modified_header_without_cookie, params=params)
                        array_of_tokens = testString.find_diff_str(r11.content, res_body)
                        if array_of_tokens is not None:
                            my_csrf_tokes.append(array_of_tokens)

                        a = check_response(r11, r21, r31)  # check for by pass in the result and print it.
                        if a[0] == colortext(32, ' OK'):
                            return a
            if i == 0:
                if command == 'POST':
                    r11 = requests.post(url, headers=original_header, data=params)
                    r21 = requests.post(url, headers=_modified_header, data=params)
                    r31 = requests.post(url, headers=_modified_header_without_cookie, data=params)
                else:
                    r11 = requests.get(url, headers=original_header, params=params)
                    r21 = requests.get(url, headers=_modified_header, params=params)
                    r31 = requests.get(url, headers=_modified_header_without_cookie, params=params)
                array_of_tokens = testString.find_diff_str(r11.content, res_body)
                if array_of_tokens is not None:
                    my_csrf_tokes.append(array_of_tokens)
                return check_response(r11, r21, r31)  # check for by pass in the result and print it.

    def printToScreen(self, uri, command, params, statusW, statusM):
        print("-----------------------------------------\n")
        print("COMMAND:%s\n"%command)
        print("URI:%s"%uri)
        print("PARAMS:%s\n"%params)
        print("status modified:%s\n"%statusM)
        print("status noCookies:%s\n"%statusW)
        print("-----------------------------------------\n")

    def mainCheck(self, url, Header, command, params, res_body):
        global modified_header_static
        check = self.check_bypass(url, Header, modified_header_static, command, res_body, params)
        self.printToScreen(url,command,params,check[0],check[1])

    def initialization(self):
        global modified_header_static
        modified_header_static = self.GetHeaderByInput()
        print(tabulate([], ['                DATA               '], tablefmt="orgtbl"))


    #ask for input from the user. return dict of headers.
    def GetHeaderByInput(self):
        sentinel = ''
        a = {}
        for line in iter(raw_input, sentinel):
            try:
                key,value=line.split(':')
                a[key] = value
            except:
                pass #maybe its the command like'GET/HTTP 1.1
        return a

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1":
            self.close_connection = 0

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://get.cert/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        req_headers = self.filter_headers(req.headers)

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req_headers))
            res = conn.getresponse()
            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
        setattr(res, 'headers', res.msg)
        setattr(res, 'response_version', version_table[res.version])

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        res_headers = self.filter_headers(res.headers)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res_headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    do_HEAD = do_GET
    do_POST = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def request_handler(self, req, req_body):
       pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        params = {}  # handle the params to dict's
        #print "blabla --- ",res_body
        if req_body is None:
            pass
        else:
            for k in req_body.split('&'):
                try:
                    key, value = k.split('=')
                    params[key] = value
                except:
                    print("ERROR IN THE PARAMS REQUEST")
                    exit(1)
        AuthorizationCMain().mainCheck(req.path, req.headers.__dict__['dict'], str(req.command), params, res_body)


def main():

    HandlerClass = ProxyRequestHandler
    ServerClass = ThreadingHTTPServer
    protocol = "HTTP/1.1"
    port = 3128
    server_address = ('', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print("[+]Serving HTTP Proxy on", sa[0], "port", sa[1], "...")
    print("enter the modify header:\n")
    AuthorizationCMain().initialization()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("force_to_EXIT[maybe keyboard]\r\nexit")
        exit(1)

if __name__ == '__main__':
    main()