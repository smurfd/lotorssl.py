#!/usr/bin/env python3
import secrets, hashlib, math, socket, threading, ast, os
import signal, ssl, sys
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
from typing import Union, Any, Self

class Curve:                                                              # Secp256k1 Curve parameters
  a = 0                                                                   # Curve coefficients
  b = 7
  h = 1                                                                   # Group cofactor
  g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,  # Base point x, y
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
  n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141    # Group order
  p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f    # Field characteristics

  def on_curve(self, point):
    if point == None: return True
    if isinstance(point, tuple) and point[0] == 0 and point[1] == 0: return True  # represents that point is going towards infinity
    x, y = point
    return (y * y - x * x * x - self.a * x - self.b) % self.p == 0


class CurveMath(Curve):
  def __init__(self): pass

  def inverse_mod(self, k, p):
    if (k == 0): raise ZeroDivisionError('Divison by zero. Not good!')
    elif (k < 0): return p - self.inverse_mod(self, -k, p)
    r, olr, s, ols, t, olt = p, k, 0, 1, 1, 0
    while (r):
      quot = olr // r
      olr, r = r, olr - (quot * r)
      ols, s = s, ols - (quot * s)
      olt, t = t, olt - (quot * t)
    gcd, x, y = olr, ols, olt
    assert(gcd == 1)
    assert((k * x) % p == 1)
    return x % p


class PointMath(CurveMath):
  def __init__(self): pass

  def point_add(self, R, Q):
    assert Curve.on_curve(Curve, R)
    assert Curve.on_curve(Curve, Q)
    if R == None: return Q # if point1 is None, return point2
    elif Q == None: return R # if point2 is None, return point1
    x1, y1 = R
    x2, y2 = Q
    if x1 == 0 and y1 == 0: return Q
    if x2 == 0 and y2 == 0: return R
    if x2 == x1 and y2 == (-y1 % Curve.p): return (0, 0)
    if R != Q: m = int(((y2 - y1) * self.inverse_mod(self, x2 - x1, Curve.p)) % Curve.p)
    else: m = int(((3 * x1 ** 2 + Curve.a) * self.inverse_mod(self, 2 * y1, Curve.p)) % Curve.p)
    x3 = (m * m - x1 - x2) % Curve.p
    y3 = -(y1 + m * (x3 - x1) % Curve.p)
    return (x3, y3)

  def point_mul(self, r, s, p):
    r0, r1 = (0, 0), r
    for i in range(math.ceil(math.log(s + 1, 2)) - 1, -1, -1):
      if ((s & (1 << i)) >> i) == 0:
        r1 = PointMath.point_add(self, r0, r1)
        r0 = PointMath.point_add(self, r0, r0)
      else:
        r0 = PointMath.point_add(self, r0, r1)
        r1 = PointMath.point_add(self, r1, r1)
    return r0

  def scalar_mul(self, k, point):
    if k % Curve.n == 0 or point == None: return None
    if k < 0: return self.scalar_mul(self, -k, point_neg(point))
    ret, add = None, point
    while k:
      if k & 1: ret = PointMath.point_add(self, ret, add)
      add = PointMath.point_add(self, add, add)
      k >>= 1
    assert Curve.on_curve(Curve, ret)
    return ret


class Handler:
  # Would we need different handlings for Test server, we create copies of these and use in Server class
  class Handler(StreamRequestHandler):
    def handle(self):
      print('lotorssl handler') # TODO: do stuff

class Server(threading.Thread):
  class TCPServerSSL(TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
      TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
      TCPServer.allow_reuse_address = True

    def get_request(self):
      newsocket, fromaddr = self.socket.accept()
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # TODO: use our own instead
      ctx.load_cert_chain('.lib/selfsigned.cert', '.lib/selfsigned.key')
      return ctx.wrap_socket(sock=newsocket, server_side=True), fromaddr

  class ThreadingTCPServerSSL(ThreadingMixIn, TCPServerSSL):
    pass

  class ServiceExit(Exception):
    pass

  class Listener:
    def __init__(self, host, port, handler=None, test=False) -> None:
      self.server = Server.ThreadingTCPServerSSL((host, port), handler)
      self.server_thread = threading.Thread(target=self.server.serve_forever)
      self.server_thread.daemon = True if test else False
      self.server_thread.start()

    def __exit__(self) -> None:
      self.server.shutdown()
      self.server.socket.close()
      self.server.server_close()
      self.server_thread.join()

  def __init__(self, dbmaster: bool = True, dbnode: int = 0, test: bool = False, dbtype: Union[bool, str] = False) -> None:
    signal.signal(signal.SIGTERM, self.service_shutdown)
    signal.signal(signal.SIGINT, self.service_shutdown)
    threading.Thread.__init__(self)
    self.sock: Union[socket.socket, Any] = None
    self.ssl_sock: Union[socket.socket, Any] = None
    self.context: Union[ssl.SSLContext, Any] = None
    self.event = threading.Event()
    self.test: bool = test
    self.type: Union[bool, str] = dbtype
    self.thread = threading.Thread()
    try:
      self.thread.start()
      self.start()
    except self.ServiceExit:
      self.event.set()
      self.thread.join()
      self.close()

  def __exit__(self, exc_type, exc_value, traceback) -> None:
    self.close()

  def close(self) -> None:
    self.ssl_sock.close()

  def service_shutdown(self, signum, frame) -> None:
    raise self.ServiceExit


class Client(threading.Thread):
  class Connection:
    def __init__(self, host, port):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) # TODO: use own instead
      ctx.load_verify_locations('.lib/selfsigned.cert')
      self.ssl_sock = ctx.wrap_socket(s, server_hostname='localhost')
      self.ssl_sock.connect((host, port))

    def get_socket(self):
      return self.ssl_sock

  def __init__(self, dbhost: str = 'localhost', dbport: int = 1337, dbmaster: bool = True, dbnode: int = 0, dbtype: Union[bool, str] = False) -> None:
    threading.Thread.__init__(self, group=None)
    #self.client = Union[None, Client]
    self.event = threading.Event()
    self.host: str = dbhost
    self.port: int = dbport
    self.sock: Union[socket.socket, Any] = None
    self.type: Union[bool, str] = dbtype
    self.key: Union[None, Keys] = None
    #self.tables: Union[None, Tables] = None
    self.thread = threading.Thread()

  def send(self, data: bytes) -> None:
    self.sock.send(data) if self.sock else None

  def receive(self, data: int) -> None:
    self.sock.recv(data) if self.sock else None

class TLS:
  def sign(k, msg):
    u = secrets.SystemRandom().randrange(1, Curve.n)
    hash1 = int.from_bytes(hashlib.sha256(msg.encode('utf-8')).digest(), 'big')
    while (True):
      p = PointMath.point_mul(PointMath, Curve.g, u, Curve.p)
      c = p[0] % Curve.n
      if c == 0: continue
      m = CurveMath.inverse_mod(CurveMath, u, Curve.n)
      kc = k * c
      h = kc + hash1
      d = (m * h) % Curve.n
      if d == 0: continue
      break
    return (c, d)

  def verify(pub, sig, msg):
    hash1 = int.from_bytes(hashlib.sha256(msg.encode('utf-8')).digest(), 'big')
    h = CurveMath.inverse_mod(CurveMath, sig[1], Curve.n)
    h1 = (hash1 * h) % Curve.n
    h2 = (sig[0] * h) % Curve.n
    p1 = PointMath.scalar_mul(PointMath, h1, (Curve.g[0], Curve.g[1]))
    p2 = PointMath.scalar_mul(PointMath, h2, pub)
    P = PointMath.point_add(PointMath, p1, p2)
    return (P[0] % Curve.n) == sig[0]

  def genkeypair():
    priv = secrets.SystemRandom().randrange(1, Curve.n) - 1
    publ = PointMath.scalar_mul(CurveMath, priv, (Curve.g[0], Curve.g[1]))
    return priv, publ

  def gensharedsecret(priv, pub):
    return PointMath.scalar_mul(CurveMath, priv, pub)

  def verifysharedsecret(alshr, boshr, alpriv, bopriv):
    priv = (alpriv * bopriv) % Curve.n
    r = PointMath.scalar_mul(CurveMath, priv, (Curve.g[0], Curve.g[1]))
    return r[0] == alshr[0]


# Handle connection and binding (client/server) and return the socket
def connect(host, port, bind=False):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  if bind == False: sock.connect((host, port)) #Client
  else: sock.bind((host, port)); sock.listen(5) # Server
  return sock

# Get a string value of the datalength, if byte we add 3 chrs for b''
def datalen(data):
  if type(data) is bytes: return str(len(data) + 3)
  return str(len(str(data)))

# Send a header with 64 bytes, which holds the length of the data & then data
def send(sock, data):
  # Fill the header with spaces to contain the exact number of 64 bytes
  hdr = "".join(" " for i in range(0, 64 - len(datalen(data)))) + datalen(data)
  sock.send(str(hdr).encode())
  sock.send(str(data).encode())

# Receive a header with 64 bytes, which holds the length of the data & then data
def recv(sock, b=False):
  rec = int(sock.recv(64).decode()) # Receive "header" containing msg length
  if b is True: return sock.recv(rec).decode()
  else: return sock.recv(rec)

# Thread loop catching possible Ctrl + c keys to break the server loop
def work(thrd):
  while thrd.is_alive():
    try: thrd.join(timeout=0.1)
    except (KeyboardInterrupt, SystemExit): threading.Event().set(); os._exit(9)

# Thread worker
def worker(fnc):
  t = threading.Thread(target=fnc, name=fnc)
  t.start()
  work(t)

# Return the byte map
def liteval(b):
  return ast.literal_eval(b.decode())



if __name__ == '__main__':
  print(f'Basepoint: ({hex(Curve.g[0])}, {hex(Curve.g[1])})')
  ap, a = TLS.genkeypair()
  bp, b = TLS.genkeypair()
  print(f'Alices secret key: {hex(ap)} and public key: ({hex(a[0])}, {hex(a[1])})')
  print(f'Bobs secret key: {hex(bp)} and public key: ({hex(b[0])}, {hex(b[1])})')
  ash = TLS.gensharedsecret(ap, b)
  bsh = TLS.gensharedsecret(bp, a)
  print(f'Alices & Bobs shared secrets: {hex(ash[0]), hex(ash[1])} & {hex(bsh[0]), hex(bsh[1])}')
  print(f'Their shared secrets match: {TLS.verifysharedsecret(ash, bsh, ap, bp)}')
  s = TLS.sign(bp, 'hai wurld!')
  assert TLS.verify(b, s, 'hai wurld!')

