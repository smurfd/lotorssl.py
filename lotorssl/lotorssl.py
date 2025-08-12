import secrets, hashlib, math

class curve:                                                              # Secp256k1 Curve parameters
  a = 0                                                                   # Curve coefficients
  b = 7
  h = 1                                                                   # Group cofactor
  g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,  # Base point x, y
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
  n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141    # Group order
  p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f    # Field characteristics

def inverse_mod(k, p):
  if (k == 0): raise ZeroDivisionError('Divison by zero. Not good!')
  elif (k < 0): return p - inverse_mod(-k, p)
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

def on_curve(point):
  if point == None: return True
  if isinstance(point, tuple) and point[0] == 0 and point[1] == 0: return True # represents point is at the infinity
  x, y = point
  return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0

def point_add(R, Q):
  assert on_curve(R)
  assert on_curve(Q)
  if R == None: return Q # if point1 is None, return point2
  elif Q == None: return R # if point2 is None, return point1
  x1, y1 = R
  x2, y2 = Q
  if x1 == 0 and y1 == 0: return Q
  if x2 == 0 and y2 == 0: return R
  if x2 == x1 and y2 == (-y1 % curve.p): return (0, 0)
  if R != Q: m = int(((y2 - y1) * inverse_mod(x2 - x1, curve.p)) % curve.p)
  else: m = int(((3 * x1 ** 2 + curve.a) * inverse_mod(2 * y1, curve.p)) % curve.p)
  x3 = (m * m - x1 - x2) % curve.p
  y3 = -(y1 + m * (x3 - x1) % curve.p)
  return (x3, y3)

def point_mul(r, s, p):
  r0, r1 = (0, 0), r
  for i in range(math.ceil(math.log(s + 1, 2)) - 1, -1, -1):
    if ((s & (1 << i)) >> i) == 0:
      r1 = point_add(r0, r1)
      r0 = point_add(r0, r0)
    else:
      r0 = point_add(r0, r1)
      r1 = point_add(r1, r1)
  return r0

def scalar_mul(k, point):
  if k % curve.n == 0 or point == None: return None
  if k < 0: return scalar_mul(-k, point_neg(point))
  ret, add = None, point
  while k:
    if k & 1: ret = point_add(ret, add)
    add = point_add(add, add)
    k >>= 1
  assert on_curve(ret)
  return ret

def sign(k, msg):
  u = secrets.SystemRandom().randrange(1, curve.n)
  hash1 = int.from_bytes(hashlib.sha256(msg.encode('utf-8')).digest(), 'big')
  while (True):
    p = point_mul(curve.g, u, curve.p)
    c = p[0] % curve.n
    if c == 0: continue
    m = inverse_mod(u, curve.n)
    kc = k * c
    h = kc + hash1
    d = (m * h) % curve.n
    if d == 0: continue
    break
  return (c, d)

def verify(pub, sig, msg):
  hash1 = int.from_bytes(hashlib.sha256(msg.encode('utf-8')).digest(), 'big')
  h = inverse_mod(sig[1], curve.n)
  h1 = (hash1 * h) % curve.n
  h2 = (sig[0] * h) % curve.n
  p1 = scalar_mul(h1, (curve.g[0], curve.g[1]))
  p2 = scalar_mul(h2, pub)
  P = point_add(p1, p2)
  return (P[0] % curve.n) == sig[0]

def genkeypair():
  priv = secrets.SystemRandom().randrange(1, curve.n) - 1
  publ = scalar_mul(priv, (curve.g[0], curve.g[1]))
  return priv, publ

def gensharedsecret(priv, pub):
  return scalar_mul(priv, pub)

def verifysharedsecret(alshr, boshr, alpriv, bopriv):
  priv = (alpriv * bopriv) % curve.n
  r = scalar_mul(priv, (curve.g[0], curve.g[1]))
  return r[0] == alshr[0]


if __name__ == '__main__':
  print(f'Basepoint: ({hex(curve.g[0])}, {hex(curve.g[1])})')
  ap, a = genkeypair()
  bp, b = genkeypair()
  print(f'Alices secret key: {hex(ap)} and public key: ({hex(a[0])}, {hex(a[1])})')
  print(f'Bobs secret key: {hex(bp)} and public key: ({hex(b[0])}, {hex(b[1])})')
  ash = gensharedsecret(ap, b)
  bsh = gensharedsecret(bp, a)
  print(f'Alices & Bobs shared secrets: {hex(ash[0]), hex(ash[1])} & {hex(bsh[0]), hex(bsh[1])}')
  print(f'Their shared secrets match: {verifysharedsecret(ash, bsh, ap, bp)}')
  s = sign(bp, 'hai wurld!')
  assert verify(b, s, 'hai wurld!')

