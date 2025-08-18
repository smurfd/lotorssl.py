#!/usr/bin/env python3
from lotorssl.lotorssl import TLS

def test_curve():
  t = TLS()
  print(f'Basepoint: ({hex(t.curve.g[0])}, {hex(t.curve.g[1])})')
  ap, a = t.genkeypair()
  bp, b = t.genkeypair()
  print(f'Alices secret key: {hex(ap)} and public key: ({hex(a[0])}, {hex(a[1])})')
  print(f'Bobs secret key: {hex(bp)} and public key: ({hex(b[0])}, {hex(b[1])})')
  ash = t.gensharedsecret(ap, b)
  bsh = t.gensharedsecret(bp, a)
  print(f'Alices & Bobs shared secrets: {hex(ash[0]), hex(ash[1])} & {hex(bsh[0]), hex(bsh[1])}')
  print(f'Their shared secrets match: {t.verifysharedsecret(ash, bsh, ap, bp)}')
  s = t.sign(bp, 'hai wurld!')
  assert t.verify(b, s, 'hai wurld!')

if __name__ == '__main__':
  print('OK')
