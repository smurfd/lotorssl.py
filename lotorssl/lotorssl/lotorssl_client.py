import lotorssl, socket, random, math

def lotorssl_rand():
  r = 0
  for i in range(0, 5): r = (r << 15) | (random.randint(0, 31337) & 0x7FFF)
  return r & 0xFFFFFFFFFFFFFFFF

def lotorssl_genkeys(g, p):
  priv = lotorssl_rand()
  return priv, pow(g, priv, p)

def lotorssl_genshare(priv1, publ1, priv2, publ2, p, s=False):
  if not s: return p % pow(publ1, priv2)
  else: return p % pow(publ2, priv1)

def lotorssl_crypt(data, s1): # TODO: use actual cryptography
  return data ^ s1

def keys():
  random.seed(31337)
  g1 = lotorssl_rand(); g2 = lotorssl_rand()
  p1 = lotorssl_rand(); p2 = lotorssl_rand()
  c = 123456; d = 0; e = 0

  priv1, pub1 = lotorssl_genkeys(g1, p1)
  priv2, pub2 = lotorssl_genkeys(g2, p2)
  s1 = lotorssl_genshare(priv1, pub1, priv2, pub2, p1, s=False)
  s2 = lotorssl_genshare(priv1, pub1, priv2, pub2, p1, s=True)
  print("Alice public & private key:", hex(pub1), hex(priv1))
  print("Bobs public & private key:", hex(pub2), hex(priv2))
  print("Alice & Bobs shared key:", hex(s1), hex(s2))
  d = lotorssl_crypt(c, s1)
  e = lotorssl_crypt(d, s2)
  assert(c == e)

# Main function
if __name__ == '__main__':
  try:
    sock = lotorssl.connect('127.0.0.1', 9999, bind=False)
    g, p, priv = lotorssl.prim(), lotorssl.prim(), lotorssl.prim()

    # Send parameters then send encrypted data
    lotorssl.send(sock, ([str(g), str(p), str((g ** priv) % p)]))
    lotorssl.send(sock, lotorssl.crypt("Secret1",
      str(((int(lotorssl.recv(sock))) ** priv) % p)))
    sock.close()
    lotorssl.keypair()
    # (g ** priv) % p = alices public key, g & p shared public values
    # int(lotorssl.recv(sock)) = bobs public key
    # (((int(lotorssl.recv(sock))) ** priv) % p) = shared secret
  except socket.error:
    keys()

