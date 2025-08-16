import lotorssl, socket


if __name__ == '__main__':
  print('client')
  sock =  lotorssl.Client.Connection('localhost', 7332).get_socket()
  sock.close()
  """
  try:
    sock = lotorssl.connect('127.0.0.1', 9999, bind=False)
    ap, a = lotorssl.genkeypair()
    lotorssl.send(sock, ([str(a[0]), str(a[1])]))
    b0, b1 = map(int, lotorssl.liteval(lotorssl.recv(sock)))

    ash = lotorssl.gensharedsecret(ap, (b0, b1))
    #lotorssl.send(sock, ([str(ash)]))
    
    #g, p, priv = lotorssl.prim(), lotorssl.prim(), lotorssl.prim()

    # Send parameters then send encrypted data
    #lotorssl.send(sock, ([str(g), str(p), str((g ** priv) % p)]))
    #lotorssl.send(sock, lotorssl.crypt("Secret1",
    #  str(((int(lotorssl.recv(sock))) ** priv) % p)))
    sock.close()
    #lotorssl.keypair()
    # (g ** priv) % p = alices public key, g & p shared public values
    # int(lotorssl.recv(sock)) = bobs public key
    # (((int(lotorssl.recv(sock))) ** priv) % p) = shared secret
  except socket.error:
    print('ruh ro')
    #keys()
  """
