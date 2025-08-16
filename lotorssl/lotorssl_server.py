import lotorssl, os


# Server loop
def srvloop():
  listenloop(lotorssl.connect('127.0.0.1', 9999, bind=True))

# Loop that listens for connections from the client
def listenloop(sock):
  #shake = False
  while True:
    c, addr = sock.accept()
    shakeloop(c) #, lotorssl.prim())
    #shake = True
    c.close()

# The loop within the loop that handles the handshake
def shakeloop(c, priv=None, shake=False):
  while True:
    if not shake:
      print("hai")
      bp, b = lotorssl.genkeypair()
      #a = lotorssl.recv(c)
      a0, a1 = map(int, lotorssl.liteval(lotorssl.recv(c)))
      lotorssl.send(c, ([str(b[0]), str(b[1])]))     #a)  #([a]))  #([str(a)]))    
      #bsh = map(int, lotorssl.liteval(lotorssl.recv(c)))


      print(a0)
      print(a1)
      ash = lotorssl.gensharedsecret(bp, (a0, a1))
      #print(lotorssl.verifysharedsecret(ash, bsh, bp, bp)) # using same private
      shake = True


      #g, p, ap = map(int, lotorssl.liteval(lotorssl.recv(c)))
      #lotorssl.send(c, str((g ** priv) % p)) # Send bobs public key
    #else: lotorssl.crypt(lotorssl.recv(c, b=True), (ap ** priv) % p); break
    else: pass 

    # Exit after handshake, data is transfered encrypted
    # ap = alices public key, g & p shared public values
    # (g ** priv) % p = bobs public key
    # (ap ** priv) % p = shared secret


# Server
# receive client public key
# send server public key
# receive shared secret

# Main function
if __name__ == '__main__':
  print('server')
  #lotorssl.worker(srvloop)
  lotorssl.Server.Listener('localhost', 7332, lotorssl.Handler.Handler, test=False)
