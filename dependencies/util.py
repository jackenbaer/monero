import dependencies.ed25519_changed as ed25519
import dependencies.base58
from _pysha3 import keccak_256



def sc_reduce32(n):
    n = int.from_bytes(n, byteorder='little')
    reduced = n % ed25519.l
    newbytes = reduced.to_bytes(32, 'little')
    return newbytes



# Stolen from https://github.com/ymgve/monero_signatures/blob/main/ring_signature_test.py
def sqroot(xx):
    I = pow(2,(ed25519.q-1)//4,ed25519.q)
    x = pow(xx,(ed25519.q+3)//8,ed25519.q)
    if (x*x - xx) % ed25519.q != 0: 
        x = (x*I) % ed25519.q
    if (x*x - xx) % ed25519.q != 0: 
        print("no square root!")
    return x

# changed a little bit from hashToPointCN in mininero, removed unused code etc
def hashToPointCN(inputs):
    u = keccak_256(inputs).digest()
    u = int.from_bytes(u, byteorder='little') % ed25519.q
    
    sqrtm1 = sqroot(-1)
    A = 486662
    
    w = (2 * u * u + 1) % ed25519.q
    xp = (w *  w - 2 * A * A * u * u) % ed25519.q

    #like sqrt (w / x) although may have to check signs..
    #so, note that if a squareroot exists, then clearly a square exists..
    rx = pow(w * ed25519.inv(xp), (ed25519.q+3)//8, ed25519.q) 

    x = (rx**2 * xp) % ed25519.q

    y = (2 * u * u  + 1 - x) % ed25519.q #w - x, if y is zero, then x = w

    negative = False
    if (y != 0):
        y = (w + x) % ed25519.q #checking if you got the negative square root.
        if (y != 0) :
            negative = True
        else :
            rx = rx * -1 * sqroot(-2 * A * (A + 2) ) % ed25519.q
            negative = False
    else :
        #y was 0..
        rx = (rx * -1 * sqroot(2 * A * (A + 2) ) ) % ed25519.q
        
    if not negative:
        rx = (rx * u) % ed25519.q
        z = (-2 * A * u * u)  % ed25519.q
        sign = 0
    else:
        z = -1 * A
        x = x * sqrtm1 % ed25519.q
        y = (w - x) % ed25519.q
        if (y != 0) :
            rx = rx * sqroot( -1 * sqrtm1 * A * (A + 2)) % ed25519.q
        else :
            rx = rx * -1 * sqroot( sqrtm1 * A * (A + 2)) % ed25519.q
        sign = 1
        
    #setsign
    if ( (rx % 2) != sign ):
        rx =  - (rx) % ed25519.q
    rz = (z + w) % ed25519.q
    ry = (z - w) % ed25519.q
    rx = rx * rz % ed25519.q
    
    rzi = ed25519.inv(rz)
    rx = (rx * rzi) % ed25519.q
    ry = (ry * rzi) % ed25519.q
    P = [rx, ry]
    P = ed25519.scalarmult(P, 8)
    # P = ed25519.encodepoint(P)
    return P

