from dependencies.util import *
import dependencies.ed25519_changed as ed25519
import dependencies.base58 as base58
from _pysha3 import keccak_256


class Key:
    def __init__(self):
        self.private = b""
        self.public = b""

    def from_hex(self, hex_string):
        self.private = bytes.fromhex(hex_string)
        self.public = ed25519.publickey(self.private)

    def show(self):
        print("private: ", self.private.hex())
        print("public:  ", self.public.hex())



def calc_address(A: bytes, B: bytes):
    """
    Args:
        A: bytes; public view key
        B: bytes; public spend key 
    """

    data = bytearray([18]) + A + B
    checksum = keccak_256(data).digest()[:4]
    return base58.encode((data + checksum).hex())


def calc_subaddress(A:bytes, v: bytes, i: int, a: int):
    """
    Args:
        A: bytes; public spend key
        v: bytes; private view key
        i: int; subaddress index 
        a: int; account index
    """

    data = b'SubAddr\x00' + v + a.to_bytes(4, byteorder="little") +  i.to_bytes(4, byteorder="little")
    HsG = ed25519.publickey(sc_reduce32(keccak_256(data).digest()))
    
    Si = ed25519.encodepoint(ed25519.edwards(ed25519.decodepoint(HsG), ed25519.decodepoint(A)))
    Vi = ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(Si), ed25519.decodeint(v)))
    
    data = bytearray([42]) + Si + Vi 
    checksum = keccak_256(data).digest()[:4]
    return base58.encode((data + checksum).hex())




def check_stealth_address(stealth_address: str, R: bytes, a: bytes, B: bytes, i: int)  :
    """ Checks if stealth address belongs to own private keys

    Keep in mind that R = rG and A = aG. Using R you are able to generate aR = arG = rA.

    Args:
        stealth_address: string; Stealth address to test
        R: bytes; Transaction public key (rG). Stored in field extra[1:33]).hex(). 
        a: bytes; Private view key
        B: bytes: Public spend key
        i: int; output index

    Returns:
        True if this is a received payment and the stealth address belongs to own private keys
        False if this is a foreign address

    """


    arG = ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(R), ed25519.decodeint(a)))
    arG =  ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(arG),  8 )) # There is a mathematical reason for this...
    arG += bytes([i])
    
    Hs = sc_reduce32(keccak_256(arG).digest())
    HsG = ed25519.publickey(Hs)

    my_addr =  ed25519.encodepoint(ed25519.edwards(ed25519.decodepoint(HsG), ed25519.decodepoint(B))).hex()
    return my_addr == stealth_address





def calc_stealth_address(r: bytes, A: bytes , B: bytes, i: int)-> str:
    """ Calculates stealth address in the form P = Hs(rA)G + B.
    
    Be careful, index and respent output (here you have to use your own public keys) have to match

    Args:
        r: bytes ; Transaction secret key (ephemeral random)
        A: bytes; pyblic view key
        B: bytes; public spend key
        i: int; output index 

    Returns:
        stealth address; subaddresses are prefixed with '8', addresses are prefixec with '4'
    """
    rA  = ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(A), ed25519.decodeint(r)))
    rA =  ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(rA), 8 )) # There is a mathematical reason for this...
    rA += bytes([i])

    Hs = sc_reduce32(keccak_256(rA).digest()) # Hs stands for Hash to scalar, interpret result as scalar
    HsG = ed25519.publickey(Hs)
    return ed25519.encodepoint(ed25519.edwards(ed25519.decodepoint(HsG), ed25519.decodepoint(B))).hex()




def calc_key_image(a: bytes, b: bytes, R: bytes, i:int) -> bytes:
    """Calculate key image for input 

    Args:
        a: bytes; Private view key
        b: bytes; Private spend key 
        R: bytes; Transaction public key (rG) of refferenced output transaction. Stored in field extra[1:33]).hex(). 
        i: int; output index of refferenced output

    Returns:
        Key image : string
    """
    
    # x = H_s(aR) + b
    aR = ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(R), ed25519.decodeint(a)))
    aR =  ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(aR),  8 )) # There is a mathematical reason for this...
    aR += bytes([i])

    Hs = sc_reduce32(keccak_256(aR).digest())

    x = int.from_bytes(Hs, byteorder='little') + int.from_bytes(b, byteorder='little')
    x = x % ed25519.l
    x = x.to_bytes(32, 'little')    

    Hp = hashToPointCN(ed25519.publickey(x))
    return ed25519.encodepoint(ed25519.scalarmult(Hp, ed25519.decodeint(x)))





def sender_pedersen_commitment(R:bytes , a:bytes, i:int, enc_amount:str):
    """
    See Zero-to-monero Section 5.3

    Args:
        R: bytes; Transaction public key (rG). Stored in field extra[1:33]).hex(). 
        a: bytes; Private view key
        i: int; Output index 
        enc_amount: string; Encrypted amount as hex string

    Returns:
        Decrypted amount

    amount = 8 byte encrypted amount XOR first 8 bytes of keccak("amount" || Hs(8aR||i))

    """
    arG = ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(R), ed25519.decodeint(a)))
    arG =  ed25519.encodepoint(ed25519.scalarmult(ed25519.decodepoint(arG),  8 )) # There is a mathematical reason for this...
    arG += bytes([i])

    Hs = sc_reduce32(keccak_256(arG).digest())
    Hs = "amount".encode() + Hs

    HsHs = keccak_256(Hs).digest()
    to_xor = HsHs.hex()[:16]
    dec_amount = bytes(a ^ b for a, b in zip(bytes.fromhex(enc_amount), bytes.fromhex(to_xor)))
    return int.from_bytes(dec_amount , byteorder="little", signed=False)










