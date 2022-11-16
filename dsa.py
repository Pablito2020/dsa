from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAParameters, DSAParameterNumbers, DSAPrivateKey, DSAPrivateNumbers, DSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from dataclasses import dataclass


@dataclass
class DSA:
    L: int
    p: int
    q: int
    g: int
    x: int
    pub_k: int
    priv_key_obj: DSAPrivateKey


def get_dsa_parameters() -> DSA:
    L = 2048
    values: DSAParameters = dsa.generate_parameters(key_size=L)
    numbers: DSAParameterNumbers = values.parameter_numbers()
    p = numbers.p
    q = numbers.q
    g = numbers.g
    private_key: DSAPrivateKey = values.generate_private_key()
    public_key: DSAPublicKey = private_key.public_key()
    pub_key = public_key.public_numbers().y
    private_numbers: DSAPrivateNumbers = private_key.private_numbers()
    x = private_numbers.x
    return DSA(L=L, p=p, q=q, g=g, x=x, pub_k=pub_key, priv_key_obj=private_key)


dsa_nums: DSA = get_dsa_parameters()
print("Generated parameters for the DSA signature algorithm.")
print(f"\tL: {dsa_nums.L}\n\tp: {dsa_nums.p}\n\tq: {dsa_nums.q}\n\tg: {dsa_nums.g}\n\tx: {dsa_nums.x}\n\tpublic key (g^x modp): {dsa_nums.pub_k}")

# Comprova que h = 2
assert dsa_nums.g == pow(2, (dsa_nums.p - 1) // dsa_nums.q, dsa_nums.p)
print("Asserted that h = 2!")

# Comprova que la clau pública és: g^x mod p
assert dsa_nums.pub_k == pow(dsa_nums.g, dsa_nums.x, dsa_nums.p)
print("Asserted that the public key == g^x mod p!")

# Signa missatge amb SHA256, calcula V i comprova que V == R
signature: bytes = dsa_nums.priv_key_obj.sign("Message".encode("utf-8"), SHA256())
r, s = decode_dss_signature(signature)
w = pow(s, -1, dsa_nums.q)
digest = Hash(SHA256())
digest.update("Message".encode("utf-8"))
message_bytes_hashed: bytes = digest.finalize()
message_int_hashed: int = int.from_bytes(message_bytes_hashed, "big")
a = (message_int_hashed * w) % dsa_nums.q
b = (r * w) % dsa_nums.q
v = pow(dsa_nums.g, a + (dsa_nums.x * b), dsa_nums.p) % dsa_nums.q
assert r == v
print("Asserted that r == v!")
