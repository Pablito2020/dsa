from argparse import ArgumentParser
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.dsa import (DSAParameterNumbers,
                                                           DSAParameters,
                                                           DSAPrivateKey,
                                                           DSAPrivateNumbers,
                                                           DSAPublicKey)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, Hash


@dataclass
class DSA:
    '''
    Encapsulates all the parameters needed for the DSA algorithm.
    '''
    L: int
    p: int
    q: int
    g: int
    x: int
    pub_k: int
    priv_key_obj: DSAPrivateKey


def get_dsa_parameters(L: int) -> DSA:
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


def print_dsa_numbers(dsa_nums: DSA):
    print("Generated parameters for the DSA signature algorithm.")
    print(
        f"\tL: {dsa_nums.L}\n\tp: {dsa_nums.p}\n\tq: {dsa_nums.q}\n\tg: {dsa_nums.g}\n\tx: {dsa_nums.x}\n\tpublic key (g^x modp): {dsa_nums.pub_k}"
    )


def assert_h_equals_2(dsa_nums: DSA):
    assert dsa_nums.g == pow(2, (dsa_nums.p - 1) // dsa_nums.q, dsa_nums.p)
    print("Asserted that h = 2!")


def assert_pub_key_is_g_pow_x_mod_p(dsa_nums: DSA):
    assert dsa_nums.pub_k == pow(dsa_nums.g, dsa_nums.x, dsa_nums.p)
    print("Asserted that the public key == g^x mod p!")


def get_hash_of_message(message: str, length_bits: int) -> int:
    """
    returns the hash (function: SHA256) of the message and truncates the message
    with the number of bits specified.
    """
    digest = Hash(SHA256())
    digest.update(message.encode("utf-8"))
    message_bytes_hashed: bytes = digest.finalize()
    assert length_bits % 8 == 0
    length_bytes = length_bits // 8
    message_truncated = (
        message_bytes_hashed
        if length_bytes == 256
        else message_bytes_hashed[:length_bytes]
    )
    return int.from_bytes(message_truncated, "big")


def assert_v_equals_r(dsa_nums: DSA):
    dummy_message: str = "Message"
    signature: bytes = dsa_nums.priv_key_obj.sign(dummy_message.encode("utf-8"), SHA256())
    r, s = decode_dss_signature(signature)
    w = pow(s, -1, dsa_nums.q)
    message_hashed: int = get_hash_of_message(dummy_message, dsa_nums.q.bit_length())
    a = (message_hashed * w) % dsa_nums.q
    b = (r * w) % dsa_nums.q
    v = pow(dsa_nums.g, a + (dsa_nums.x * b), dsa_nums.p) % dsa_nums.q
    assert r == v
    print("Asserted that r == v!")


if __name__ == "__main__":
    # arg parser
    parser = ArgumentParser(
        prog="main.py", description="Create DSA parameters and assert the properties."
    )
    parser.add_argument("-l", "--number-bits-prime-number")
    args = parser.parse_args()

    # create and assert
    L = int(args.number_bits_prime_number) if args.number_bits_prime_number else 2048
    dsa_params: DSA = get_dsa_parameters(L)
    print_dsa_numbers(dsa_params)
    assert_h_equals_2(dsa_params)
    assert_pub_key_is_g_pow_x_mod_p(dsa_params)
    assert_v_equals_r(dsa_params)
