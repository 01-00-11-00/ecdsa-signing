
# ---------------------------- Libraries ------------------------------- #
from utils.ec_operations import EllipticCurveOperations
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib


# ---------------------------- ECDSA Signing ------------------------------- #

class EcdsaSigning:
    """
    A class used to perform ECDSA signing and verification operations.
    """

    # Constructor
    def __init__(self):
        """
        Initializes the EcdsaSigning class with the parameters of the elliptic curve P-256.
        """
        # parameter of the elliptic curve P-256
        self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        self.G = (
            0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
            0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        )
        self.n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        self.h = 0x1

        self.calculator = EllipticCurveOperations(self.p, self.a, self.b)

    @staticmethod
    def read_keys(file_path: str):
        """
        Reads a private key from a PEM file.
        :param file_path: The path to the PEM file.
        :return: The private key.
        """

        with open(file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

            return private_key

    def read_signature(self, file_path: str) -> tuple:
        """
        Reads a signature from a binary file.
        :param file_path: The path to the binary file.
        :return: The signature as a tuple.
        """

        with open(file_path, "rb") as sig_file:
            encoded_sig = sig_file.read()
            sig = self.asn1_decode(encoded_sig)

            return sig

    @staticmethod
    def read_message(file_path: str) -> bytes:
        """
        Reads a message from a binary file.
        :param file_path: The path to the binary file.
        :return: The message as bytes.
        """

        with open(file_path, "rb") as m_file:
            message = m_file.read()

            return message

    @staticmethod
    def create_public_key_pem(public_key: tuple):
        """
        Creates a PEM file from a public key.
        :param public_key: The public key as a tuple.
        """

        public_numbers = ec.EllipticCurvePublicNumbers(public_key[0], public_key[1], ec.SECP256R1())
        public_key_obj = public_numbers.public_key(default_backend())

        pem_public_key = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("output/public_key.pem", "wb") as file:
            file.write(pem_public_key)

    def create_public_key(self, private_key: int) -> tuple:
        """
        Creates a public key from a private key.
        :param private_key: The private key as an integer.
        :return: The public key as a tuple.
        """

        return self.calculator.multiply(self.G, private_key)

    def create_signed_bin(self, message: bytes, private_key: int, k: int, file_path="output/signature.bin"):
        """
        Creates a signed binary file from a message, a private key, and a nonce.
        :param message: The message as bytes.
        :param private_key: The private key as an integer.
        :param k: The nonce as an integer.
        :param file_path: The path to the output binary file.
        """

        sig = self.ecdsa_sign(message, private_key, k)

        with open(file_path, "wb") as file:
            file.write(self.asn1_encode(sig))

    @staticmethod
    def create_message_bin(message: bytes, file_path="output/message.bin"):
        """
        Creates a binary file from a message.
        :param message: The message as bytes.
        :param file_path: The path to the output binary file.
        """

        with open(file_path, "wb") as file:
            file.write(message)

    def ecdsa_sign(self, message: bytes, private_key: int, k: int) -> tuple:
        """
        Signs a message using ECDSA.
        :param message: The message as bytes.
        :param private_key: The private key as an integer.
        :param k: The nonce as an integer.
        :return: The signature as a tuple.
        """

        e = int(hashlib.sha256(message).hexdigest(), 16)

        R = self.calculator.multiply(self.G, k)

        r = R[0] % self.n
        s = (self.calculator.extended_euclidean_algorithm(k, self.n)[2] * (e + private_key * r)) % self.n

        return r, s

    def ecdsa_verify(self, public_key: tuple[int, int], message: bytes, signature: tuple) -> bool:
        """
        Verifies a signature using ECDSA.
        :param public_key: The public key as a tuple.
        :param message: The message as bytes.
        :param signature: The signature as a tuple.
        :return: True if the signature is valid, False otherwise.
        """

        e = int(hashlib.sha256(message).hexdigest(), 16)
        r, s = signature

        w = self.calculator.extended_euclidean_algorithm(s, self.n)[2] % self.n
        u1 = (e * w) % self.n
        u2 = (r * w) % self.n

        P = self.calculator.add(self.calculator.multiply(self.G, u1), self.calculator.multiply(public_key, u2))

        if P[0] % self.n == r:
            return True

        else:
            return False

    @staticmethod
    def asn1_encode(signature: tuple) -> bytes:
        """
        Encodes a signature using ASN.1.
        :param signature: The signature as a tuple.
        :return: The encoded signature as bytes.
        """

        r, s = signature
        r = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big').lstrip(b'\x00')
        s = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big').lstrip(b'\x00')

        if r[0] & 0x80:
            r = b'\x00' + r
        if s[0] & 0x80:
            s = b'\x00' + s

        sequence_length = len(r) + len(s) + 4

        return (
                b'\x30' + bytes([sequence_length]) +
                b'\x02' + bytes([len(r)]) + r +
                b'\x02' + bytes([len(s)]) + s
        )

    @staticmethod
    def asn1_decode(encoded_sequence: bytes) -> tuple:
        """
        Decodes a signature using ASN.1.
        :param encoded_sequence: The encoded signature as bytes.
        :return: The signature as a tuple.
        """

        if encoded_sequence[0] != 0x30:
            raise ValueError("Expected Sequence")

        r_length = encoded_sequence[3]
        s_length = encoded_sequence[5 + r_length]

        if encoded_sequence[2] != 0x02 or encoded_sequence[4 + r_length] != 0x02:
            raise ValueError("Expected integer")

        r = int.from_bytes(encoded_sequence[4:4 + r_length], byteorder='big')
        s = int.from_bytes(encoded_sequence[5 + r_length + 1:5 + r_length + 1 + s_length], byteorder='big')

        return r, s

    def check_for_identical_nonce(self, message_1: bytes, message_2: bytes, sig_1: tuple, sig_2: tuple) -> int or None:
        """
        Checks if two messages were signed using the same nonce.
        :param message_1: The first message as bytes.
        :param message_2: The second message as bytes.
        :param sig_1: The signature of the first message as a tuple.
        :param sig_2: The signature of the second message as a tuple.
        :return: The private key if the nonce is identical, None otherwise.
        """

        e1 = int(hashlib.sha256(message_1).hexdigest(), 16)
        e2 = int(hashlib.sha256(message_2).hexdigest(), 16)

        s1 = sig_1[1]
        s2 = sig_2[1]

        r = sig_1[0]

        s2_e1 = (s2 * e1) % self.n
        s1_e2 = (s1 * e2) % self.n
        s1_r = (s1 * r) % self.n
        s2_r = (s2 * r) % self.n

        numerator = (s2_e1 - s1_e2) % self.n
        denominator = (s1_r - s2_r) % self.n

        d = (numerator * self.calculator.extended_euclidean_algorithm(denominator, self.n)[2]) % self.n

        k1 = ((e1 + d * r) * self.calculator.extended_euclidean_algorithm(s1, self.n)[2]) % self.n
        k2 = ((e2 + d * r) * self.calculator.extended_euclidean_algorithm(s2, self.n)[2]) % self.n

        if k1 == k2:
            return d

        else:
            return None
