import base64
import cryptography.hazmat.primitives.asymmetric
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.hazmat.primitives import serialization
import nacl.bindings


class KeyHandler:

    PREFIX_SK = bytes([int(x, 16) for x in '30:2E:02:01:00:30:05:06:03:2B:65:70:04:22:04:20'.split(':')])
    PREFIX_PK = bytes([int(x, 16) for x in '30:2A:30:05:06:03:2B:65:70:03:21:00'.split(':')])

    def __init__(self, private_key=None):
        self._private_key, self._public_key = self.__generate_key_pair(private_key=private_key)
        tmp_ed25519_sk = self.ed25519_sk_bytes
        tmp_ed25519_pk = self.ed25519_pk_bytes
        """
        # crypto_sign_ed25519_sk_to_curve25519() is equivalent to :
        tmp = list(hashlib.sha512(ed25519_sk).digest()[:32])
        tmp[0] &= 248
        tmp[31] &= 127
        tmp[31] |= 64
        self._x25519_sk = bytes(tmp)
        """
        self._x25519_sk = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(tmp_ed25519_sk + tmp_ed25519_pk)
        self._x25519_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(tmp_ed25519_pk)

    @classmethod
    def get_proton_fingerprint_from_x25519_pk(cls, x25519_pk: bytes) -> str:
        import hashlib
        return base64.b64encode(hashlib.sha512(x25519_pk).digest()).decode("ascii")

    @classmethod
    def from_sk_file(cls, ed25519sk_file):
        backend_default = None
        # cryptography.sys.version_info not available in 2.6
        crypto_major, crypto_minor = cryptography.__version__.split(".")[:2]
        if (int(crypto_major) < 3 or
                int(crypto_major) == 3 and int(crypto_minor) < 1):
            backend_default = cryptography.hazmat.backends.default_backend()  # backend is required if library < 3.1
        pem_data = "".join(open(ed25519sk_file).readlines())
        key = serialization.load_pem_private_key(pem_data.encode("ascii"), password=None, backend=backend_default)
        assert isinstance(key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)
        private_key = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        return KeyHandler(private_key=private_key)

    @property
    def ed25519_sk_str(self) -> str:
        return base64.b64encode(self.ed25519_sk_bytes).decode("ascii")

    @property
    def ed25519_sk_bytes(self) -> bytes:
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())

    @property
    def ed25519_pk_bytes(self) -> bytes:
        return self._public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    @property
    def ed25519_pk_str_asn1(self) -> bytes:
        return base64.b64encode(self.PREFIX_PK + self.ed25519_pk_bytes)

    @property
    def ed25519_sk_pem(self) -> str:
        return self._private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode('ascii')

    @property
    def ed25519_pk_pem(self) -> str:
        return self._public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')

    @property
    def x25519_sk_bytes(self) -> bytes:
        return self._x25519_sk

    @property
    def x25519_pk_bytes(self) -> bytes:
        return self._x25519_pk

    @property
    def x25519_sk_str(self) -> str:
        return base64.b64encode(self._x25519_sk).decode("ascii")

    @property
    def x25519_pk_str(self) -> str:
        return base64.b64encode(self._x25519_pk).decode("ascii")

    @classmethod
    def __generate_key_pair(cls, private_key=None):
        if private_key:
            private_key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        else:
            private_key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key


def bytes_to_str_hexa(b: bytes):
    return ":".join(["{:02x}".format(x) for x in b])

if __name__=="__main__":
    a=KeyHandler()
    print(a.ed25519_pk_pem)