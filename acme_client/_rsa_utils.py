import hashlib
from typing import Callable, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from josepy import JWKRSA, b64encode


class RSAKey:

    def __init__(self, key: rsa.RSAPrivateKey, alg: str) -> None:
        self.key = key
        self.alg = alg
        self.jwk_rsa: JWKRSA = JWKRSA(key=key)

    @classmethod
    def new(
        cls,
        key: Optional[rsa.RSAPrivateKey] = None,
        public_exponent: int = 65537,
        key_size: int = 2048,
        alg: str = "RS256",
    ) -> "RSAKey":
        key = key or rsa.generate_private_key(public_exponent, key_size)
        return cls(key, alg)

    @classmethod
    def from_pem_bytes(
        cls, data: bytes, password: Optional[bytes] = None, alg: str = "RS256"
    ) -> "RSAKey":
        key = ser.load_pem_private_key(data, password=password)
        return cls(key, alg)

    @staticmethod
    def make_x509_name(domain_name: str, org_name: str) -> x509.Name:
        return x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, org_name),
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, domain_name),
            ]
        )

    @staticmethod
    def make_sans(
        domain_name: str, alt_names: Optional[List[str]] = None
    ) -> List[x509.GeneralName]:
        names = [domain_name] + (alt_names or [])
        return [x509.DNSName(name) for name in names]

    @property
    def jwk_json(self) -> Dict:
        data = self.jwk_rsa.to_json()
        return {"e": data["e"], "n": data["n"], "kty": data["kty"]}

    def sign(
        self,
        data: bytes,
        sign_padding: Optional[padding.AsymmetricPadding] = None,
        hash_algorithm: Callable = hashes.SHA256,
    ) -> bytes:
        return self.key.sign(
            data=data,
            padding=sign_padding or padding.PKCS1v15(),
            algorithm=hash_algorithm(),
        )

    def make_csr(
        self,
        domain_name: str,
        alternative_names: Optional[List[str]] = None,
        encoding: ser.Encoding = ser.Encoding.DER,
    ) -> bytes:
        alternative_x509_names = self.make_sans(domain_name, alternative_names)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                self.make_x509_name(domain_name, "alternative_names"),
            )
            .add_extension(
                x509.SubjectAlternativeName(alternative_x509_names),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        return csr.public_bytes(encoding)

    def validate(self, token: str, hash_algorithm: Callable = hashes.SHA256) -> str:
        key_auth = (
            f"{token}.{b64encode(self.jwk_rsa.thumbprint(hash_function=hash_algorithm)).decode()}"
        )
        return b64encode(hashlib.sha256(key_auth.encode("utf-8")).digest()).decode()
