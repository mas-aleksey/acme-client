from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Certificate

from acme_client import RSAKey


@pytest.fixture
def rsa_key() -> RSAKey:
    return RSAKey.new()


@pytest.fixture
def self_signed_cert(rsa_key: RSAKey) -> Certificate:
    domain_name = "example.com"
    expiration_date = datetime.now(tz=timezone.utc) + timedelta(days=365)
    alternative_names = ["www.example.com", "mail.example.com"]

    x509_name = RSAKey.make_x509_name(domain_name, "Example Inc.")
    alternative_x509_names = RSAKey.make_sans(domain_name, alternative_names)

    return (
        x509.CertificateBuilder()
        .subject_name(x509_name)
        .issuer_name(x509_name)
        .public_key(rsa_key.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(expiration_date)
        .add_extension(
            x509.SubjectAlternativeName(alternative_x509_names),
            critical=False,
        )
        .sign(rsa_key.key, hashes.SHA256())
    )


@pytest.fixture
def self_signed_pem(self_signed_cert: Certificate) -> bytes:
    return self_signed_cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def self_signed_der(self_signed_cert: Certificate) -> bytes:
    return self_signed_cert.public_bytes(serialization.Encoding.DER)
