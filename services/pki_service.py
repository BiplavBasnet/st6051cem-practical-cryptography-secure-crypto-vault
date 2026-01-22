import os
import datetime
from pathlib import Path

from services.app_paths import pki_dir as app_pki_dir

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from services.crypto_utils import CryptoUtils


class PKIService:
    def __init__(self, pki_dir=None):
        self.pki_dir = (app_pki_dir() if pki_dir is None else Path(pki_dir))
        self.pki_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.pki_dir, 0o700)
        except Exception:
            pass

        self.ca_key_path = self.pki_dir / "ca_key.pem"
        self.ca_cert_path = self.pki_dir / "ca_cert.pem"

        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            self._setup_ca()
        else:
            self._harden_key_permissions()

    def _secure_write(self, path: Path, data: bytes, mode: int):
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(path), flags, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            os.chmod(path, mode)
        except Exception:
            pass

    def _harden_key_permissions(self):
        try:
            if self.ca_key_path.exists():
                os.chmod(self.ca_key_path, 0o600)
            if self.ca_cert_path.exists():
                os.chmod(self.ca_cert_path, 0o644)
        except Exception:
            pass

    def _setup_ca(self):
        """Initialize a self-signed Root CA."""
        private_key = CryptoUtils.generate_rsa_key_pair(4096)
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Kathmandu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureCrypt Root CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )

        self._secure_write(self.ca_key_path, CryptoUtils.serialize_private_key(private_key), 0o600)
        self._secure_write(self.ca_cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)

    def get_ca_cert(self):
        return x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())

    def get_ca_key(self):
        return CryptoUtils.load_private_key(self.ca_key_path.read_bytes())

    def issue_user_certificate(self, username, public_key, purpose="auth"):
        """
        Issue end-entity X.509 certificate with purpose-constrained key usages.
        purpose: 'auth' | 'signing' | 'encryption'
        """
        ca_cert = self.get_ca_cert()
        ca_key = self.get_ca_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )

        if purpose == "auth":
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
        elif purpose == "signing":
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        elif purpose == "encryption":
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        else:
            raise ValueError("Invalid certificate purpose")

        cert = builder.sign(ca_key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)
