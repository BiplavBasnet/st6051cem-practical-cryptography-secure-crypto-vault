import os
import datetime
import uuid
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from services.crypto_utils import CryptoUtils

class PKIService:
    def __init__(self, pki_dir="pki"):
        self.pki_dir = pki_dir
        os.makedirs(self.pki_dir, exist_ok=True)
        self.ca_key_path = os.path.join(self.pki_dir, "ca_key.pem")
        self.ca_cert_path = os.path.join(self.pki_dir, "ca_cert.pem")
        
        if not os.path.exists(self.ca_key_path) or not os.path.exists(self.ca_cert_path):
            self._setup_ca()

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
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA256())

        with open(self.ca_key_path, "wb") as f:
            f.write(CryptoUtils.serialize_private_key(private_key))
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def get_ca_cert(self):
        with open(self.ca_cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def get_ca_key(self):
        with open(self.ca_key_path, "rb") as f:
            return CryptoUtils.load_private_key(f.read())

    def issue_user_certificate(self, username, public_key, purpose="auth"):
        """
        Issue an X.509 certificate for a user with specific KeyUsage.
        purpose can be 'auth', 'signing', or 'encryption'.
        """
        ca_cert = self.get_ca_cert()
        ca_key = self.get_ca_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureCrypt Vault"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )

        # Enforce Key Separation via Extensions
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
                ), critical=True
            ).add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False
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
                ), critical=True
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
                ), critical=True
            )

        cert = builder.sign(ca_key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)

    def validate_certificate(self, cert_pem_bytes, db_manager=None, required_ku=None, required_eku=None):
        """Validate a certificate against the CA, check revocation, and enforce extensions."""
        cert = x509.load_pem_x509_certificate(cert_pem_bytes)
        ca_cert = self.get_ca_cert()

        # 1. Check validity period
        now = datetime.datetime.now(datetime.timezone.utc)
        if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
            return False, "Certificate is expired or not yet valid"

        # 2. Verify CA signature
        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception:
            return False, "Invalid CA signature"

        # 3. Check Revocation
        if db_manager:
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT revoked FROM certificates WHERE serial_number = ?", (str(cert.serial_number),))
            row = cursor.fetchone()
            conn.close()
            if row and row['revoked'] == 1:
                return False, "Certificate has been revoked"

        # 4. Enforce KeyUsage extensions (Tier 1 Requirement)
        if required_ku:
            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                for attr in required_ku:
                    if not getattr(ku, attr):
                        return False, f"Certificate lacks required KeyUsage: {attr}"
            except Exception:
                return False, "Certificate missing KeyUsage extension"

        # 5. Enforce ExtendedKeyUsage extensions (Tier 1 Requirement)
        if required_eku:
            try:
                eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                for required_oid in required_eku:
                    if required_oid not in eku:
                        return False, f"Certificate lacks required ExtendedKeyUsage: {required_oid}"
            except Exception:
                return False, "Certificate missing ExtendedKeyUsage extension"

        return True, "Valid"


# Forensic Integrity: d5843a84 verified at 2026-02-11 13:48:57
