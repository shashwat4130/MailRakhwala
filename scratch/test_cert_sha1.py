import sys
from pathlib import Path

backend_dir = Path("backend")
sys.path.insert(0, str(backend_dir))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# Test generating CERT_BAD with SHA1
key_1024 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
cert_bad = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.attacker.local")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil.attacker.local")]))
    .public_key(key_1024.public_key())
    .serial_number(1002)
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=200))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=20))
    .sign(key_1024, hashes.SHA1())
)
der_bad = cert_bad.public_bytes(serialization.Encoding.DER)
print("CERT_BAD with SHA-1 generated successfully, size:", len(der_bad))
