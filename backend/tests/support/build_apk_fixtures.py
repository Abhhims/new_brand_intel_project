"""Build the demo brand's APK test files (D-26). Run once; outputs are committed under backend/tests/fixtures/.

    python -m tests.support.build_apk_fixtures

Creates two signing identities — "Zentrova Bank Ltd" (official) and "ZB Apps Studio" (attacker) — and three
v1-signed APK test files in backend/tests/fixtures/site/apk/:
  * zentrova-bank-official-8.1.0.apk     official package, official key        → genuine, must NOT alert
  * zentrova-mobile-banking-v5.2.apk     look-alike package, attacker key      → fake APK
  * zentrova-bank-mod-8.1.0.apk          official package, attacker key        → repackaged / re-signed fake
and writes the official certificate's SHA-256 into backend/tests/fixtures/brand/zentrova.json as a `signing_cert` allowlist entry.
These are test fixtures, not real applications.
"""

import hashlib
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1] / "fixtures"
APK_DIR = ROOT / "site" / "apk"


def identity(cn: str, org: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COUNTRY_NAME, "IN")])
    now = datetime(2026, 1, 1, tzinfo=UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=365 * 25)).sign(key, hashes.SHA256()))
    return key, cert


def build(path: Path, package: str, version: str, key, cert) -> None:
    manifest = f'<manifest package="{package}" android:versionName="{version}"/>'.encode()
    cert_sf = b"Signature-Version: 1.0\r\nCreated-By: test fixture\r\n\r\n"
    signature = (pkcs7.PKCS7SignatureBuilder().set_data(cert_sf).add_signer(cert, key, hashes.SHA256())
                 .sign(Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.write(APK_DIR / "icon.png", "res/mipmap/ic_launcher.png")
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
        z.writestr("META-INF/CERT.SF", cert_sf)
        z.writestr("META-INF/CERT.RSA", signature)
        z.writestr("README.txt", "TEST FIXTURE for the Beyond Cloud Brand Intelligence platform. Not a real app.")


def main() -> None:
    off_key, off_cert = identity("Zentrova Bank Ltd", "Zentrova Bank Ltd")
    bad_key, bad_cert = identity("ZB Apps Studio", "ZB Apps Studio")
    build(APK_DIR / "zentrova-bank-official-8.1.0.apk", "com.zentrova.mobile", "8.1.0", off_key, off_cert)
    build(APK_DIR / "zentrova-mobile-banking-v5.2.apk", "com.zentrova.mobilebanking.secure", "5.2", bad_key, bad_cert)
    build(APK_DIR / "zentrova-bank-mod-8.1.0.apk", "com.zentrova.mobile", "8.1.0", bad_key, bad_cert)
    official_fp = hashlib.sha256(off_cert.public_bytes(Encoding.DER)).hexdigest().upper()

    brand_path = ROOT / "brand" / "zentrova.json"
    spec = json.loads(brand_path.read_text(encoding="utf-8"))
    spec["allowlist"] = [a for a in spec["allowlist"] if a["kind"] != "signing_cert"]
    spec["allowlist"].append({"kind": "signing_cert", "value": official_fp})
    brand_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    print("official signer SHA-256:", official_fp)


if __name__ == "__main__":
    main()
