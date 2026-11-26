"""APK signing certificates (decision D-26).

Every genuine build of a company's app is signed with the company's key; a fake or repackaged APK cannot
reuse that signature. We read only the signer certificates — from the APK Signature Scheme v2/v3/v3.1 block
(Androguard) and the v1/JAR signature in META-INF (cryptography) — and fingerprint them with SHA-256, the same
value shown in Google Play Console → App integrity → App signing key certificate. Nothing is decompiled or run.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID


@dataclass
class SignerInfo:
    fingerprints: list[str] = field(default_factory=list)  # SHA-256, upper-case hex, no colons
    subjects: list[str] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)

    @property
    def signed(self) -> bool:
        return bool(self.fingerprints)


def normalize_fingerprint(value: str) -> str:
    """'AB:CD:…' / 'ab cd …' / 'SHA-256: abcd…' → 'ABCD…' (64 hex characters)."""
    hexed = re.sub(r"[^0-9a-fA-F]", "", value.replace("SHA-256", "").replace("SHA256", "").replace("sha256", ""))
    return hexed.upper()


def _subject(der: bytes) -> str | None:
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    parts = []
    for oid, label in ((NameOID.COMMON_NAME, "CN"), (NameOID.ORGANIZATION_NAME, "O"), (NameOID.COUNTRY_NAME, "C")):
        vals = cert.subject.get_attributes_for_oid(oid)
        if vals:
            parts.append(f"{label}={vals[0].value}")
    return ", ".join(parts) or None


def read_signers(apk_bytes: bytes) -> SignerInfo:
    found: dict[str, tuple[bytes, set[str]]] = {}

    def add(der: bytes, scheme: str) -> None:
        fp = hashlib.sha256(der).hexdigest().upper()
        found.setdefault(fp, (der, set()))[1].add(scheme)

    # v2 / v3 / v3.1 signing block
    try:
        from androguard.core.apk import APK

        apk = APK(apk_bytes, raw=True)
        for scheme, getter in (("v3.1", "get_certificates_der_v31"), ("v3", "get_certificates_der_v3"),
                               ("v2", "get_certificates_der_v2")):
            try:
                for der in getattr(apk, getter)() or []:
                    add(der, scheme)
            except Exception:  # noqa: BLE001 - scheme absent or malformed
                continue
    except Exception:  # noqa: BLE001 - not a parsable APK; still try the v1 signature below
        pass

    # v1 (JAR) signature: META-INF/*.RSA|*.DSA|*.EC are PKCS#7 blocks holding the signer certificate
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
            for name in z.namelist():
                if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", name, re.I):
                    for cert in pkcs7.load_der_pkcs7_certificates(z.read(name)):
                        add(cert.public_bytes(Encoding.DER), "v1")
    except (zipfile.BadZipFile, ValueError, OSError):
        pass

    info = SignerInfo()
    for fp, (der, schemes) in sorted(found.items()):
        info.fingerprints.append(fp)
        info.schemes.extend(sorted(schemes - set(info.schemes)))
        subject = _subject(der)
        if subject:
            info.subjects.append(subject)
    return info
