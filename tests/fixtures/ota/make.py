"""Regenerates the OTA signature fixtures with independent tools (python-cryptography for the
payload signatures, `openssl cms` for the signapk-style zip signature):
    python3 make.py   ->  ota-signed.zip, cert.pem, other-cert.pem
Keys are throwaway and not kept. Needs: pip install cryptography; openssl."""
import datetime, hashlib, struct, subprocess, tempfile, zipfile, os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def mk(cn):
    k = rsa.generate_private_key(65537, 2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2024, 1, 1)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now)
         .not_valid_after(now + datetime.timedelta(days=36500)).sign(k, hashes.SHA256()))
    return k, c

def varint(v):
    o = b""
    while True:
        b = v & 0x7f; v >>= 7
        o += bytes([b | (0x80 if v else 0)])
        if not v: return o

def field(tag, wt, payload): return varint(tag << 3 | wt) + payload
def ld(tag, data): return field(tag, 2, varint(len(data)) + data)

def sigs(key, digest):
    s = key.sign(digest, padding.PKCS1v15(), __import__("cryptography").hazmat.primitives.asymmetric.utils.Prehashed(hashes.SHA256()))
    return ld(1, ld(2, s) + field(3, 5, struct.pack("<I", len(s))))

key, cert = mk("OTA Fixture")
okey, ocert = mk("Other")
pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
open("cert.pem", "wb").write(pem(cert)); open("other-cert.pem", "wb").write(pem(ocert))

# payload: header | manifest | metadata signature | (no data) | payload signature
sig_len = len(sigs(key, b"\0" * 32))
manifest = field(3, 0, varint(4096)) + field(4, 0, varint(0)) + field(5, 0, varint(sig_len)) + field(12, 0, varint(0))
hdr = b"CrAU" + struct.pack(">QQI", 2, len(manifest), sig_len)
meta_sig = sigs(key, hashlib.sha256(hdr + manifest).digest())
prefix = hdr + manifest + meta_sig
payload = prefix + sigs(key, hashlib.sha256(prefix).digest())

with tempfile.TemporaryDirectory() as d:
    z = os.path.join(d, "ota.zip")
    with zipfile.ZipFile(z, "w", zipfile.ZIP_STORED) as zf:
        for name, data in [("payload.bin", payload), ("META-INF/com/android/otacert", pem(cert))]:
            zi = zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0)); zf.writestr(zi, data)
    raw = open(z, "rb").read()
    body = raw[:-2]  # signed: everything up to the EOCD comment length
    open(os.path.join(d, "body"), "wb").write(body)
    open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(os.path.join(d, "c.pem"), "wb").write(pem(cert))
    subprocess.check_call(["openssl", "cms", "-sign", "-binary", "-outform", "DER", "-md", "sha256", "-nosmimecap",
                           "-signer", os.path.join(d, "c.pem"), "-inkey", os.path.join(d, "k.pem"),
                           "-in", os.path.join(d, "body"), "-out", os.path.join(d, "sig.der")])
    p7 = open(os.path.join(d, "sig.der"), "rb").read()
    comment = p7 + struct.pack("<HHH", len(p7) + 6, 0xFFFF, len(p7) + 6)
    open("ota-signed.zip", "wb").write(body + struct.pack("<H", len(comment)) + comment)
