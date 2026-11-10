"""Make the ML-DSA vbmeta fixtures next to this file, signed by OpenSSL (not by this crate).

Run: python3 -I make_vbmeta.py OUTDIR   (needs openssl 3.5 or newer for ML-DSA)

Layout is libavb's AvbVBMetaImageHeader as src/avb.rs reads it: a 256-byte header, an
authentication block (32-byte SHA-256 hash, then the signature, padded to 64 bytes), and an
auxiliary block (the AvbMLDSAPublicKeyHeader key blob, padded to 64 bytes; no descriptors).
Two signed messages are written: `aux` signs the header and auxiliary block, `hash` signs the
authentication hash. The verifier accepts either; see verify_mldsa_signature in src/avb.rs.
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile

HEADER_LEN = 256
# algorithm type: (OpenSSL name, raw public key bytes, signature bytes)
PARAMS = {7: ("ML-DSA-65", 1952, 3309), 8: ("ML-DSA-87", 2592, 4627)}


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL)


def make(outdir, alg, mode, work):
    name, pk_len, sig_len = PARAMS[alg]
    key, pub, msg_path, sig_path = (os.path.join(work, n) for n in ("k.pem", "pub.der", "msg.bin", "sig.bin"))
    openssl("genpkey", "-algorithm", name, "-out", key)
    openssl("pkey", "-in", key, "-pubout", "-outform", "DER", "-out", pub)
    with open(pub, "rb") as f:
        raw = f.read()[-pk_len:]  # SubjectPublicKeyInfo: the raw key is the last pk_len bytes
    key_blob = struct.pack(">I", pk_len) + raw
    aux = key_blob + b"\0" * (-len(key_blob) % 64)

    hash_len = 32
    auth_len = -(-(hash_len + sig_len) // 64) * 64
    h = bytearray(HEADER_LEN)
    h[0:4] = b"AVB0"
    struct.pack_into(">II", h, 4, 1, 0)  # required libavb version 1.0
    struct.pack_into(">QQ", h, 12, auth_len, len(aux))
    struct.pack_into(">I", h, 28, alg)
    struct.pack_into(">QQ", h, 32, 0, hash_len)  # hash: offset, size
    struct.pack_into(">QQ", h, 48, hash_len, sig_len)  # signature: offset, size
    struct.pack_into(">QQ", h, 64, 0, len(key_blob))  # public key: offset, size (no descriptors)
    struct.pack_into(">QQ", h, 80, len(key_blob), 0)  # public key metadata: offset, size
    struct.pack_into(">QQ", h, 96, 0, 0)  # descriptors: offset, size
    struct.pack_into(">Q", h, 112, 1234)  # rollback index
    struct.pack_into(">I", h, 124, 3)  # rollback index location
    h[128:137] = b"test 1.0\0"

    signed = bytes(h) + aux
    digest = hashlib.sha256(signed).digest()
    with open(msg_path, "wb") as f:
        f.write(signed if mode == "aux" else digest)
    openssl("pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", msg_path, "-out", sig_path)
    with open(sig_path, "rb") as f:
        sig = f.read()
    assert len(sig) == sig_len, len(sig)
    # the signature checks out under OpenSSL's own verifier before it goes into the fixture
    openssl("pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", pub, "-rawin",
            "-in", msg_path, "-sigfile", sig_path)

    auth = digest + sig + b"\0" * (auth_len - hash_len - sig_len)
    out = os.path.join(outdir, f"mldsa{ {7: 65, 8: 87}[alg] }-{mode}.vbmeta")
    with open(out, "wb") as f:
        f.write(bytes(h) + auth + aux)
    print("wrote", out)


def main():
    outdir = sys.argv[1]
    for alg in PARAMS:
        for mode in ("aux", "hash"):
            with tempfile.TemporaryDirectory() as work:
                make(outdir, alg, mode, work)


if __name__ == "__main__":
    main()
