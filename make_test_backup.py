#!/usr/bin/env python3
"""Erzeugt synthetische Huawei-Backups zum Testen von huawei_backup_recover.py.

Deckt beide Schemata ab:
  - Schema A (KoBackup v10..v12, AES-256-CTR)
  - Schema B (KoBackup v13 / HiSuite 11+, AES-256-GCM)

Zusaetzlich: ein Fall mit zerstoertem info.xml, bei dem der Abbruch
mitten im Attribut passiert - exakt das Szenario aus dem Backup.
"""
from __future__ import annotations

import binascii
import hashlib
import io
import os
import shutil
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from huawei_backup_recover import (
    PBKDF2_ITER_BKEY, PBKDF2_ITER_FILE, PBKDF2_ITER_V13,
    derive_bkey, derive_file_key_a, derive_key_b,
    _prf_sha256,
)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

PASSWORD = "TestPasswort123!"


def _jpg_bytes(n=3000):
    """Minimal gueltiges JPEG-Geruest mit Comment-Payload."""
    out = io.BytesIO()
    out.write(b"\xff\xd8\xff\xe0")
    out.write(b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    out.write(b"\xff\xfe")
    payload = b"JPEGDATA" * (n // 7)
    out.write(len(payload).to_bytes(2, "big") + payload)
    out.write(b"\xff\xd9")
    return out.getvalue()


def _png_bytes(n=2000):
    out = io.BytesIO()
    out.write(b"\x89PNG\r\n\x1a\n")
    out.write(b"PNGDATA" * (n // 7))
    return out.getvalue()


def _mp4_bytes(n=4000):
    body = b"MP4DATA" * (n // 7)
    return b"\x00\x00\x00\x18ftypisom" + body


def _db_bytes(n=1500):
    return b"SQLite format 3\x00" + b"ROWDATA" * (n // 7)


def _ogg_bytes(n=4000):
    """Minimaler Ogg/Opus-Kopf (OggS-Signatur)."""
    return b"OggS" + b"\x00" * 8 + b"\x01\x1e" + b"\x00" * (n - 10)


PAYLOADS = {
    "photo/DCIM/IMG_0001.jpg": _jpg_bytes(),
    "photo/DCIM/IMG_0002.jpg": _jpg_bytes(),
    "photo/DCIM/IMG_0003.png": _png_bytes(),
    "video/Movies/VID_0001.mp4": _mp4_bytes(),
    "video/Movies/VID_0002.mp4": _mp4_bytes(),
}


# ---------------------------------------------------------------------------
# Schema A - KoBackup v10..v12, AES-256-CTR
# ---------------------------------------------------------------------------

def build_schema_a(root: Path, corrupt_info: bool = False):
    root.mkdir(parents=True, exist_ok=True)

    pwkey_salt = get_random_bytes(32)
    K = PBKDF2(PASSWORD.encode(), pwkey_salt[:16], 32, PBKDF2_ITER_BKEY, _prf_sha256)
    # bkey ist laut Schema ein 32-stelliger HEX-STRING (als UTF-8 bytes),
    # nicht beliebige Bytes.
    bkey_str = binascii.hexlify(get_random_bytes(16)).decode("utf-8")
    bkey_bytes = bkey_str.encode("utf-8")

    # WICHTIG: die GCM-Nonce des bkey-Schritts ist 16 Byte lang
    # (pwkey_salt[16:32]). Mit 12 Byte schlaegt der GCM-Tag fehl - das
    # wurde am echten Backup verifiziert (siehe RECOVERY-NOTES.md).
    nonce = pwkey_salt[16:32]
    cipher = AES.new(K, AES.MODE_GCM, nonce=nonce, mac_len=16)
    epbk_ct = cipher.encrypt(bkey_bytes)
    epbk = epbk_ct + cipher.digest()

    encmsgv3 = get_random_bytes(48)
    file_key, iv = derive_file_key_a(bkey_str, encmsgv3)

    from Crypto.Util import Counter

    def _new_ctr():
        # WICHTIG: jede Datei wird UNABHAENGIG verschluesselt - der
        # Counter startet pro Datei neu. Ein durchlaufender Counter
        # waere kein realistisches HiSuite-Backup und wuerde die
        # Verifikation verfaelschen.
        ctr = Counter.new(128, initial_value=int.from_bytes(iv[:16], "big"),
                          little_endian=False)
        return AES.new(file_key, AES.MODE_CTR, counter=ctr)

    session = root / "backupFiles1" / "20261104020000"
    session.mkdir(parents=True, exist_ok=True)

    for rel, data in PAYLOADS.items():
        dst = root / "media" / "20261104020000" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(_new_ctr().encrypt(data))

    # info.xml
    enc_hex = binascii.hexlify(encmsgv3).decode()
    info = f"""<?xml version="1.0" encoding="utf-8"?>
<root>
  <row table="BackupFilesTypeInfo">
    <column name="e_perbackupkey"><value String="{binascii.hexlify(epbk).decode()}"/></column>
    <column name="pwkey_salt"><value String="{binascii.hexlify(pwkey_salt).decode()}"/></column>
  </row>
  <row table="BackupFileModuleInfo_Media">
    <column name="name"><value String="media"/></column>
    <column name="encMsgV3"><value String="{enc_hex}"/></column>
  </row>
</root>
"""
    info_path = session / "info.xml"
    if corrupt_info:
        # Abbruch mitten im Attribut -> XML nicht wohlgeformt
        info = info.replace(enc_hex, enc_hex[:40])
        info_path.write_text(info, encoding="utf-8")
        # Rohtext-Rettung braucht den Wert noch irgendwo -> in cinfoset.dat
        # legen wir einen vollstaendigen Block ab (simuliert Vorhandensein)
        (root / "cinfoset.dat").write_bytes(
            binascii.hexlify(encmsgv3) + b"\x00" * 16)
    else:
        info_path.write_text(info, encoding="utf-8")

    return {"bkey": bkey_str, "encmsgv3": encmsgv3, "epbk": epbk,
            "pwkey_salt": pwkey_salt}


# ---------------------------------------------------------------------------
# Schema B - KoBackup v13 / HiSuite 11+, AES-256-GCM
# ---------------------------------------------------------------------------

def build_schema_b(root: Path, corrupt_info: bool = False):
    root.mkdir(parents=True, exist_ok=True)

    encmsgv3 = get_random_bytes(48)
    key, nonce = derive_key_b(PASSWORD, encmsgv3)

    for rel, data in PAYLOADS.items():
        dst = root / rel.replace("photo/", "photo/").replace("video/", "video/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce[:16], mac_len=16)
        ct = cipher.encrypt(data)
        dst.write_bytes(ct + cipher.digest())

    enc_hex = binascii.hexlify(encmsgv3).decode()
    info = f"""<?xml version="1.0" encoding="utf-8"?>
<root>
  <row table="BackupFileModuleInfo">
    <column name="name"><value String="media"/></column>
    <column name="encMsgV3"><value String="{enc_hex}"/></column>
  </row>
</root>
"""
    p = root / "check" / "info.xml"
    p.parent.mkdir(parents=True, exist_ok=True)
    if corrupt_info:
        p.write_text(info.replace(enc_hex, enc_hex[:40]), encoding="utf-8")
        # Realistischer Fall: cinfoset.dat ist eine KOPIE des Index und
        # kann unbeschaedigt sein, waehrend check/info.xml abgeschnitten
        # wurde. Genau danach sucht das Recovery-Tool.
        (root / "cinfoset.dat").write_bytes(
            info.encode("utf-16-le") + b"\x00" * 8)
    else:
        p.write_text(info, encoding="utf-8")

    return {"encmsgv3": encmsgv3}


def build_copy_file(root: Path):
    """Copy-File-Variante (isCopyFileEncrypt=true).

    Mediendateien werden nicht ueber encMsgV3 abgeleitet, sondern ueber
    eine EIGENE IV pro Datei aus der Multimedia-XML:

        Key = SHA256(bkey)[0:16]  (AES-128)
        IV  = der <Iv>-Wert der Datei
        Modus = AES-256-CTR

    Genau dieser Weg liess die WhatsApp-Sprachnachricht aus dem Modul
    `soundrecorder` bisher unentschluesselt.
    """
    root.mkdir(parents=True, exist_ok=True)

    pwkey_salt = get_random_bytes(32)
    K = PBKDF2(PASSWORD.encode(), pwkey_salt[:16], 32, PBKDF2_ITER_BKEY, _prf_sha256)
    bkey_str = binascii.hexlify(get_random_bytes(16)).decode("utf-8")

    # WICHTIG: die GCM-Nonce des bkey-Schritts ist 16 Byte lang
    # (pwkey_salt[16:32]). Mit 12 Byte schlaegt der GCM-Tag fehl - das
    # wurde am echten Backup verifiziert (siehe RECOVERY-NOTES.md).
    nonce = pwkey_salt[16:32]
    cipher = AES.new(K, AES.MODE_GCM, nonce=nonce, mac_len=16)
    epbk_ct = cipher.encrypt(bkey_str.encode("utf-8"))
    epbk = epbk_ct + cipher.digest()

    media_key = hashlib.sha256(bkey_str.encode("utf-8")).digest()[:16]

    from Crypto.Util import Counter

    media_files = {
        "/Sounds/AUD-20261026-WA0001---aaaa.ogg": _ogg_bytes(),
        "/Sounds/AUD-20261026-WA0002---bbbb.ogg": _ogg_bytes(),
    }

    files_xml = []
    for abs_path, data in media_files.items():
        # Eigene IV pro Datei.
        iv = get_random_bytes(16)
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"),
                          little_endian=False)
        enc = AES.new(media_key, AES.MODE_CTR, counter=ctr).encrypt(data)

        rel = abs_path.lstrip("/")
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(enc)

        files_xml.append("    <File><Path>%s</Path><Iv>%s</Iv></File>"
                         % (abs_path, binascii.hexlify(iv).decode()))

    multimedia = ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                  "<Multimedia>\n" + "\n".join(files_xml) + "\n</Multimedia>\n")
    (root / "multimedia.xml").write_text(multimedia, encoding="utf-8")

    enc_hex = binascii.hexlify(get_random_bytes(48)).decode()
    info = f"""<?xml version="1.0" encoding="utf-8"?>
<root>
  <row table="BackupFilesTypeInfo">
    <column name="e_perbackupkey"><value String="{binascii.hexlify(epbk).decode()}"/></column>
    <column name="pwkey_salt"><value String="{binascii.hexlify(pwkey_salt).decode()}"/></column>
  </row>
  <row table="BackupFileModuleInfo_Media">
    <column name="name"><value String="soundrecorder"/></column>
    <column name="encMsgV3"><value String="{enc_hex}"/></column>
  </row>
</root>
"""
    (root / "info.xml").write_text(info, encoding="utf-8")

    return {"bkey": bkey_str, "epbk": epbk, "pwkey_salt": pwkey_salt,
            "media_key": media_key}


def main():
    base = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/hw_test")
    if base.exists():
        shutil.rmtree(base)

    cases = [
        ("schema_a", lambda p: build_schema_a(p)),
        ("schema_a_corrupt", lambda p: build_schema_a(p, corrupt_info=True)),
        ("schema_b", lambda p: build_schema_b(p)),
        ("schema_b_corrupt", lambda p: build_schema_b(p, corrupt_info=True)),
        ("copy_file", lambda p: build_copy_file(p)),
    ]

    for name, builder in cases:
        d = base / name
        builder(d)
        n = sum(1 for _ in d.rglob("*") if _.is_file())
        print("  %-20s %d Dateien" % (name, n))

    print("\nPasswort: %s" % PASSWORD)


if __name__ == "__main__":
    main()
