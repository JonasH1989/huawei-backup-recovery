#!/usr/bin/env python3
"""Huawei/Honor KoBackup - Recovery fuer unvollstaendige (abgebrochene) Backups.

Ziel: Bilder/Videos zurueckholen, auch wenn die Index-Datei (info.xml)
durch einen Abbruch mitten im Backup beschaedigt ist.

Hintergrund (reverse-engineered aus der KoBackup-/HiSuite-Implementierung):

  Schema A - KoBackup v10..v12 (AES-256-CTR)
    1. K        = PBKDF2-HMAC-SHA256(password, pwkey_salt[:16], 10000, 32)
    2. bkey     = AES-256-GCM(K, nonce=pwkey_salt[16:]).decrypt(e_perbackupkey[:32])
                   (e_perbackupkey[32:] ist der GCM-Tag -> Passwort-Pruefung)
    3. je Modul: seed = encMsgV3[:32], iv = encMsgV3[32:48]
       file_key = PBKDF2-HMAC-SHA256(bkey.encode('utf-8'), seed, 32, 5000)
    4. Datei    = AES-256-CTR(file_key, iv, big-endian counter)

  Schema B - KoBackup v13 / HiSuite 11+ (AES-256-GCM)
    aes_key = PBKDF2-HMAC-SHA256(password, encMsgV3[:32], 32, 5000)
    Datei   = ciphertext || 16-Byte-GCM-Tag, nonce = encMsgV3[32:48]

Wichtig fuer die Rettung:
  * Schema B braucht KEIN e_perbackupkey - der Schluessel folgt direkt aus
    Passwort + Salt. Damit reicht es, die encMsgV3-Bloecke zu bergen.
  * Schema A braucht e_perbackupkey + pwkey_salt. Beide muessen im
    geretteten XML-Fragment noch vorhanden sein.

Deshalb arbeitet das Tool mit zwei unabhaengigen Rettungswegen:
  1. Strukturierte Auswertung des (ggf. beschaedigten) XML.
  2. Rohtext-Suche nach den Hex-Bloecken im gesamten Backup, damit auch
     ein mitten im Attribut abgeschnittener Wert noch gefunden wird.

Anschliessend wird jede Datei mit jedem plausiblichen Schluessel
entschluesselt und anhand der Dateisignatur (JPEG/PNG/MP4/...)
verifiziert - das braucht weder Ordnerstruktur noch Index-Vollstaendigkeit.

Aufruf:
    # 1) Bestandsaufnahme (read-only, veraendert nichts)
    python3 huawei_backup_recover.py --inspect /pfad/zum/backup

    # 2) Entschluesselung
    HUAWEI_BACKUP_PASSWORD='...' python3 huawei_backup_recover.py \
        --recover /pfad/zum/backup --out /pfad/zum/ausgabe

    Passwort alternativ interaktiv eingeben (wird nicht in der History gespeichert).
"""
from __future__ import annotations

import argparse
import binascii
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    sys.exit("ERROR: pycryptodome wird benoetigt:  pip install pycryptodome")


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

GCM_TAG_LEN = 16
# Laenge der GCM-Nonce fuer den bkey-Schritt: 16 Byte (am echten
# Backup verifiziert). Mit 12 Byte schlaegt der GCM-Tag fehl.
BKEY_NONCE_LEN = 16
PBKDF2_ITER_BKEY = 10000     # Schema A: Passwort -> K
PBKDF2_ITER_FILE = 5000      # Schema A: bkey -> file_key
PBKDF2_ITER_V13 = 5000       # Schema B: Passwort -> aes_key

MODULE_TABLES = (
    "BackupFileModuleInfo",
    "BackupFileModuleInfo_Media",
    "BackupFileModuleInfo_SystemData",
)

# Dateisignaturen zur Verifikation der Entschluesselung
SIGNATURES = (
    (b"\xff\xd8\xff",                 ".jpg"),
    (b"\x89PNG\r\n\x1a\n",             ".png"),
    (b"SQLite format 3\x00",           ".db"),
    (b"RIFF",                          ".riff"),
    (b"\x1aE\xdf\xa3",                 ".mkv"),
    (b"fLaC",                          ".flac"),
    (b"ID3",                           ".mp3"),
    (b"OggS",                          ".ogg"),
    (b"<?xml",                         ".xml"),
    (b"PK\x03\x04",                    ".zip"),
)

# MP4/MOV: 'ftyp' steht bei Byte 4
MP4_BRANDS = (b"isom", b"mp42", b"mp41", b"isom", b"avc1", b"qt  ", b"MSNV", b"3gp")

# ---------------------------------------------------------------------------
# MPEG-Audio-Frame (fuer MP3 ohne ID3-Tag)
# ---------------------------------------------------------------------------

# Bitraten in kBit/s, Index = Bitratefeld (MPEG-1 Layer III zuerst).
_BITRATES = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0)
# Abtastraten MPEG 1 (Layer III) in Hz.
_SAMPLERATES_M1 = (44100, 48000, 32000, 0)
# Abtastraten MPEG 2 / 2.5 in Hz.
_SAMPLERATES_M2 = (22050, 24000, 16000, 0)


def _prf_sha256(p: bytes, s: bytes) -> bytes:
    return HMAC.new(p, s, SHA256).digest()


# ---------------------------------------------------------------------------
# Passwort
# ---------------------------------------------------------------------------

def get_password() -> str:
    pw = os.environ.get("HUAWEI_BACKUP_PASSWORD", "")
    if pw:
        return pw
    if sys.stdin.isatty():
        import getpass
        return getpass.getpass("Backup-Passwort: ")
    sys.exit("ERROR: Passwort fehlt. Setze HUAWEI_BACKUP_PASSWORD oder "
             "fuehre das Tool in einem Terminal aus.")


# ---------------------------------------------------------------------------
# Strukturierte XML-Auswertung
# ---------------------------------------------------------------------------

def _decode_index(raw: bytes) -> str:
    """UTF-8, UTF-16LE/BE (mit BOM) - der Index kann in jeder davon
    vorliegen."""
    if len(raw) >= 2:
        if raw[0] == 0xFF and raw[1] == 0xFE:
            return raw.decode("utf-16-le", errors="ignore")
        if raw[0] == 0xFE and raw[1] == 0xFF:
            return raw.decode("utf-16-be", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


_ROW_RE = re.compile(r"<row\s+table=\"([^\"]*)\"[^>]*>(.*?)</row>", re.S)
_COL_RE = re.compile(r"<column\s+name=\"([^\"]*)\"[^>]*>(.*?)</column>", re.S)
_VALUE_RE = re.compile(r"<value\s+([^>]*?)/?>")
_ATTR_RE = re.compile(r"(String|Integer|Long|Boolean)=\"([^\"]*)\"")


def _parse_columns(block: str) -> dict:
    """Liest alle <column name="X"><value .../> aus einem Block."""
    cols: dict[str, str] = {}
    for name, body in _COL_RE.findall(block):
        vm = _VALUE_RE.search(body)
        if not vm:
            continue
        am = _ATTR_RE.search(vm.group(1))
        if am:
            cols[name] = am.group(2)
    return cols


def parse_info_xml(xml_path: Path) -> dict:
    """Strukturiert auswerten - auch wenn das XML abgeschnitten ist.

    Ein abgebrochenes Backup endet mitten in einem Attribut. Ein
    strenger XML-Parser liefert dann gar nichts mehr, obwohl die
    vollstaendigen Zeilen davor vollstaendig lesbar sind. Deshalb wird
    der Index mit einem lockeren Zeilen-Parser ausgewertet: pro
    <row table="...">...</row> ein Block, unabhaengig davon, ob die
    Gesamtdokumentstruktur noch wohlgeformt ist.

    Wichtig: das fuehrt beim abgeschnittenen Index zu Werten, die
    vollstaendig sind - ein abgeschnittener encMsgV3 bleibt abgeschnitten
    und wird ueber die Rohtext-Rettung (salvage_truncated) gefuellt."""
    modules: dict[str, dict] = {}
    e_pbk = pwkey = None
    xml_ok = False

    try:
        raw = xml_path.read_bytes()
    except OSError:
        return {"modules": {}, "e_perbackupkey": None, "pwkey_salt": None,
                "xml_ok": False}

    text = _decode_index(raw)

    for table, block in _ROW_RE.findall(text):
        cols = _parse_columns(block)
        if table == "BackupFilesTypeInfo":
            e_pbk = e_pbk or cols.get("e_perbackupkey")
            pwkey = pwkey or cols.get("pwkey_salt")
        elif table in MODULE_TABLES:
            name = cols.get("name")
            if name and name.strip():
                modules.setdefault(name.strip(), {
                    "encMsgV3": (cols.get("encMsgV3") or "").strip(),
                    "checkMsgV3": (cols.get("checkMsgV3") or "").strip(),
                })
    if _ROW_RE.search(text):
        xml_ok = True

    if not xml_ok:
        print("  XML nicht lesbar/wohlgeformt -> Rohtext-Rettung")

    return {
        "modules": modules,
        "e_perbackupkey": e_pbk,
        "pwkey_salt": pwkey,
        "xml_ok": xml_ok,
    }


# ---------------------------------------------------------------------------
# Rohtext-Rettung (funktioniert auch bei abgeschnittenem XML)
# ---------------------------------------------------------------------------

HEX_RE = re.compile(rb"\b([0-9a-fA-F]{64,})\b")


def _decoded_variants(raw: bytes) -> list[bytes]:
    """Rohtext plus UTF-16-Dekodierungen.

    Index-Dateien koennen UTF-16LE/BE-kodiert sein. Dann sind die
    Hex-Zeichen von Nullbytes durchsetzt und ein Regex auf den
    Rohbytes greift nicht.
    """
    variants = [raw]
    if b"\x00" in raw[:400]:
        variants.append(raw.decode("utf-16-le", errors="ignore").encode("ascii", errors="ignore"))
        variants.append(raw.decode("utf-16-be", errors="ignore").encode("ascii", errors="ignore"))
    return variants


def salvage_hex_blobs(raw: bytes) -> list[str]:
    """Alle Hex-Bloecke >= 32 Byte (64 Hex-Zeichen) aus Rohdaten ziehen.

    Ein mitten im Attribut abgeschnittener Wert wird dabei NICHT gefunden
    (unvollstaendige Hex-Laenge). Fuer den Fall, dass der Abbruch genau
    dort passiert ist, gibt es zusaetzlich salvage_truncated().
    """
    out = []
    for variant in _decoded_variants(raw):
        for m in HEX_RE.finditer(variant):
            out.append(m.group(1).decode("ascii"))
    return out


def salvage_truncated(raw: bytes) -> list[str]:
    """Hex-Bloecke rekonstruieren, die am Dateiende abgeschnitten wurden.

    Ein Backup-Abbruch mitten in der Datei hinterlaesst oft einen
    angefangenen Hex-Wert. Wir finden alle Hex-Runs und ergaenzen sie um
    das erwartete Format, damit die Laengen passen (48 Byte = 96 Hex).
    Der fehlende Teil wird mit Nullen aufgefuellt; die GCM-Pruefung
    entscheidet, ob der Kandidat taugt.
    """
    found = []
    for src in _decoded_variants(raw):
        for m in re.finditer(rb"[0-9a-fA-F]{16,}", src):
            h = m.group(0).decode("ascii").lower()
            if len(h) >= 96:
                continue
            if len(h) % 2:
                h = h[:-1]
            found.append(h.ljust(96, "0"))
    return found


def collect_index_candidates(backup_root: Path) -> tuple[dict, list[str]]:
    """Alle index-relevanten Dateien finden und auswerten.

    Zwei unabhaengige Rettungswege:
      a) strukturierte XML-Auswertung (info.xml / cinfoset.dat)
      b) Rohtext-Suche nach Hex-Bloecken - im GEGENWERTIG in ALLEN
         Dateien des Backups, nicht nur in den Index-Dateien. Ein
         Backup bricht oft an genau einer Stelle ab; die Kopie des
         Index an anderer Stelle kann intakt sein.
    """
    index_files = []
    for name in ("info.xml", "cinfoset.dat", "backupinfo.ini", "index.xml",
                 "backupinfo.xml"):
        for p in backup_root.rglob(name):
            if p.is_file():
                index_files.append(p)

    modules: dict[str, dict] = {}
    e_pbk = pwkey = None
    blob_pool: list[str] = []

    for p in index_files:
        print("  Index-Datei: %s (%d Byte)" % (p.name, p.stat().st_size))
        try:
            raw = p.read_bytes()
        except OSError:
            continue

        if p.suffix.lower() == ".xml" or raw[:400].lstrip()[:5] == b"<?xml":
            info = parse_info_xml(p)
            if info["xml_ok"]:
                for k, v in info["modules"].items():
                    modules.setdefault(k, v)
                e_pbk = e_pbk or info["e_perbackupkey"]
                pwkey = pwkey or info["pwkey_salt"]

        blob_pool.extend(salvage_hex_blobs(raw))
        blob_pool.extend(salvage_truncated(raw))

    # Rohttext-Suche im GESAMTEN Backup
    index_set = {p.resolve() for p in index_files}
    scanned = 0
    for p in backup_root.rglob("*"):
        if not p.is_file() or p.resolve() in index_set:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size < 32 or size > 64 * 1024 * 1024:
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        scanned += 1
        found = salvage_hex_blobs(raw)
        if found:
            print("  Weitere Hex-Bloecke in: %s (%d Treffer)"
                  % (p.relative_to(backup_root), len(found)))
            blob_pool.extend(found)
    if scanned:
        print("  Rohtext-Suche ueber %d weitere Dateien" % scanned)

    # Deduplizieren, Reihenfolge stabil halten
    seen = set()
    unique = []
    for b in blob_pool:
        key = b.lower()
        if key not in seen:
            seen.add(key)
            unique.append(b)

    return (modules, e_pbk, pwkey), unique


# ---------------------------------------------------------------------------
# Schluessel-Ableitung
# ---------------------------------------------------------------------------

def derive_bkey(password: str, e_perbackupkey_hex: str, pwkey_salt_hex: str):
    """Schema A: bkey (Hex-String) aus Passwort ableiten.

    Wirft ValueError, wenn der GCM-Tag nicht passt -> falsches Passwort.
    """
    pw_salt = binascii.unhexlify(pwkey_salt_hex.strip())
    epbk = binascii.unhexlify(e_perbackupkey_hex.strip())
    if len(pw_salt) < 16 or len(epbk) < 32:
        raise ValueError("pwkey_salt/e_perbackupkey zu kurz")

    key_salt = pw_salt[:16]
    # WICHTIG: die GCM-Nonce des bkey-Schritts ist 16 Byte lang
    # (pwkey_salt[16:32]). Mit 12 Byte schlaegt der GCM-Tag fehl und das
    # Passwort wird faelschlich als falsch gemeldet. Am echten Backup
    # verifiziert (siehe docs/RECOVERY-NOTES.md).
    nonce = pw_salt[16:16 + BKEY_NONCE_LEN] if len(pw_salt) >= 16 + BKEY_NONCE_LEN \
        else pw_salt[16:]
    ct = epbk[:32]
    tag = epbk[32:48] if len(epbk) >= 48 else b""

    K = PBKDF2(password.encode("utf-8"), key_salt, 32, PBKDF2_ITER_BKEY, _prf_sha256)
    if tag:
        cipher = AES.new(K, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LEN)
        bkey_bytes = cipher.decrypt(ct)
        cipher.verify(tag)
    else:
        cipher = AES.new(K, AES.MODE_GCM, nonce=nonce)
        bkey_bytes = cipher.decrypt(ct)
    return bkey_bytes[:32].decode("utf-8", errors="replace")


def derive_file_key_a(bkey_str: str, encmsgv3: bytes) -> tuple[bytes, bytes]:
    """Schema A: (file_key, iv) fuer ein Modul."""
    seed = encmsgv3[:32]
    iv = encmsgv3[32:48]
    file_key = PBKDF2(bkey_str.encode("utf-8"), seed, 32, PBKDF2_ITER_FILE, _prf_sha256)
    return file_key, iv


def derive_key_b(password: str, encmsgv3: bytes) -> tuple[bytes, bytes]:
    """Schema B: (aes_key, nonce) fuer ein Modul."""
    seed = encmsgv3[:32]
    nonce = encmsgv3[32:48]
    key = PBKDF2(password.encode("utf-8"), seed, 32, PBKDF2_ITER_V13, _prf_sha256)
    return key, nonce


# ---------------------------------------------------------------------------
# Entschluesselung + Verifikation
# ---------------------------------------------------------------------------

def _is_mpeg_frame_sync(b: bytes, p: int) -> bool:
    """Prueft, ob an Position p ein gueltiger MPEG-Frame-Header steht.

    Ein Frame beginnt mit 11 Einsen. Danach folgen:
      Byte 1: 111 VV LL P   (Version, Layer, Protection)
      Byte 2: BBBB SS Pd    (Bitrate, Samplerate, Padding)

    Damit Zufallstreffer ausgeschlossen sind, muessen Layer und
    Version gueltig sein und Bitrate-/Samplerate-Index keine
    reservierten Werte tragen.
    """
    if p + 4 > len(b):
        return False
    b0, b1, b2 = b[p] & 0xFF, b[p + 1] & 0xFF, b[p + 2] & 0xFF
    if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
        return False
    version = (b1 >> 3) & 0x03
    layer = (b1 >> 1) & 0x03
    if version == 1 or layer == 0:
        return False
    bitrate_index = (b2 >> 4) & 0x0F
    samplerate_index = (b2 >> 2) & 0x03
    return bitrate_index != 0x0F and samplerate_index != 3


def _mpeg_frame_length(b: bytes, p: int) -> int:
    """Berechnet die Laenge eines MPEG-Frames in Byte (0 = unbestimmbar)."""
    if p + 4 > len(b):
        return 0
    b1, b2 = b[p + 1] & 0xFF, b[p + 2] & 0xFF
    version = (b1 >> 3) & 0x03
    layer = (b1 >> 1) & 0x03
    bitrate_index = (b2 >> 4) & 0x0F
    samplerate_index = (b2 >> 2) & 0x03
    padding = (b2 >> 1) & 0x01
    bitrate = _BITRATES[bitrate_index]
    samplerate = (_SAMPLERATES_M1[samplerate_index] if version == 3
                  else _SAMPLERATES_M2[samplerate_index])
    if bitrate == 0 or samplerate == 0:
        return 0
    if layer == 3:
        return (12 * bitrate * 1000 // samplerate + padding) * 4
    if layer == 2:
        return 144 * bitrate * 1000 // samplerate + padding
    if version == 3:
        return 144 * bitrate * 1000 // samplerate + padding
    return 72 * bitrate * 1000 // samplerate + padding


def _count_mpeg_frames(b: bytes, p: int) -> int:
    """Zaehlt aufeinanderfolgende gueltige MPEG-Frames ab Position p."""
    count = 0
    while p + 4 <= len(b) and count < 64:
        if not _is_mpeg_frame_sync(b, p):
            break
        length = _mpeg_frame_length(b, p)
        if length < 4:
            break
        count += 1
        p += length
    return count


def _looks_like_mp3_stream(head: bytes) -> bool:
    """Prueft, ob der Anfang eine Folge gueltiger MPEG-Audio-Frames ist.

    WICHTIG: ein einzelner Sync reicht NICHT als Beweis. In Zufallsdaten
    tritt 0xFFEx alle ~5.600 Byte auf - bei einer 4-KB-Probe waere ein
    Fehlalarm wahrscheinlich. Deshalb werden mindestens drei
    aufeinanderfolgende Frames an den erwarteten Positionen geprueft.
    """
    if len(head) < 32:
        return False
    start = 0
    if head[:3] == b"ID3":
        if len(head) < 10:
            return False
        size = ((head[6] & 0x7F) << 21) | ((head[7] & 0x7F) << 14) \
            | ((head[8] & 0x7F) << 7) | (head[9] & 0x7F)
        start = 10 + size
        if start >= len(head):
            # Der ID3-Header allein gilt als Beweis.
            return True
    return _count_mpeg_frames(head, start) >= 3


def detect_extension(head: bytes) -> str | None:
    for sig, ext in SIGNATURES:
        if head.startswith(sig):
            return ext
    if len(head) >= 12 and head[4:8] == b"ftyp" and head[8:12] in MP4_BRANDS:
        return ".mp4"
    # MP3 ohne ID3-Tag: der MPEG-Frame-Sync beginnt direkt.
    # Wichtig fuer Huawei-Sprachnachrichten, die oft ohne ID3
    # gespeichert werden.
    if _looks_like_mp3_stream(head):
        return ".mp3"
    return None


def try_decrypt_a(file_key: bytes, iv: bytes, data: bytes,
                  has_tag: bool = False) -> bytes | None:
    """AES-256-CTR (Schema A). Kein Tag - has_tag wird ignoriert."""
    try:
        from Crypto.Util import Counter
        if len(iv) < 16:
            iv = iv.ljust(16, b"\x00")
        ctr = Counter.new(128, initial_value=int.from_bytes(iv[:16], "big"),
                          little_endian=False)
        cipher = AES.new(file_key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(data)
    except Exception:
        return None


def try_decrypt_b(key: bytes, nonce: bytes, data: bytes,
                  has_tag: bool = False) -> bytes | None:
    """AES-256-GCM (Schema B).

    WICHTIG: Bei Schema B steht der 16-Byte-GCM-Tag am Dateiende. Er ist
    KEIN Chiffrat und gehoert NICHT zum Klartext. Wird er mitentschluesselt,
    bekommt die Ausgabe 16 Byte zu viel (z.B. ein 16-Byte-Schluss an ein
    JPEG) und die Datei ist kaputt. Bei has_tag=True wird er abgetrennt.

    Fuer die Signaturpruefung wird nur ein Dateianfang gelesen (kein Tag
    vorhanden) -> has_tag=False.
    """
    try:
        if len(nonce) < 12:
            nonce = nonce.ljust(12, b"\x00")
        ct = data
        if has_tag:
            if len(data) <= GCM_TAG_LEN:
                return None
            ct = data[:-GCM_TAG_LEN]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce[:16], mac_len=GCM_TAG_LEN)
        return cipher.decrypt(ct)
    except Exception:
        return None


def verify_gcm_tag(key: bytes, nonce: bytes, data: bytes) -> bool:
    """Prueft den GCM-Tag einer vollstaendigen Schema-B-Datei.

    True  = Datei ist authentifiziert (Schluessel stimmt, Datei intakt).
    False = Tag passt nicht. Das kann am falschen Schluessel liegen ODER
            an einer abgebrochenen Datei (Backup-Abbruch) - der Klartext
            ist dann trotzdem gueltig und wird geschrieben.
    """
    try:
        if len(data) <= GCM_TAG_LEN:
            return False
        if len(nonce) < 12:
            nonce = nonce.ljust(12, b"\x00")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce[:16], mac_len=GCM_TAG_LEN)
        cipher.decrypt(data[:-GCM_TAG_LEN])
        cipher.verify(data[-GCM_TAG_LEN:])
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Media-Index (Copy-Files / Multimedia-XML)
# ---------------------------------------------------------------------------
#
# Mediendateien (Audio/Foto/Video) werden in manchen Backup-Versionen
# nicht ueber encMsgV3 abgeleitet, sondern ueber eine EIGENE IV pro
# Datei aus einer Multimedia-XML:
#
#   <Multimedia><File><Path>/Sounds/AUD-....mp3</Path><Iv>HEX</Iv></File></Multimedia>
#
# Key = SHA256(bkey)[0:16] (AES-128), Modus = AES-256-CTR.
# Ohne diese XML bleibt die Datei unentschluesselbar - die IV laesst
# sich nicht aus der Datei ableiten.

_MULTIMEDIA_ROOT_RE = re.compile(r"<Multimedia\b", re.IGNORECASE)
_PATH_TAG_RE = re.compile(r"<Path>\s*(.*?)\s*</Path>", re.S)
_IV_TAG_RE = re.compile(r"<Iv>\s*([0-9a-fA-F]+)\s*</Iv>", re.S)
_MAX_XML_BYTES = 32 * 1024 * 1024


def _normalize_path(p: str) -> str:
    """Vereinheitlicht Pfade: Trennzeichen, fuehrende Trenner, './'.

    Kleinschreibung, weil der Index und das Dateisystem unterschiedliche
    Gross-/Kleinschreibung verwenden koennen.
    """
    s = p.replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    s = s.lstrip("/")
    return s.lower()


def _read_text_fallback(p: Path) -> str:
    """Liest eine Datei als Text (UTF-8, Fallback ISO-8859-1/BOM)."""
    raw = p.read_bytes()
    if raw[:2] == b"\xff\xfe":
        return raw.decode("utf-16-le", errors="ignore")
    if raw[:2] == b"\xfe\xff":
        return raw.decode("utf-16-be", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


class MediaIndex:
    """Zuordnung Dateipfad -> IV aus den Multimedia-Indizes des Backups."""

    def __init__(self) -> None:
        self.path_to_iv: dict[str, str] = {}
        self.source_files: list[str] = []

    # -- Aufbau ----------------------------------------------------------

    @classmethod
    def scan(cls, root: Path) -> "MediaIndex":
        """Durchsucht das Backup nach Multimedia-Indizes."""
        index = cls()
        for p in root.rglob("*.xml"):
            try:
                if not p.is_file() or p.stat().st_size > _MAX_XML_BYTES:
                    continue
                xml = _read_text_fallback(p)
            except OSError:
                continue
            if not _MULTIMEDIA_ROOT_RE.search(xml):
                continue
            index.parse(xml)
            index.source_files.append(str(p))
        return index

    def parse(self, xml: str) -> None:
        """Parst eine Multimedia-XML.

        Die Datei kann abgeschnitten sein. Deshalb wird nicht auf eine
        vollstaendige Struktur vertraut, sondern jedes <File>-Segment
        einzeln ausgewertet: ein Block mit <Path> und <Iv> ist auch dann
        nutzbar, wenn der Rest abgeschnitten wurde.
        """
        pos = 0
        while True:
            start = xml.find("<File", pos)
            if start < 0:
                break
            end = xml.find("</File>", start)
            block = xml[start:] if end < 0 else xml[start:end]
            pos = len(xml) if end < 0 else end + len("</File>")

            pm = _PATH_TAG_RE.search(block)
            if not pm:
                continue
            path = pm.group(1).strip()
            if not path:
                continue
            vm = _IV_TAG_RE.search(block)
            if not vm:
                # Abgeschnittene IV - die Datei bleibt unentschluesselbar.
                continue
            iv = vm.group(1).strip()
            if len(iv) < 32:
                continue
            self.path_to_iv[_normalize_path(path)] = iv

    # -- Abfrage ---------------------------------------------------------

    def iv_for(self, file: Path, backup_root: Path) -> str | None:
        """Liefert die IV zu einer Datei im Backup.

        Der Pfad wird in mehreren Schreibweisen gesucht, weil der
        absolute Pfad aus der XML und der relative Pfad im Backup selten
        identisch sind.
        """
        candidates: list[str] = []
        try:
            rel = file.relative_to(backup_root)
            candidates.append(_normalize_path(str(rel)))
        except ValueError:
            pass
        name = file.name
        candidates.append(_normalize_path(name))
        # Ohne Suffix - der Index nennt oft den Namen ohne Endung.
        dot = name.rfind(".")
        stem = name[:dot] if dot > 0 else name
        candidates.append(_normalize_path(stem))
        parent = file.parent.name if file.parent else ""
        if parent:
            candidates.append(_normalize_path(parent + "/" + name))
            # Der Index nennt haeufig den Pfad OHNE Endung, das Dateisystem
            # hat sie. Deshalb auch die Kombination Ordner/Name-ohne-Endung.
            candidates.append(_normalize_path(parent + "/" + stem))

        for c in candidates:
            iv = self.path_to_iv.get(c)
            if iv is not None:
                return iv

        # Notfalls ueber das Dateiende der Pfadliste suchen.
        file_key = _normalize_path(name)
        for key, iv in self.path_to_iv.items():
            if key and (key.endswith("/" + file_key) or key == file_key):
                return iv
        return None

    def size(self) -> int:
        return len(self.path_to_iv)

    def entries(self) -> dict[str, str]:
        return self.path_to_iv


def derive_media_key(bkey: str) -> bytes:
    """Copy-File-/Media-Key: SHA256(bkey)[0:16] (AES-128)."""
    import hashlib
    return hashlib.sha256(bkey.encode("utf-8")).digest()[:16]


# ---------------------------------------------------------------------------
# Schluessel-Kandidaten
# ---------------------------------------------------------------------------

def build_candidates(password: str, modules: dict, e_pbk, pwkey,
                     blob_pool: list[str]) -> tuple[list[tuple[str, bytes, bytes]], str | None]:
    """Alle plausiblen (Schluessel, iv)-Kandidaten erzeugen.

    Rueckgabe: (Kandidaten, bkey). Der bkey wird zusaetzlich zurueckgegeben,
    weil der Copy-File-/Media-Weg ihn braucht (Key = SHA256(bkey)[0:16]).
    """
    cands: list[tuple[str, bytes, bytes]] = []
    seen = set()

    def add(label: str, key: bytes, iv: bytes):
        h = (label, key, iv)
        if h not in seen:
            seen.add(h)
            cands.append((label, key, iv))

    # 1) Schema B direkt aus Passwort - benoetigt nur den Salt
    salts: list[bytes] = []
    for name, mod in modules.items():
        h = (mod.get("encMsgV3") or "").strip()
        if len(h) >= 64:
            try:
                b = binascii.unhexlify(h[:96].ljust(96, "0"))
                if len(b) == 48:
                    salts.append(b)
            except binascii.Error:
                pass
    for b in blob_pool:
        try:
            raw = binascii.unhexlify(b[:96].ljust(96, "0"))
            if len(raw) == 48:
                salts.append(raw)
        except binascii.Error:
            pass

    for enc in salts:
        try:
            key, nonce = derive_key_b(password, enc)
            add("B(passwort)", key, nonce)
        except Exception:
            pass

    # 2) Schema A - braucht bkey
    bkey = None
    if e_pbk and pwkey:
        try:
            bkey = derive_bkey(password, e_pbk, pwkey)
            print("  bkey erfolgreich abgeleitet (GCM-Tag gueltig)")
        except Exception as exc:
            print("  bkey nicht ableitbar (%s)" % exc)
    if bkey:
        for enc in salts:
            try:
                key, iv = derive_file_key_a(bkey, enc)
                add("A(bkey)", key, iv)
            except Exception:
                pass

    return cands, bkey


# ---------------------------------------------------------------------------
# Datei-Walk
# ---------------------------------------------------------------------------

SKIP_NAMES = {"info.xml", "cinfoset.dat", "backupinfo.ini", "index.xml",
               "backupinfo.xml", "readme.txt", "readme"}


def collect_payload_files(backup_root: Path) -> list[Path]:
    """Alle Dateien, die Inhalt sein koennten (keine Index-Dateien)."""
    out = []
    for p in backup_root.rglob("*"):
        if not p.is_file():
            continue
        if p.name.lower() in SKIP_NAMES:
            continue
        try:
            if p.stat().st_size < 32:
                continue
        except OSError:
            continue
        out.append(p)
    return out


# ---------------------------------------------------------------------------
# Hauptprogramm
# ---------------------------------------------------------------------------

def cmd_inspect(args) -> int:
    root = Path(args.backup).resolve()
    print("Backup: %s" % root)
    if not root.is_dir():
        print("ERROR: Verzeichnis existiert nicht")
        return 1

    print("\n=== Verzeichnisstruktur (Tiefe 3) ===")
    for p in sorted(root.rglob("*"))[:400]:
        rel = p.relative_to(root)
        if len(rel.parts) > 3:
            continue
        if p.is_dir():
            print("  [d] %s" % rel)
        else:
            print("      %-60s %10d Byte" % (str(rel)[:60], p.stat().st_size))

    print("\n=== Index-Auswertung ===")
    (modules, e_pbk, pwkey), blob_pool = collect_index_candidates(root)
    print("  Module mit encMsgV3 (strukturiert): %d" % len(modules))
    for name, mod in list(modules.items())[:20]:
        enc = mod.get("encMsgV3") or ""
        print("    %-24s encMsgV3=%s..." % (name[:24], enc[:24]))
    print("  e_perbackupkey: %s" % ("vorhanden" if e_pbk else "FEHLT"))
    print("  pwkey_salt    : %s" % ("vorhanden" if pwkey else "FEHLT"))
    print("  Hex-Bloecke per Rohtext-Rettung: %d" % len(blob_pool))

    payloads = collect_payload_files(root)
    print("\n=== Nutzdaten ===")
    print("  Dateien gesamt: %d" % len(payloads))
    total = 0
    for p in payloads:
        try:
            total += p.stat().st_size
        except OSError:
            pass
    print("  Summe: %.1f MB" % (total / 1024 / 1024))

    exts = {}
    for p in payloads:
        exts[p.suffix.lower()] = exts.get(p.suffix.lower(), 0) + 1
    print("  Endungen: %s" % ", ".join("%s=%d" % (k or "(none)", v)
                                      for k, v in sorted(exts.items(),
                                                        key=lambda x: -x[1])[:12]))

    print("\n=== Passwort-Probe (nur lesend, entschluesselt nichts) ===")
    pw = get_password()
    cands, bkey = build_candidates(pw, modules, e_pbk, pwkey, blob_pool)
    print("  Schluessel-Kandidaten: %d" % len(cands))
    if not cands:
        print("  -> KEIN Schluessel ableitbar. Es fehlt entweder das Passwort")
        print("     oder e_perbackupkey/pwkey_salt UND alle Salt-Bloecke.")
        return 2

    # Ersten Kandidaten gegen ein paar Dateien testen
    hits = 0
    for p in payloads[:400]:
        try:
            head = p.open("rb").read(4096)
        except OSError:
            continue
        for label, key, iv in cands:
            for dec, mode in ((try_decrypt_b(key, iv, head), "B"),
                              (try_decrypt_a(key, iv, head), "A")):
                if dec and detect_extension(dec[:64]):
                    hits += 1
                    print("  TREFFER: %s -> Schema %s (%s) erkennt %s"
                          % (p.name, mode, label, detect_extension(dec[:64])))
                    break
            if hits >= 5:
                break
        if hits >= 5:
            break
    if hits == 0:
        print("  -> noch kein Treffer in den ersten 400 Dateien")
    return 0


def cmd_recover(args) -> int:
    root = Path(args.backup).resolve()
    out_root = Path(args.out).resolve()
    if not root.is_dir():
        print("ERROR: Verzeichnis existiert nicht")
        return 1

    print("Backup: %s" % root)
    print("Output: %s" % out_root)
    print("\n=== Index-Auswertung ===")
    (modules, e_pbk, pwkey), blob_pool = collect_index_candidates(root)
    print("  Module strukturiert: %d | Hex-Bloecke gerettet: %d"
          % (len(modules), len(blob_pool)))
    print("  e_perbackupkey: %s | pwkey_salt: %s"
          % ("ja" if e_pbk else "NEIN", "ja" if pwkey else "NEIN"))

    pw = get_password()
    cands, bkey = build_candidates(pw, modules, e_pbk, pwkey, blob_pool)
    print("  Schluessel-Kandidaten: %d" % len(cands))
    if not cands and not bkey:
        print("ERROR: kein Schluessel ableitbar")
        return 2

    # Copy-File-/Media-Weg: eigene IV pro Datei aus der Multimedia-XML.
    media_index = MediaIndex.scan(root)
    print("  Multimedia-XML: %d | IVs: %d"
          % (len(media_index.source_files), media_index.size()))
    media_key = derive_media_key(bkey) if bkey else None

    payloads = collect_payload_files(root)
    print("\n=== Entschluesselung (%d Dateien) ===" % len(payloads))

    out_root.mkdir(parents=True, exist_ok=True)
    ok = fail = 0
    by_ext: dict[str, int] = {}

    for i, p in enumerate(payloads, 1):
        try:
            raw = p.read_bytes()
        except OSError:
            fail += 1
            continue

        head = raw[:4096]
        done = False

        # Copy-File-/Media-Kandidat: eigene IV aus der Multimedia-XML,
        # Key = SHA256(bkey)[0:16]. Muss VOR den Modul-Kandidaten
        # probiert werden - eine Mediendatei gehoert zu keinem Modul
        # und wuerde sonst nie getroffen.
        if media_key is not None:
            iv_hex = media_index.iv_for(p, root)
            if iv_hex:
                try:
                    media_iv = binascii.unhexlify(iv_hex)
                except binascii.Error:
                    media_iv = b""
                if len(media_iv) >= 16:
                    dec = try_decrypt_a(media_key, media_iv, head, has_tag=False)
                    if dec:
                        ext = detect_extension(dec[:64])
                        if ext:
                            full = try_decrypt_a(media_key, media_iv, raw,
                                                 has_tag=False)
                            if full is not None:
                                rel = p.relative_to(root)
                                stem = rel.stem if rel.suffix else rel.name
                                dst = out_root / rel.parent / (stem + ext)
                                dst.parent.mkdir(parents=True, exist_ok=True)
                                dst.write_bytes(full)
                                ok += 1
                                by_ext[ext] = by_ext.get(ext, 0) + 1
                                print("  [%d/%d] %-46s -> %s (Copy-File)"
                                      % (i, len(payloads), rel.name[:46], ext))
                                done = True

        if done:
            continue

        for label, key, iv in cands:
            # Schema B: GCM-Tag steht am Dateiende -> muss abgetrennt
            # werden, sonst haengt 16 Byte Muell an der Datei.
            for dec_fn, mode, has_tag in ((try_decrypt_b, "B", True),
                                          (try_decrypt_a, "A", False)):
                dec = dec_fn(key, iv, head, has_tag=False)
                if not dec:
                    continue
                ext = detect_extension(dec[:64])
                if not ext:
                    continue

                # vollstaendig entschluesseln
                full = dec_fn(key, iv, raw, has_tag=has_tag)
                if full is None:
                    continue

                # Integritaet pruefen (Schema B). Bei einer durch den
                # Backup-Abbruch verkuerzten Datei passt der Tag nicht -
                # der Klartext ist aber trotzdem gueltig und wird gerettet.
                intact = None
                if mode == "B":
                    intact = verify_gcm_tag(key, iv, raw)

                rel = p.relative_to(root)
                stem = rel.stem if rel.suffix else rel.name
                dst = out_root / rel.parent / (stem + ext)
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(full)
                ok += 1
                by_ext[ext] = by_ext.get(ext, 0) + 1
                mark = ""
                if intact is False:
                    mark = " [Tag passt nicht - Datei evtl. unvollstaendig]"
                elif intact is True:
                    mark = " [authentifiziert]"
                print("  [%d/%d] %-46s -> %s (%s)%s"
                      % (i, len(payloads), rel.name[:46], ext, mode, mark))
                done = True
                break
            if done:
                break

        if not done:
            fail += 1
            if i % 50 == 0:
                print("  [%d/%d] ... %d ok, %d nicht entschluesselbar"
                      % (i, len(payloads), ok, fail))

    print("\n=== Ergebnis ===")
    print("  entschluesselt: %d | nicht entschluesselbar: %d" % (ok, fail))
    if by_ext:
        print("  nach Typ: %s" % ", ".join("%s=%d" % (k, v)
                                         for k, v in sorted(by_ext.items(),
                                                            key=lambda x: -x[1])))
    print("  Ausgabe: %s" % out_root)
    if ok == 0:
        print("\n  Keine Datei liess sich entschluesseln. Moegliche Gruende:")
        print("   - falsches Passwort")
        print("   - beide Schluessel-Arten fehlen (e_perbackupkey + alle Salts)")
        print("   - anderes Verschluesselungsverfahren (dann: Datei-Header hexdump)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Recovery fuer unvollstaendige Huawei/Honor KoBackup-Backups",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("backup", help="Verzeichnis des Backups")
    ap.add_argument("--inspect", action="store_true",
                    help="nur Bestandsaufnahme, entschluesselt nichts")
    ap.add_argument("--recover", action="store_true",
                    help="entschluesseln und nach --out schreiben")
    ap.add_argument("--out", help="Ausgabeverzeichnis (mit --recover)")
    args = ap.parse_args()

    if args.recover:
        if not args.out:
            sys.exit("ERROR: --out fehlt")
        return cmd_recover(args)
    return cmd_inspect(args)


if __name__ == "__main__":
    sys.exit(main())
