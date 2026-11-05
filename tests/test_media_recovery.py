#!/usr/bin/env python3
"""Tests fuer die Copy-File-/Media-Logik im Python-Recovery-Tool.

Hintergrund (2026-11-05):
Die Java-Variante des Recovery-Tools hatte bereits eine vollstaendige
Copy-File-Logik (MediaIndex + buildMediaCandidate), das Python-Pendant
nur nicht. Deshalb blieb die WhatsApp-Sprachnachricht aus dem Modul
`soundrecorder` (isCopyFileEncrypt=true) unentschluesselt, obwohl der
Weg technisch bekannt war.

Der Weg:
  Key = SHA256(bkey)[0:16]  (AES-128)
  IV  = eigene IV pro Datei aus der Multimedia-XML
  Modus = AES-256-CTR

Diese Tests decken ab:
  1) MediaIndex: findet <Path>/<Iv>-Paare, auch in abgeschnittenen XML.
  2) Pfadaufloesung ueber mehrere Schreibweisen.
  3) derive_media_key: SHA256(bkey)[0:16].
  4) OGG-Erkennung (fehlte im Python-Tool komplett).
  5) MP3-Erkennung ohne ID3-Tag ueber Frame-Kette (fehlte ebenfalls).
"""
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import huawei_backup_recover as rec


class TestMediaIndexParsing(unittest.TestCase):

    def test_parses_path_iv_pairs(self):
        xml = ("<Multimedia>"
               "<File><Path>/Sounds/AUD-1.mp3</Path><Iv>aabbccdd00112233445566778899aabbccdd</Iv></File>"
               "<File><Path>/Media/photo.jpg</Path><Iv>1122334400112233445566778899aabbccdd</Iv></File>"
               "</Multimedia>")
        idx = rec.MediaIndex()
        idx.parse(xml)
        self.assertEqual(idx.size(), 2)
        self.assertEqual(idx.entries()["sounds/aud-1.mp3"], "aabbccdd00112233445566778899aabbccdd")
        self.assertEqual(idx.entries()["media/photo.jpg"], "1122334400112233445566778899aabbccdd")

    def test_ignores_file_without_iv(self):
        """Abgeschnittene IV -> Datei bleibt unentschluesselbar."""
        xml = ("<Multimedia>"
               "<File><Path>/Sounds/AUD-1.mp3</Path>"
               "<Iv>aabbccdd00112233445566778899aabbccdd</Iv></File>"
               "<File><Path>/Sounds/AUD-2.mp3</Path></File>"
               "</Multimedia>")
        idx = rec.MediaIndex()
        idx.parse(xml)
        # Nur der erste Block hat eine IV; der zweite wird verworfen.
        self.assertEqual(idx.size(), 1)
        self.assertNotIn("sounds/aud-2.mp3", idx.entries())

    def test_rejects_short_iv(self):
        xml = "<Multimedia><File><Path>/x.mp3</Path><Iv>ab</Iv></File></Multimedia>"
        idx = rec.MediaIndex()
        idx.parse(xml)
        self.assertEqual(idx.size(), 0)

    def test_handles_truncated_xml(self):
        """Die XML kann mitten im Block abgeschnitten sein."""
        xml = ("<Multimedia>"
               "<File><Path>/Sounds/good.mp3</Path><Iv>aabbccdd00112233445566778899aabbccdd</Iv></File>"
               "<File><Path>/Sounds/trunc.mp3</Path><Iv>aabbccdd00112233445566778899aabbccdd")
        idx = rec.MediaIndex()
        idx.parse(xml)
        self.assertEqual(idx.size(), 1)
        self.assertIn("sounds/good.mp3", idx.entries())

    def test_normalize_path(self):
        self.assertEqual(rec._normalize_path("/Sounds/AUD.mp3"), "sounds/aud.mp3")
        self.assertEqual(rec._normalize_path("./a/b/../c"), "a/b/../c")
        self.assertEqual(rec._normalize_path("a\\b"), "a/b")


class TestMediaIndexLookup(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "Sounds").mkdir()
        self.target = self.root / "Sounds" / "AUD-1.mp3"
        self.target.write_bytes(b"x" * 64)

    def tearDown(self):
        self.tmp.cleanup()

    def _index(self):
        idx = rec.MediaIndex()
        idx.parse("<Multimedia>"
                  "<File><Path>/Sounds/AUD-1.mp3</Path><Iv>aabbccdd00112233445566778899aabbccdd</Iv></File>"
                  "</Multimedia>")
        return idx

    def test_finds_by_relative_path(self):
        idx = self._index()
        self.assertEqual(idx.iv_for(self.target, self.root), "aabbccdd00112233445566778899aabbccdd")

    def test_finds_by_filename_only(self):
        idx = self._index()
        other = self.root / "anders" / "AUD-1.mp3"
        self.assertEqual(idx.iv_for(other, self.root), "aabbccdd00112233445566778899aabbccdd")

    def test_finds_by_name_without_suffix(self):
        idx = rec.MediaIndex()
        idx.parse("<Multimedia>"
                  "<File><Path>/Sounds/AUD-1</Path><Iv>deadbeefdeadbeefdeadbeefdeadbeef</Iv></File>"
                  "</Multimedia>")
        self.assertEqual(idx.iv_for(self.target, self.root), "deadbeefdeadbeefdeadbeefdeadbeef")

    def test_unknown_file_returns_none(self):
        idx = self._index()
        other = self.root / "Sounds" / "other.mp3"
        self.assertIsNone(idx.iv_for(other, self.root))


class TestMediaKey(unittest.TestCase):

    def test_is_sha256_prefix_16(self):
        bkey = "some-bkey-string"
        expected = hashlib.sha256(bkey.encode("utf-8")).digest()[:16]
        self.assertEqual(rec.derive_media_key(bkey), expected)
        self.assertEqual(len(rec.derive_media_key(bkey)), 16)


class TestMediaIndexScan(unittest.TestCase):

    def test_scan_finds_multimedia_xml(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "multimedia.xml").write_text(
                "<Multimedia><File><Path>/a.mp3</Path>"
                "<Iv>aabbccdd00112233445566778899aabbccdd</Iv></File></Multimedia>")
            (root / "irrelevant.xml").write_text("<root><a/></root>")
            idx = rec.MediaIndex.scan(root)
            self.assertEqual(idx.size(), 1)
            self.assertEqual(len(idx.source_files), 1)


class TestSignatureDetection(unittest.TestCase):

    def test_detects_ogg(self):
        """OGG fehlte im Python-Tool komplett - WhatsApp nutzt Ogg/Opus."""
        head = b"OggS" + b"\x00" * 60
        self.assertEqual(rec.detect_extension(head), ".ogg")

    def test_detects_jpeg_png_db(self):
        self.assertEqual(rec.detect_extension(b"\xff\xd8\xff\xe0" + b"\x00" * 60), ".jpg")
        self.assertEqual(rec.detect_extension(b"\x89PNG\r\n\x1a\n" + b"\x00" * 60), ".png")
        self.assertEqual(rec.detect_extension(b"SQLite format 3\x00" + b"\x00" * 60), ".db")

    def test_random_data_is_not_mp3(self):
        """Zufallsdaten duerfen nicht als MP3 durchgehen (Fehlalarm-Schutz)."""
        import os as _os
        rnd = _os.urandom(4096)
        self.assertIsNone(rec.detect_extension(rnd))

    def test_mp3_frame_chain_detected(self):
        """Drei aufeinanderfolgende gueltige MPEG-Frames = MP3."""
        # MPEG-1 Layer III, 128 kBit/s, 44100 Hz -> Frame-Laenge 417 Byte
        header = bytes([0xFF, 0xFB, 0x90, 0x00])  # sync, Layer III, 128k/44.1k
        frame_len = 417
        head = b""
        for _ in range(4):
            head += header + b"\x00" * (frame_len - 4)
        self.assertEqual(rec.detect_extension(head), ".mp3")

    def test_single_sync_is_not_enough(self):
        """Ein einzelner 0xFFEx reicht nicht - sonst Fehlalarm."""
        head = b"\xff\xfb\x90\x00" + b"\x00" * 4092
        self.assertIsNone(rec.detect_extension(head))


class TestBuildCandidatesReturnsBkey(unittest.TestCase):

    def test_returns_tuple_with_bkey(self):
        """build_candidates liefert jetzt (Kandidaten, bkey)."""
        cands, bkey = rec.build_candidates("pw", {}, None, None, [])
        self.assertIsInstance(cands, list)
        self.assertIsNone(bkey)


if __name__ == "__main__":
    unittest.main(verbosity=2)
