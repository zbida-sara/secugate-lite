
import unittest

from src.collecte import (
    masquer_ip,
    masquer_parametres,
    normaliser_acces,
    normaliser_scan
)


class TestCollecte(unittest.TestCase):

    def test_masquer_ip(self):
        self.assertEqual(
            masquer_ip("192.168.1.15"),
            "192.168.1.x"
        )

    def test_ip_invalide(self):
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")

    def test_masquer_parametres(self):
        resultat = masquer_parametres("/api?id=3&token=abc123")
        self.assertEqual(
            resultat,
            "/api?id=3&token=[MASQUE]"
        )

    def test_plusieurs_parametres(self):
        resultat = masquer_parametres("/api?password=123&session=abc")
        self.assertEqual(
            resultat,
            "/api?password=[MASQUE]&session=[MASQUE]"
        )

    def test_normaliser_acces(self):
        ligne = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"
        sig = normaliser_acces(ligne, 42)

        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.type, "LOGIN_ECHEC")
        self.assertEqual(sig.gravite, "MOYENNE")
        self.assertEqual(sig.source, "ACCES")

    def test_acces_normal(self):
        ligne = "2026-10-05 10:00:00 10.0.0.5 GET /home 200"
        sig = normaliser_acces(ligne, 1)

        self.assertEqual(sig.type, "ACCES")
        self.assertEqual(sig.gravite, "FAIBLE")

    def test_acces_erreur(self):
        ligne = "2026-10-05 10:00:00 10.0.0.5 GET /api 500"
        sig = normaliser_acces(ligne, 2)

        self.assertEqual(sig.gravite, "ELEVEE")

    def test_ligne_invalide(self):
        with self.assertRaises(ValueError):
            normaliser_acces("ligne invalide", 1)

    def test_normaliser_scan(self):
        rapport = {
            "rule": "S3649",
            "component": "backend",
            "severity": "blocker",
            "message": "injection SQL possible",
            "date": "2026-10-05T10:05:00Z"
        }

        sig = normaliser_scan(rapport, 9)

        self.assertEqual(sig.id, "SIG-00009")
        self.assertEqual(sig.type, "FAILLE")
        self.assertEqual(sig.source, "SCAN")
        self.assertEqual(sig.gravite, "CRITIQUE")
        self.assertEqual(sig.cible, "backend")

    def test_scan_invalide(self):
        with self.assertRaises(ValueError):
            normaliser_scan({"rule": "S3649"}, 1)


if __name__ == "__main__":
    unittest.main()
