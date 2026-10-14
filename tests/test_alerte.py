import unittest
from src.alerte import alerter, choisir_canal, rediger, valider_action
from src.contrat import Signal, Verdict


class TestAlerte(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITIQUE"), "TELEPHONE")
        self.assertEqual(choisir_canal("ELEVEE"), "SLACK")
        self.assertEqual(choisir_canal("MOYENNE"), "EMAIL")
        self.assertEqual(choisir_canal("FAIBLE"), "TABLEAU")

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            choisir_canal("X")


if __name__ == "__main__":
    unittest.main()