import unittest
from src.alerte import alerter, choisir_canal, rediger, valider_action
from src.contrat import Signal, Verdict

def exemple(sensible=True, niveau="CRITIQUE"):
    s = Signal("SIG-00125", "2026-10-05T10:01:31Z", "ACCES", "192.168.1.15",
               "web-app", "LOGIN_ECHEC", "MOYENNE",
               "POST /login -> 401 depuis 192.168.1.x")
    v = Verdict("SIG-00125", niveau, "Echecs de connexion",
                "Bloquer l'IP 192.168.1.15", sensible, ["ACCES"])
    return s, v

class TestAlerte(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITIQUE"), "TELEPHONE")
        self.assertEqual(choisir_canal("ELEVEE"), "SLACK")
        self.assertEqual(choisir_canal("MOYENNE"), "EMAIL")
        self.assertEqual(choisir_canal("FAIBLE"), "TABLEAU")

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            choisir_canal("X")
            
    def test_rediger(self):
        s, v = exemple()
        self.assertEqual(len(rediger(s, v).split("\n")), 5)

    def test_alerter(self):
        s, v = exemple()
        journal = []
        al = alerter(s, v, journal)
        self.assertEqual(al.canal, "TELEPHONE")
        self.assertEqual(journal, [al])
        self.assertEqual(s.statut, "ALERTE")

    def test_validation(self):
        _, v = exemple()
        self.assertTrue(valider_action(v, " OUI "))
        self.assertFalse(valider_action(v, "n"))


if __name__ == "__main__":
    unittest.main()