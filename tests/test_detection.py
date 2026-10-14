import unittest
from src.contrat import PROCEDURES, Signal
from src.detection import (analyser, chercher_procedures, compter_echecs,
                           est_deja_vu, evaluer)


def sig(type_="ACCES", gravite="FAIBLE", message="GET /home -> 200",
        ip="10.0.0.5", timestamp="2026-10-05T10:00:00Z", cible="web-app"):
    return Signal("SIG-00001", timestamp, "ACCES", ip, cible,
                  type_, gravite, message)


class TestDetection(unittest.TestCase):
    # est_deja_vu
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_deja_vu(sig(), vus))
        self.assertTrue(est_deja_vu(sig(), vus))

    def test_pas_doublon_secondes_differentes(self):
        vus = set()
        self.assertFalse(est_deja_vu(sig(timestamp="2026-10-05T10:00:01Z"), vus))
        self.assertFalse(est_deja_vu(sig(timestamp="2026-10-05T10:00:02Z"), vus))

    # compter_echecs
    def test_compter_echecs_incremente_par_ip(self):
        c = {}
        e = sig("LOGIN_ECHEC", "MOYENNE", "POST /login -> 401", ip="1.1.1.1")
        self.assertEqual(compter_echecs(e, c), 1)
        self.assertEqual(compter_echecs(e, c), 2)
        autre = sig("LOGIN_ECHEC", "MOYENNE", "POST /login -> 401", ip="2.2.2.2")
        self.assertEqual(compter_echecs(autre, c), 1)

    def test_compter_echecs_autre_type(self):
        c = {}
        self.assertEqual(compter_echecs(sig(), c), 0)
        self.assertEqual(c, {})

    # chercher_procedures
    def test_procedures_trouvees_ordre_base(self):
        s = sig(message="Injection via TOKEN login")
        self.assertEqual(chercher_procedures(s, PROCEDURES),
                         [PROCEDURES["login"], PROCEDURES["injection"],
                          PROCEDURES["token"]])

    def test_procedures_casse(self):
        s = sig(message="POST /LOGIN -> 401")
        self.assertEqual(chercher_procedures(s, PROCEDURES), [PROCEDURES["login"]])

    def test_procedures_aucune(self):
        self.assertEqual(chercher_procedures(sig(), PROCEDURES), [])

    # evaluer
    def test_evaluer_echecs_login(self):
        e = sig("LOGIN_ECHEC", "MOYENNE")
        self.assertEqual(evaluer(e, 5), "CRITIQUE")
        self.assertEqual(evaluer(e, 4), "MOYENNE")

    def test_evaluer_gravite_du_signal(self):
        self.assertEqual(evaluer(sig(gravite="ELEVEE"), 10), "ELEVEE")
        self.assertEqual(evaluer(sig(gravite="FAIBLE")), "FAIBLE")

    # analyser
    def test_analyser_login_critique(self):
        e = sig("LOGIN_ECHEC", "MOYENNE", "POST /login -> 401", ip="192.168.1.15")
        v = analyser(e, PROCEDURES, 5)
        self.assertEqual(v.niveau, "CRITIQUE")
        self.assertEqual(v.action, "Bloquer l'IP 192.168.1.15")
        self.assertEqual(v.explication, PROCEDURES["login"])
        self.assertTrue(v.sensible)
        self.assertEqual(v.sources, ["ACCES"])
        self.assertEqual(v.signal_id, "SIG-00001")
        self.assertEqual(e.statut, "ANALYSE")

    def test_analyser_login_moyenne_surveiller(self):
        e = sig("LOGIN_ECHEC", "MOYENNE", "POST /login -> 401")
        v = analyser(e, PROCEDURES, 2)
        self.assertEqual(v.action, "Surveiller")
        self.assertFalse(v.sensible)

    def test_analyser_faille(self):
        f = sig("FAILLE", "CRITIQUE", "Faille S3649 : injection SQL possible",
                ip="", cible="backend")
        v = analyser(f, PROCEDURES)
        self.assertEqual(v.action, "Corriger la faille dans backend")
        self.assertTrue(v.sensible)

    def test_analyser_cause_inconnue(self):
        v = analyser(sig(), PROCEDURES)
        self.assertEqual(v.explication,
                         "Cause inconnue : analyse manuelle requise")
        self.assertEqual(v.action, "Surveiller")
        self.assertFalse(v.sensible)


if __name__ == "__main__":
    unittest.main()