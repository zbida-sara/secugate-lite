from src import alerte, collecte, detection
from src.contrat import PROCEDURES


def _traiter(sig, vus, compteur, journal, base):
    if detection.est_deja_vu(sig, vus):
        return None
    nb_echecs = detection.compter_echecs(sig, compteur)
    verdict = detection.analyser(sig, base, nb_echecs)
    al = alerte.alerter(sig, verdict, journal)
    return {"signal": sig, "verdict": verdict, "alerte": al}


def traiter_acces(ligne, numero, vus, compteur, journal, base=PROCEDURES):
    sig = collecte.normaliser_acces(ligne, numero)
    return _traiter(sig, vus, compteur, journal, base)


def traiter_scan(rapport, numero, vus, compteur, journal, base=PROCEDURES):
    sig = collecte.normaliser_scan(rapport, numero)
    return _traiter(sig, vus, compteur, journal, base)