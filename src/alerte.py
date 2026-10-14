from src.contrat import Alerte, Signal, Verdict


def choisir_canal(niveau: str) -> str:
    if niveau == "CRITIQUE":
        return "TELEPHONE"
    if niveau == "ELEVEE":
        return "SLACK"
    if niveau == "MOYENNE":
        return "EMAIL"
    if niveau == "FAIBLE":
        return "TABLEAU"
    raise ValueError("Niveau inconnu")


def rediger(sig: Signal, verdict: Verdict) -> str:
    raise NotImplementedError


def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    raise NotImplementedError


def valider_action(verdict: Verdict, reponse: str) -> bool:
    raise NotImplementedError