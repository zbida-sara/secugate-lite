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
    return (f"[{verdict.niveau}] Cible : {sig.cible}\n"
            f"Signal : {sig.message}\n"
            f"Explication : {verdict.explication}\n"
            f"Action proposee : {verdict.action}\n"
            f"Sources : {', '.join(verdict.sources)}")


def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    al = Alerte(sig.id, choisir_canal(verdict.niveau), "equipe-secu", rediger(sig, verdict))
    journal.append(al)
    sig.statut = "ALERTE"
    return al

def valider_action(verdict: Verdict, reponse: str) -> bool:
    raise NotImplementedError