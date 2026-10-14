from src.contrat import Signal, Verdict

def est_deja_vu(sig: Signal, vus: set) -> bool:
    cle = (sig.timestamp, sig.source, sig.ip, sig.cible, sig.type, sig.message)
    if cle in vus:
        return True 
    vus.add(cle)
    return False

def compter_echecs(sig: Signal, compteur: dict) -> int:
    if sig.type != "LOGIN_ECHEC":
        return 0
    compteur[sig.ip] = compteur.get(sig.ip, 0) + 1
    return compteur[sig.ip]

def chercher_procedues(sig: Signal, base: dict) -> list:
    msg = sig.message.lower()
    return[proc for mot, proc in base.items() if mot.lower()]
    