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

def chercher_procedures(sig: Signal, base: dict) -> list:
    msg = sig.message.lower()
    return[proc for mot, proc in base.items() if mot.lower()]

def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
    if sig.type == "LOGIN_ECHEC":
        return "CRITIQUE" if nb_echecs >= 5 else "MOYENNE"
    return sig.gravite

def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
    niveau = evaluer(sig, nb_echecs)
    procs = chercher_procedures(sig, base)
    explication = (" | ".join(procs) if procs 
                    else "Cause inconnue : analyse manuelle requise")
    if sig.type == "LOGIN_ECHEC" and niveau == "CRITIQUE":
        action = f"Bloquer l'IP {sig.ip}"
    elif sig.type == "FAILLE":
        action = f"Corriger la faille dans {sig.cible}"
    else:
        action = "Surveiller"
    sig.statut = "ANALYSE"    
    return Verdict(
        signal_id=sig.id,
        niveau=niveau,
        explication=explication,
        action=action,
        sensible=niveau in ("ELEVEE", "CRITIQUE"),
        sources=[sig.source],
    )