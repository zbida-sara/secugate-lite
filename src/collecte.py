
import re
from src.contrat import Signal


def masquer_ip(ip: str) -> str:
    parties = ip.split(".")
    if len(parties) != 4:
        raise ValueError("IP invalide")
    return ".".join(parties[:3]) + ".x"


def masquer_parametres(chemin: str) -> str:
    return re.sub(
        r"\b(token|password|session|key)=[^&\s]*",
        r"\1=[MASQUE]",
        chemin,
        flags=re.IGNORECASE
    )


def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    champs = ligne.split()

    if len(champs) < 6:
        raise ValueError("Ligne invalide")

    date, heure, ip, methode, chemin, statut = champs[:6]

    code = int(statut)

    type_ = "ACCES"
    if chemin.split("?")[0] == "/login" and code in (401, 403):
        type_ = "LOGIN_ECHEC"

    gravite = "FAIBLE"
    if code >= 500:
        gravite = "ELEVEE"
    elif code >= 400:
        gravite = "MOYENNE"

    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=f"{date}T{heure}Z",
        source="ACCES",
        ip=ip,
        cible=cible,
        type=type_,
        gravite=gravite,
        message=f"{methode} {masquer_parametres(chemin)} -> {statut} depuis {masquer_ip(ip)}"
    )


def normaliser_scan(rapport: dict, numero: int) -> Signal:
    for cle in ["rule", "component", "severity", "message", "date"]:
        if cle not in rapport:
            raise ValueError("Clé manquante")

    gravites = {
        "blocker": "CRITIQUE",
        "critical": "ELEVEE",
        "major": "MOYENNE",
        "minor": "FAIBLE"
    }

    gravite = gravites.get(rapport["severity"].lower(), "FAIBLE")

    return Signal(
        id=f"SIG-{numero:05d}",
        timestamp=rapport["date"],
        source="SCAN",
        ip="",
        cible=rapport["component"],
        type="FAILLE",
        gravite=gravite,
        message=f"Faille {rapport['rule']} : {rapport['message']}"
    )
