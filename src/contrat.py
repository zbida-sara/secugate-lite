
from dataclasses import dataclass

NIVEAUX = ["FAIBLE", "MOYENNE", "ELEVEE", "CRITIQUE"]

PROCEDURES = {
    "login": "Echecs de connexion : verifier l'IP source et la bloquer apres 5 essais.",
    "injection": "Injection : valider les entrees et utiliser des requetes preparees.",
    "token": "Jeton visible dans l'URL : le transmettre dans un en-tete, jamais en parametre.",
}


@dataclass
class Signal:
    id: str
    timestamp: str
    source: str
    ip: str
    cible: str
    type: str
    gravite: str
    message: str
    statut: str = "NOUVEAU"


@dataclass
class Verdict:
    signal_id: str
    niveau: str
    explication: str
    action: str
    sensible: bool
    sources: list


@dataclass
class Alerte:
    signal_id: str
    canal: str
    destinataire: str
    texte: str
