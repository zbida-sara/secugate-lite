import sys
from src.alerte import valider_action
from src.workflow import traiter_acces, traiter_scan

LIGNES_ACCES = [
    "2026-10-05 10:00:01 10.0.0.5 GET /home 200",
    "2026-10-05 10:01:10 192.168.1.15 POST /login 401",
    "2026-10-05 10:01:14 192.168.1.15 POST /login 401",
    "2026-10-05 10:01:14 192.168.1.15 POST /login 401",
    "2026-10-05 10:01:20 192.168.1.15 POST /login 401",
    "2026-10-05 10:01:25 192.168.1.15 POST /login 401",
    "2026-10-05 10:01:31 192.168.1.15 POST /login 401",
    "2026-10-05 10:03:00 10.0.0.7 GET /api/users?id=3&token=abc123 200",
]

RAPPORTS_SCAN = [
    {"rule": "S3649", "component": "backend", "severity": "blocker",
     "message": "injection SQL possible", "date": "2026-10-05T10:05:00Z"},
]


def afficher(resultat):
    alerte = resultat["alerte"]
    verdict = resultat["verdict"]
    print(f"--- {alerte.signal_id} -> {alerte.canal} ({alerte.destinataire})")
    print(alerte.texte)
    if verdict.sensible:
        reponse = input("Action sensible. Approuver ? (o/n) : ")
        ok = valider_action(verdict, reponse)
        print("Action", "APPROUVEE" if ok else "REFUSEE",
              "(simulation : rien n'est execute)")
    print()


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    vus, compteur, journal = set(), {}, []
    entrees = [(traiter_acces, ligne) for ligne in LIGNES_ACCES]
    entrees += [(traiter_scan, rapport) for rapport in RAPPORTS_SCAN]
    ignores = 0
    for numero, (traiter, brut) in enumerate(entrees, start=1):
        resultat = traiter(brut, numero, vus, compteur, journal)
        if resultat is None:
            ignores += 1
            print(f"--- SIG-{numero:05d} ignore (doublon)\n")
        else:
            afficher(resultat)
    print(f"{len(entrees)} signaux recus, {ignores} doublon(s) ignore(s), "
          f"{len(journal)} alerte(s) envoyee(s).")


if __name__ == "__main__":
    main()