# network-security-dashboard

Python-based network monitoring and intrusion detection system inspired by Wireshark and Snort.

## Structure du projet

```
network-security-dashboard/
│
├── backend/                 # Logique principale de l'application
│   ├── sniffer.py           # Capture le trafic réseau en direct
│   ├── parser.py            # Décode et structure les paquets capturés
│   ├── analyzer.py          # Analyse les données réseau
│   ├── detector.py          # Détecte les anomalies / intrusions
│   ├── database.py          # Gère les connexions à la base de données
│   ├── app.py                # Lance le serveur de l'application
│   └── main.py               # Point d'entrée principal du programme
│
├── database/
│   └── security.db          # Base de données SQLite (alertes, logs de sécurité)
│
├── frontend/
│   └── index.html           # Interface web du tableau de bord
│
├── logs/
│   ├── backend/
│   │   └── logger.py        # Génère les fichiers de logs de l'application
│   └── network_logs.json    # Historique du trafic réseau capturé
│
├── tests/
│   └── test_detector.py     # Tests unitaires du module de détection
│
├── requirements.txt          # Dépendances Python du projet
└── README.md
```

## Description des modules

| Fichier | Rôle |
|---|---|
| `sniffer.py` | Capture les paquets réseau en temps réel |
| `parser.py` | Extrait les informations utiles des paquets bruts |
| `analyzer.py` | Analyse le trafic pour repérer des comportements suspects |
| `detector.py` | Applique les règles de détection d'intrusion |
| `database.py` | Enregistre et lit les données dans `security.db` |
| `logger.py` | Écrit les événements dans les fichiers de log |
| `app.py` / `main.py` | Démarrent l'application |
| `index.html` | Affiche les résultats dans une interface web |

## Installation

```bash
pip install -r requirements.txt
```

## Lancer le projet

```bash
python backend/main.py
```

## Tests

```bash
python -m pytest tests/
```
