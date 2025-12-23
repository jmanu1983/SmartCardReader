# Smart Card Reader

Application moderne et fluide pour la lecture de badges sans contact et à contact.

## Fonctionnalités

### Lecteurs
- **Sélection de lecteur** : Choisissez parmi tous les lecteurs PC/SC connectés (USB, NFC, etc.)
- **Détection automatique** : Les lecteurs et cartes sont détectés automatiquement
- **Multi-lecteur** : Support de plusieurs lecteurs simultanés

### MIFARE DESFire EV1 / EV2 / EV3
- Lecture des informations de version (hardware, software, production)
- Récupération de l'UID
- Liste des applications et fichiers
- Lecture des fichiers (Standard, Backup, Value, Record)
- Paramètres de fichiers
- Mémoire libre
- **Authentification** :
  - DES (8 octets)
  - 2K3DES (16 octets)
  - 3K3DES (24 octets)
  - AES-128 (16 octets)

### JavaCard
- Sélection d'applets par AID
- Base de données d'AIDs connus (GlobalPlatform, VISA, Mastercard, FIDO, etc.)
- Sonde automatique des applets présents
- Données CPLC (Card Production Life Cycle)
- Lecture NDEF
- Envoi d'APDUs personnalisés

### Diversification de clés
- **AN10922 AES-128** : Diversification CMAC AES conforme à NXP AN10922
- **AN10922 2K3DES** : Diversification CMAC 3DES
- **Custom AES CMAC** : Données de diversification personnalisées
- Lecture automatique de l'UID depuis la carte

### Console APDU
- Envoi de commandes APDU brutes en hexadécimal
- Historique des commandes (flèches haut/bas)
- Boutons rapides pour les commandes courantes
- Affichage hex dump avec représentation ASCII
- Copie du résultat dans le presse-papiers

## Installation

### Prérequis
- Python 3.9+
- Un lecteur de carte compatible PC/SC (USB NFC reader, contact reader, etc.)

### Installation des dépendances

```bash
cd SmartCardReaderApp
pip install -r requirements.txt
```

### Dépendances
| Package | Usage |
|---------|-------|
| `customtkinter` | Interface graphique moderne |
| `pyscard` | Communication PC/SC avec les lecteurs |
| `pycryptodome` | Cryptographie (authentification, diversification) |
| `Pillow` | Support d'images |

### Note Windows
Sur Windows, les pilotes PC/SC sont installés nativement. Branchez simplement votre lecteur USB.

### Note Linux
Sur Linux, installez `pcscd` :
```bash
sudo apt install pcscd pcsc-tools
sudo systemctl start pcscd
```

## Lancement

```bash
python main.py
```

## Utilisation

1. **Connecter un lecteur** USB (ACR122U, ACR1252U, HID OMNIKEY, etc.)
2. **Cliquer sur "Refresh"** pour détecter les lecteurs
3. **Sélectionner le lecteur** dans la liste de gauche
4. **Poser une carte** sur le lecteur
5. **Cliquer sur "Connect"** pour se connecter à la carte
6. Les informations s'affichent automatiquement pour les cartes DESFire

## Lecteurs supportés
Tous les lecteurs compatibles PC/SC, notamment :
- ACS ACR122U, ACR1252U
- HID OMNIKEY 5021, 5022, 5321, 5422
- Identive SCM SCR3310
- Gemalto IDBridge
- SpringCard Crazy Writer, TwistyWriter
- Et tout autre lecteur PC/SC...

## Structure du projet

```
SmartCardReaderApp/
├── main.py                  # Point d'entrée
├── requirements.txt         # Dépendances Python
├── README.md               # Ce fichier
├── core/                   # Modules métier
│   ├── apdu.py            # Utilitaires APDU et hex
│   ├── reader_manager.py  # Gestion des lecteurs PC/SC
│   ├── atr_parser.py      # Analyse ATR
│   ├── desfire.py         # Protocole DESFire EV1/EV2/EV3
│   ├── javacard.py        # Handler JavaCard
│   └── diversification.py # Diversification de clés AN10922
└── ui/                    # Interface graphique
    ├── app.py             # Fenêtre principale
    ├── theme.py           # Thème et couleurs
    ├── reader_panel.py    # Panneau de sélection lecteur
    ├── card_info_view.py  # Onglet informations carte
    ├── desfire_view.py    # Onglet opérations DESFire
    ├── javacard_view.py   # Onglet opérations JavaCard
    ├── diversification_view.py  # Onglet diversification
    ├── apdu_console.py    # Console APDU
    └── log_panel.py       # Panneau de log
```

## Licence
Usage libre - Application créée pour la lecture de badges sans contact.
