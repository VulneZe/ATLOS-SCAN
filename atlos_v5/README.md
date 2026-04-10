# ATLOS v5.0 - Advanced Threat Landscape Observation System

**Version :** 5.0 - Enterprise Red Team Edition  
**Auteur :** Baptiste Rouault  
**Site :** [atlos.fr](https://atlos.fr)  
**License :** MIT License  

ATLOS v5.0 est une refonte complète de l'outil de pentest réseau, avec une architecture modulaire, des fonctionnalités avancées et une sécurité renforcée.

---

## ## Nouveautés de la v5.0

### Architecture Modulaire
- **Structure propre** : Séparation en modules (core, modules, utils, api)
- **Configuration centralisée** : Fichier YAML pour tous les paramètres
- **Logging structuré** : JSON, rotation, audit trail
- **Base de données** : Persistance avec SQLAlchemy

### Sécurité Renforcée
- **Gestion sécurisée des credentials** : Chiffrement AES-256
- **Mode furtif** : Détection IDS/IPS et techniques d'évasion
- **Audit complet** : Traçabilité de toutes les actions
- **Validation d'entrée** : Protection contre les injections

### Fonctionnalités Avancées
- **API REST** : Intégration avec d'autres outils
- **Threading optimisé** : Scans parallèles performants
- **Reporting avancé** : HTML, JSON, PDF
- **Cross-platform** : Support Linux/Windows

---

## Installation

### Prérequis
```bash
# Python 3.8+
python3 --version

# Système
sudo apt update && sudo apt install -y nmap dnsutils snmp

# Windows (optionnel)
# Installer nmap manuellement depuis https://nmap.org/
```

### Installation des dépendances
```bash
# Clone du projet
git clone https://github.com/baptiste-rouault/atlos.git
cd atlos/atlos_v5

# Installation Python
pip3 install -r requirements.txt

# Installation des outils système
sudo apt install nmap dnsutils snmp -y  # Linux/Debian
# ou
sudo yum install nmap bind-utils net-snmp -y  # Linux/RHEL
```

### Configuration initiale
```bash
# Copie de la configuration par défaut
cp config/settings.yaml config/settings.local.yaml

# Édition de la configuration
nano config/settings.local.yaml
```

---

## Utilisation

### Scan Réseau Basique
```bash
# Scan complet du réseau actuel
sudo python3 main.py scan 192.168.1.0/24

# Scan avec options avancées
sudo python3 main.py scan 192.168.1.0/24 \
    --ports 1-1000,3389,5985 \
    --stealth \
    --threads 100 \
    --report \
    --format html
```

### Énumération SMB
```bash
# Énumération anonyme
sudo python3 main.py smb 192.168.1.10

# Avec credentials
sudo python3 main.py smb 192.168.1.10 \
    --username administrator \
    --password Password123 \
    --domain COMPANY
```

### API REST
```bash
# Démarrage de l'API
sudo python3 main.py api

# L'API sera disponible sur http://localhost:8080
# Documentation : http://localhost:8080/docs
```

### Gestion de la configuration
```bash
# Afficher la configuration
python3 main.py config show

# Valider la configuration
python3 main.py config validate

# Recharger la configuration
python3 main.py config reload
```

---

## Configuration

### Fichier `config/settings.yaml`

```yaml
# Scan Configuration
scan:
  timeout: 30
  max_threads: 50
  stealth_mode: false
  default_ports: "1-1000,3389,5985,8080,8443"

# Security
security:
  encrypt_credentials: true
  audit_log: true
  session_timeout: 3600

# Database
database:
  type: "sqlite"
  sqlite_path: "data/atlos.db"

# API REST
api:
  enabled: true
  port: 8080
  host: "127.0.0.1"

# IDS/IPS Detection & Evasion
ids_detection:
  enabled: true
  auto_adapt: true
  evasion_techniques:
    - "fragmentation"
    - "timing_variation"
    - "source_port_randomization"
```

### Modules Disponibles

#### Core Modules
- **scanner.py** : Moteur de scan réseau principal
- **enumerator.py** : Énumération des services

#### Feature Modules
- **smb.py** : Énumération SMB avancée
- **ldap.py** : Énumération LDAP/Active Directory
- **http.py** : Analyse web et vulnérabilités
- **stealth.py** : Mode furtif et détection IDS/IPS

#### Utility Modules
- **config.py** : Gestion de configuration
- **logger.py** : Logging structuré
- **crypto.py** : Gestion sécurisée des credentials
- **database.py** : Persistance des données

---

## API REST

### Endpoints Principaux

#### Lancement d'un scan
```bash
curl -X POST "http://localhost:8080/api/v1/scans" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target_network": "192.168.1.0/24",
    "ports": "1-1000",
    "stealth_mode": true
  }'
```

#### Statut d'un scan
```bash
curl "http://localhost:8080/api/v1/scans/{scan_id}/status" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### Résultats d'un scan
```bash
curl "http://localhost:8080/api/v1/scans/{scan_id}" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### Statistiques
```bash
curl "http://localhost:8080/api/v1/statistics" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### Réponses JSON

```json
{
  "scan_id": "uuid-string",
  "status": "completed",
  "target_network": "192.168.1.0/24",
  "start_time": "2024-01-01T12:00:00Z",
  "end_time": "2024-01-01T12:05:30Z",
  "duration": 330.5,
  "total_hosts": 254,
  "hosts_online": 15,
  "vulnerabilities_found": 8,
  "hosts": [
    {
      "ip": "192.168.1.10",
      "hostname": "SRV-01",
      "mac": "00:11:22:33:44:55",
      "vendor": "Dell Inc.",
      "os_guess": "Windows Server 2019",
      "status": "online",
      "ports_open": [22, 80, 443, 445],
      "vulnerabilities": [
        {
          "cve": "CVE-2017-0144",
          "name": "EternalBlue",
          "severity": "Critical"
        }
      ]
    }
  ]
}
```

---

## Mode Furtif

### Détection IDS/IPS

ATLOS v5.0 détecte automatiquement les systèmes de détection :

- **Suricata** : Détection basée sur les signatures
- **Snort** : Analyse des règles et alertes
- **Zeek (Bro)** : Monitoring réseau avancé
- **OSSEC/Wazuh** : HIDS et monitoring système

### Techniques d'Évasion

1. **Fragmentation** : Division des paquets pour éviter la détection
2. **Variation de timing** : Délais aléatoires entre les requêtes
3. **Randomisation des ports source** : Éviter les patterns prévisibles
4. **Scans de leurre (Decoy)** : Utilisation d'IPs de diversion
5. **MAC Spoofing** : Masquage de l'adresse MAC
6. **Trafic chiffré** : Utilisation de protocoles sécurisés

### Configuration du Mode Furtif

```yaml
ids_detection:
  enabled: true
  auto_adapt: true
  signatures:
    - "suricata"
    - "snort"
    - "zeek"
  evasion_techniques:
    - "fragmentation"
    - "timing_variation"
    - "source_port_randomization"
```

---

## Base de Données

### Schéma

```sql
-- Scans
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    scan_id TEXT UNIQUE,
    target_network TEXT,
    scan_type TEXT,
    status TEXT,
    start_time DATETIME,
    end_time DATETIME,
    duration REAL,
    total_hosts INTEGER,
    hosts_online INTEGER,
    vulnerabilities_found INTEGER
);

-- Hosts
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    scan_id TEXT,
    ip TEXT,
    hostname TEXT,
    mac TEXT,
    vendor TEXT,
    os_guess TEXT,
    status TEXT,
    ports_open JSON,
    services JSON,
    vulnerabilities JSON
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    host_id INTEGER,
    cve TEXT,
    name TEXT,
    severity TEXT,
    description TEXT,
    port INTEGER,
    service TEXT
);
```

### Migration

```bash
# Création des tables (automatique au démarrage)
python3 -c "from utils.database import init_database; init_database()"

# Nettoyage des anciennes données
python3 -c "
from utils.database import get_database
from utils.config import get_config
from utils.logger import get_logger
db = get_database(get_config(), get_logger())
db.cleanup_old_data(days=30)
"
```

---

## Sécurité

### Gestion des Credentials

```python
from utils.crypto import SecureStorage

# Stockage sécurisé
storage = SecureStorage()
cred_id = storage.store_credentials(
    service="LDAP",
    username="admin",
    password="Password123",
    domain="company.local"
)

# Récupération
credentials = storage.retrieve_credentials(cred_id)
```

### Audit Trail

Toutes les actions sont loggées avec :

- **Timestamp** : Date et heure précises
- **Utilisateur** : Identifiant de l'opérateur
- **Action** : Type d'opération effectuée
- **Cible** : IP ou service ciblé
- **Résultat** : Succès ou échec

### Validation d'Entrée

```python
# Validation automatique des IP
from utils.validators import validate_ip, validate_network

if not validate_ip(target_ip):
    raise ValueError("IP invalide")

if not validate_network(target_network):
    raise ValueError("Réseau invalide")
```

---

## Performance

### Optimisations

- **Threading** : Jusqu'à 100 threads concurrents
- **Timeouts adaptatifs** : Ajustement automatique selon la latence
- **Cache DNS** : Réduction des requêtes répétées
- **Connection pooling** : Réutilisation des connexions

### Benchmarks

| Taille Réseau | Hôtes | Durée (v4.1) | Durée (v5.0) | Amélioration |
|---------------|-------|--------------|--------------|--------------|
| /24           | 254   | 5m30s        | 2m15s        | 59%          |
| /23           | 508   | 12m45s       | 4m30s        | 65%          |
| /22           | 1016  | 28m20s       | 8m45s        | 69%          |

---

## Développement

### Structure du Projet

```
atlos_v5/
|-- __init__.py
|-- main.py
|-- requirements.txt
|-- README.md
|
|-- core/
|   |-- __init__.py
|   |-- scanner.py
|   `-- enumerator.py
|
|-- modules/
|   |-- __init__.py
|   |-- smb.py
|   |-- ldap.py
|   |-- http.py
|   `-- stealth.py
|
|-- utils/
|   |-- __init__.py
|   |-- config.py
|   |-- logger.py
|   |-- crypto.py
|   `-- database.py
|
|-- api/
|   |-- __init__.py
|   `-- rest.py
|
|-- config/
|   `-- settings.yaml
|
|-- tests/
|   |-- __init__.py
|   |-- test_scanner.py
|   |-- test_smb.py
|   `-- test_api.py
|
`-- docs/
    |-- api.md
    |-- development.md
    `-- security.md
```

### Tests

```bash
# Lancement des tests
pytest tests/ -v

# Tests avec coverage
pytest tests/ --cov=atlos_v5 --cov-report=html

# Tests spécifiques
pytest tests/test_scanner.py -v
```

### Code Quality

```bash
# Formatage du code
black atlos_v5/

# Vérification du style
flake8 atlos_v5/

# Analyse de sécurité
bandit -r atlos_v5/

# Vérification des types
mypy atlos_v5/
```

---

## Contribuer

### Guidelines

1. **Code Style** : Respecter PEP 8 et utiliser Black
2. **Tests** : Ajouter des tests unitaires pour chaque nouvelle fonctionnalité
3. **Documentation** : Documenter les fonctions et classes
4. **Sécurité** : Valider toutes les entrées utilisateur
5. **Performance** : Optimiser les opérations réseau

### Soumission de Pull Request

1. Forker le projet
2. Créer une branche : `git checkout -b feature/nouvelle-fonctionnalite`
3. Commiter : `git commit -am 'Ajout nouvelle fonctionnalité'`
4. Push : `git push origin feature/nouvelle-fonctionnalite`
5. Ouvrir une Pull Request

---

## Support

### Documentation

- **API Documentation** : `/docs/api.md`
- **Development Guide** : `/docs/development.md`
- **Security Guide** : `/docs/security.md`

### Communauté

- **Issues** : [GitHub Issues](https://github.com/baptiste-rouault/atlos/issues)
- **Discussions** : [GitHub Discussions](https://github.com/baptiste-rouault/atlos/discussions)
- **Wiki** : [GitHub Wiki](https://github.com/baptiste-rouault/atlos/wiki)

### Contact

- **Email** : contact@atlos.fr
- **Twitter** : [@ATLOS_Security](https://twitter.com/ATLOS_Security)
- **Site Web** : [atlos.fr](https://atlos.fr)

---

## License

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## Changelog

### v5.0.0 (2024-01-01)
- Refactorisation complète de l'architecture
- Ajout de l'API REST
- Mode furtif et détection IDS/IPS
- Gestion sécurisée des credentials
- Base de données intégrée
- Performance améliorée de 60%

### v4.1 (2023-06-15)
- Correction des bugs de timeout
- Amélioration de la détection SMB
- Support IPv6 partiel

### v4.0 (2023-01-01)
- Version initiale
- Scan réseau complet
- Énumération SMB/LDAP
- MITM basique

---

## Avertissement

**Usage éthique uniquement** : ATLOS est conçu pour les tests d'intrusion autorisés et la formation en cybersécurité. L'utilisation non autorisée est illégale et strictement interdite.

**Responsabilité** : L'auteur décline toute responsabilité en cas d'utilisation malveillante de cet outil.

---

**Développé avec passion pour la communauté cybersécurité**  
*Baptiste Rouault - atlos.fr*
