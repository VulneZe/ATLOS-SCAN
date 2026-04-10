# Architecture ATLOS v5.0

## Vue d'Ensemble

ATLOS v5.0 est une application de pentest réseau modulaire conçue avec une architecture en couches pour assurer la maintenabilité, la performance et la sécurité.

## Structure des Modules

```
atlos_v5/
|
|-- core/                   # Coeur métier
|   |-- scanner.py         # Moteur de scan réseau
|   `-- enumerator.py      # Énumération des services
|
|-- modules/                # Fonctionnalités spécialisées
|   |-- smb.py            # Énumération SMB
|   |-- ldap.py           # Énumération LDAP
|   |-- http.py           # Analyse HTTP
|   `-- stealth.py       # Mode furtif & IDS/IPS
|
|-- utils/                  # Utilitaires partagés
|   |-- config.py         # Gestion configuration
|   |-- logger.py         # Logging structuré
|   |-- crypto.py         # Chiffrement credentials
|   |-- database.py       # Persistance des données
|   |-- performance.py    # Optimisation performances
|   |-- exceptions.py     # Gestion d'erreurs
|   `-- validators.py     # Validation des entrées
|
|-- api/                    # Interface REST
|   `-- rest.py           # Endpoints FastAPI
|
|-- config/                 # Fichiers de configuration
|   `-- settings.yaml     # Configuration principale
|
`-- tests/                  # Suite de tests
    |-- test_basic.py      # Tests unitaires
    `-- run_tests.py      # Lanceur de tests
```

## Architecture en Couches

### 1. Couche Présentation (API)
- **Fichier**: `api/rest.py`
- **Responsabilité**: Interface REST pour l'intégration externe
- **Technologies**: FastAPI, Pydantic
- **Endpoints**: `/api/v1/scans`, `/api/v1/statistics`, `/api/v1/health`

### 2. Couche Métier (Core)
- **Fichiers**: `core/scanner.py`, `core/enumerator.py`
- **Responsabilité**: Logique métier principale de scanning
- **Patterns**: Strategy Pattern pour différents types de scan

### 3. Couche Services (Modules)
- **Fichiers**: `modules/*.py`
- **Responsabilité**: Services spécialisés (SMB, LDAP, HTTP, etc.)
- **Design**: Injection de dépendances, configuration externe

### 4. Couche Infrastructure (Utils)
- **Fichiers**: `utils/*.py`
- **Responsabilité**: Services transverses (config, logging, BDD, etc.)
- **Patterns**: Singleton, Factory, Observer

## Flux de Données

### Scan Réseau
```
CLI/API -> Scanner -> Discovery -> Enumeration -> Database -> Results
    |          |           |            |           |          |
    |          |           |            |           |          |
Input    Core Logic  Host Discovery  Service Scan  Persistence  Output
```

### Énumération SMB
```
Target -> SMBEnumerator -> Authentication -> Share Discovery -> Results
   |           |                |               |             |
   |           |                |               |             |
IP/Host   Module Logic    Credential Mgmt  Network Ops  Data Struct
```

## Patterns de Conception

### 1. Strategy Pattern
```python
# Différentes stratégies de scan
class ScanStrategy:
    def scan(self, target): pass

class AggressiveScan(ScanStrategy): pass
class StealthScan(ScanStrategy): pass
class CustomScan(ScanStrategy): pass
```

### 2. Factory Pattern
```python
# Création des modules
class ModuleFactory:
    @staticmethod
    def create_module(module_type, config, logger):
        if module_type == "smb":
            return SMBEnumerator(config, logger)
        elif module_type == "ldap":
            return LDAPEnumerator(config, logger)
```

### 3. Observer Pattern
```python
# Monitoring des performances
class PerformanceMonitor:
    def __init__(self):
        self.observers = []
    
    def add_observer(self, observer):
        self.observers.append(observer)
    
    def notify_observers(self, metrics):
        for observer in self.observers:
            observer.update(metrics)
```

### 4. Singleton Pattern
```python
# Gestionnaire de configuration
class ConfigManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
```

## Sécurité

### 1. Chiffrement
- **Credentials**: AES-256 avec clé dérivée (PBKDF2)
- **Stockage**: Fichiers chiffrés avec permissions restrictives
- **Rotation**: Support de la rotation des clés

### 2. Validation
- **Entrées**: Validation stricte avec regex
- **Commandes**: Filtrage des commandes dangereuses
- **Réseau**: Validation des IP, ports, domaines

### 3. Audit
- **Logging**: Traçabilité complète avec timestamps UTC
- **Événements**: Séparation des logs de sécurité
- **Intégrité**: Hashing des logs pour détection de falsification

## Performance

### 1. Optimisation Mémoire
- **Cache**: LRU cache pour les résultats fréquents
- **Garbage Collection**: Nettoyage agressif
- **Limitation**: Taille maximale des résultats

### 2. Optimisation Réseau
- **Connection Pool**: Réutilisation des connexions
- **Timeouts**: Adaptatifs selon la latence
- **Parallelisme**: Threading avec limites dynamiques

### 3. Monitoring
- **Métriques**: CPU, mémoire, threads, connexions
- **Alertes**: Seuils configurables
- **Adaptation**: Ajustement automatique des paramètres

## Base de Données

### 1. Schéma
```sql
scans (id, scan_id, target_network, status, timestamps, metadata)
hosts (id, scan_id, ip, hostname, mac, vendor, os, ports, services)
vulnerabilities (id, host_id, cve, name, severity, description)
credentials (id, service, username, encrypted_password, metadata)
```

### 2. ORM
- **Technologie**: SQLAlchemy
- **Migrations**: Support des migrations Alembic
- **Pool**: Connection pooling configuré

### 3. Persistance
- **SQLite**: Par défaut pour la portabilité
- **PostgreSQL**: Pour les déploiements production
- **MySQL**: Support alternatif

## Configuration

### 1. Fichier YAML
```yaml
scan:
  timeout: 30
  max_threads: 50
  stealth_mode: false

security:
  encrypt_credentials: true
  audit_log: true

database:
  type: sqlite
  sqlite_path: data/atlos.db

api:
  enabled: true
  port: 8080
```

### 2. Validation
- **Schéma**: Validation automatique au chargement
- **Types**: Vérification des types et valeurs
- **Dépendances**: Validation des relations

## Tests

### 1. Types de Tests
- **Unitaires**: Tests des fonctions isolées
- **Intégration**: Tests des interactions entre modules
- **Performance**: Tests de charge et mémoire

### 2. Couverture
- **Cible**: >80% de couverture de code
- **Automatisation**: Exécution automatique dans CI/CD
- **Rapports**: Génération des rapports de couverture

## Déploiement

### 1. Environnements
- **Développement**: SQLite, logs verbeux
- **Test**: PostgreSQL, monitoring activé
- **Production**: Optimisé, monitoring complet

### 2. Sécurité
- **Permissions**: Exécution avec privileges minimum
- **Réseau**: Isolation si possible
- **Audit**: Logs externes pour la production

## Évolution

### 1. Extensibilité
- **Plugins**: Support de plugins externes
- **Modules**: Ajout facile de nouveaux modules
- **API**: Versioning des endpoints

### 2. Maintenance
- **Documentation**: Mise à jour continue
- **Tests**: Ajout de tests pour chaque nouvelle fonctionnalité
- **Revue**: Code review systématique

Cette architecture assure une base solide pour le développement continu tout en maintenant la qualité et la sécurité.
