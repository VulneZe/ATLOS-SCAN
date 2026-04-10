# Guide d'Installation ATLOS v5.0

## Prérequis Système

### Systèmes d'Exploitation Supportés
- **Linux**: Ubuntu 18.04+, Debian 10+, CentOS 7+, RHEL 7+
- **Windows**: Windows 10+, Windows Server 2016+
- **macOS**: macOS 10.14+

### Python Requis
- **Version**: Python 3.8 ou supérieur
- **Gestionnaire de paquets**: pip 21.0+

### Outils Système Requis

#### Linux
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y python3 python3-pip nmap dnsutils snmp

# CentOS/RHEL
sudo yum install -y python3 python3-pip nmap bind-utils net-snmp

# Arch Linux
sudo pacman -S python python-pip nmap bind-tools net-snmp
```

#### Windows
1. **Python**: Télécharger depuis [python.org](https://python.org)
2. **Nmap**: Télécharger depuis [nmap.org](https://nmap.org)
3. **Git**: Télécharger depuis [git-scm.com](https://git-scm.com)

#### macOS
```bash
# Homebrew
brew install python3 nmap

# MacPorts
sudo port install python38 nmap
```

## Installation

### 1. Clonage du Projet
```bash
git clone https://github.com/baptiste-rouault/atlos.git
cd atlos/atlos_v5
```

### 2. Installation des Dépendances Python
```bash
# Création d'environnement virtuel (recommandé)
python3 -m venv atlos_env
source atlos_env/bin/activate  # Linux/macOS
# ou
atlos_env\Scripts\activate     # Windows

# Installation des dépendances
pip install -r requirements.txt
```

### 3. Configuration Initiale
```bash
# Copie de la configuration par défaut
cp config/settings.yaml config/settings.local.yaml

# Édition de la configuration
nano config/settings.local.yaml
```

### 4. Création des Répertoires
```bash
# Création des répertoires nécessaires
mkdir -p data logs reports temp
```

### 5. Vérification de l'Installation
```bash
# Test des imports
python3 -c "
try:
    from utils.config import ConfigManager
    from utils.logger import ATLOSLogger
    from core.scanner import NetworkScanner
    print('Installation réussie!')
except ImportError as e:
    print(f'Erreur d\'installation: {e}')
"

# Exécution des tests
python3 tests/run_tests.py
```

## Configuration

### 1. Fichier de Configuration Principal (`config/settings.local.yaml`)

```yaml
# Configuration de scan
scan:
  timeout: 30                    # Timeout en secondes
  max_threads: 50                # Threads maximum
  stealth_mode: false            # Mode furtif
  default_ports: "1-1000,3389,5985"  # Ports par défaut
  exclude_hosts: []              # Hôtes à exclure

# Sécurité
security:
  encrypt_credentials: true      # Chiffrement des credentials
  audit_log: true                # Log d'audit
  session_timeout: 3600          # Timeout de session

# Base de données
database:
  type: "sqlite"                 # Type: sqlite, postgresql, mysql
  sqlite_path: "data/atlos.db"   # Chemin SQLite
  # Pour PostgreSQL/MySQL:
  # host: "localhost"
  # port: 5432
  # name: "atlos"
  # user: "atlos_user"
  # password: "secure_password"

# API REST
api:
  enabled: true                  # Activer l'API
  port: 8080                     # Port d'écoute
  host: "127.0.0.1"              # Host d'écoute
  api_key: "your_secure_key"     # Clé API
  rate_limit: 100                # Requêtes/minute

# Logging
logging:
  level: "INFO"                  # DEBUG, INFO, WARNING, ERROR
  file_handler:
    enabled: true
    file: "logs/atlos.log"
    max_size: "10MB"
    backup_count: 5
  console_handler:
    enabled: true
    colored: true

# Détection IDS/IPS
ids_detection:
  enabled: true
  auto_adapt: true
  evasion_techniques:
    - "fragmentation"
    - "timing_variation"
    - "source_port_randomization"
```

### 2. Variables d'Environnement (Optionnel)
```bash
# Fichier .env
ATLOS_CONFIG_PATH="/path/to/config.yaml"
ATLOS_LOG_LEVEL="DEBUG"
ATLOS_DB_TYPE="postgresql"
ATLOS_DB_HOST="localhost"
ATLOS_DB_PORT="5432"
ATLOS_DB_NAME="atlos"
ATLOS_DB_USER="atlos_user"
ATLOS_DB_PASSWORD="secure_password"
```

## Permissions

### Linux/macOS
```bash
# Permissions pour le script principal
chmod +x main.py

# Permissions pour les répertoires
chmod 700 data logs reports temp
chmod 600 config/settings.local.yaml
```

### Windows
Exécuter en tant qu'administrateur pour les fonctionnalités réseau avancées.

## Vérification Post-Installation

### 1. Test de Configuration
```bash
# Validation de la configuration
python3 main.py config validate
```

### 2. Test de Scan Basique
```bash
# Scan d'un hôte local
sudo python3 main.py scan 127.0.0.1/32 --ports 22,80,443
```

### 3. Test de l'API
```bash
# Démarrage de l'API
sudo python3 main.py api

# Test dans un autre terminal
curl http://localhost:8080/api/v1/health
```

### 4. Test des Modules
```bash
# Test SMB (si disponible)
python3 main.py smb 127.0.0.1

# Test de configuration
python3 main.py config show
```

## Dépannage

### Problèmes Communs

#### 1. Erreur "Module not found"
```bash
# Solution: Réinstaller les dépendances
pip install -r requirements.txt --force-reinstall
```

#### 2. Erreur de permissions (Linux)
```bash
# Solution: Exécuter avec sudo
sudo python3 main.py scan 192.168.1.0/24
```

#### 3. Erreur Nmap non trouvé
```bash
# Ubuntu/Debian
sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# Windows: Ajouter nmap au PATH système
```

#### 4. Erreur de base de données
```bash
# Supprimer et recréer la base de données
rm data/atlos.db
python3 -c "from utils.database import init_database; init_database()"
```

#### 5. Erreur de configuration
```bash
# Recharger la configuration par défaut
cp config/settings.yaml config/settings.local.yaml
```

### Logs et Debug

### 1. Logs d'Erreur
```bash
# Voir les logs récents
tail -f logs/atlos.log

# Logs avec erreurs uniquement
grep ERROR logs/atlos.log
```

### 2. Mode Debug
```bash
# Activer le mode debug
export ATLOS_LOG_LEVEL="DEBUG"
python3 main.py scan 192.168.1.0/24
```

### 3. Vérification des Dépendances
```bash
# Liste des paquets installés
pip list | grep -E "(cryptography|sqlalchemy|fastapi|psutil)"

# Version de Python
python3 --version
```

## Performance

### 1. Optimisation Mémoire
```yaml
# Dans settings.yaml
performance:
  cache_enabled: true
  max_memory_mb: 1024
  gc_threshold: 700
```

### 2. Optimisation Réseau
```yaml
# Dans settings.yaml
scan:
  timeout: 10          # Réduire pour les réseaux rapides
  max_threads: 100     # Augmenter pour les machines puissantes
  connection_pool_size: 50
```

### 3. Monitoring
```bash
# Surveillance des performances
python3 -c "
from utils.performance import get_performance_monitor
monitor = get_performance_monitor()
if monitor:
    monitor.start_monitoring()
    print('Monitoring démarré')
"
```

## Mise à Jour

### 1. Mise à Jour du Code
```bash
# Récupération des dernières modifications
git pull origin main

# Mise à jour des dépendances
pip install -r requirements.txt --upgrade
```

### 2. Migration de la Base de Données
```bash
# Si le schéma a changé
python3 -c "
from utils.database import get_database
from utils.config import get_config
from utils.logger import get_logger

db = get_database(get_config(), get_logger())
# La migration sera automatique au prochain démarrage
"
```

### 3. Configuration
```bash
# Comparer la nouvelle configuration
diff config/settings.yaml config/settings.local.yaml

# Mettre à jour manuellement si nécessaire
```

## Support

### 1. Documentation
- **Architecture**: `docs/ARCHITECTURE.md`
- **API**: `docs/API.md`
- **Sécurité**: `docs/SECURITY.md`

### 2. Aide Communautaire
- **Issues**: [GitHub Issues](https://github.com/baptiste-rouault/atlos/issues)
- **Discussions**: [GitHub Discussions](https://github.com/baptiste-rouault/atlos/discussions)

### 3. Contact Professionnel
- **Email**: contact@atlos.fr
- **Site**: [atlos.fr](https://atlos.fr)

## Installation Docker (Optionnel)

### 1. Dockerfile
```dockerfile
FROM python:3.9-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    snmp \
    && rm -rf /var/lib/apt/lists/*

# Copie du code
COPY . /app
WORKDIR /app

# Installation Python
RUN pip install -r requirements.txt

# Création des répertoires
RUN mkdir -p data logs reports temp

# Permissions
RUN chmod +x main.py

# Exposition du port API
EXPOSE 8080

# Point d'entrée
CMD ["python3", "main.py", "api"]
```

### 2. docker-compose.yml
```yaml
version: '3.8'
services:
  atlos:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./reports:/app/reports
      - ./config/settings.local.yaml:/app/config/settings.local.yaml
    environment:
      - ATLOS_LOG_LEVEL=INFO
    privileged: true  # Requis pour les opérations réseau
```

### 3. Construction et Exécution
```bash
# Construction
docker-compose build

# Exécution
docker-compose up -d

# Logs
docker-compose logs -f atlos
```

L'installation est maintenant terminée. ATLOS v5.0 est prêt pour être utilisé!
