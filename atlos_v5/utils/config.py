#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire de configuration ATLOS v5.0
Charge et valide la configuration YAML
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, field

@dataclass
class ScanConfig:
    timeout: int = 30
    max_threads: int = 50
    stealth_mode: bool = False
    random_delay: bool = True
    delay_range: List[float] = field(default_factory=lambda: [0.1, 2.0])
    default_ports: str = "1-1000,3389,5985,8080,8443"
    exclude_hosts: List[str] = field(default_factory=list)
    retry_attempts: int = 3

@dataclass
class SecurityConfig:
    encrypt_credentials: bool = True
    encryption_key: Optional[str] = None
    audit_log: bool = True
    session_timeout: int = 3600
    log_retention: int = 30
    strict_input_validation: bool = True

@dataclass
class DatabaseConfig:
    type: str = "sqlite"
    sqlite_path: str = "data/atlos.db"
    host: str = "localhost"
    port: int = 5432
    name: str = "atlos"
    user: str = "atlos_user"
    password: Optional[str] = None
    pool_size: int = 10
    max_overflow: int = 20

@dataclass
class APIConfig:
    enabled: bool = True
    port: int = 8080
    host: str = "127.0.0.1"
    api_key: Optional[str] = None
    cors_origins: List[str] = field(default_factory=lambda: ["http://localhost:3000"])
    rate_limit: int = 100

class ConfigManager:
    """Gestionnaire centralisé de configuration ATLOS"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Chemin du fichier de configuration
        if config_path is None:
            config_path = self._get_default_config_path()
        
        self.config_path = Path(config_path)
        self._config_data = {}
        
        # Charger la configuration
        self.load_config()
        
        # Valider et créer les objets de configuration
        self.scan = ScanConfig(**self._config_data.get('scan', {}))
        self.security = SecurityConfig(**self._config_data.get('security', {}))
        self.database = DatabaseConfig(**self._config_data.get('database', {}))
        self.api = APIConfig(**self._config_data.get('api', {}))
        
        # Créer les répertoires nécessaires
        self._create_directories()
    
    def _get_default_config_path(self) -> str:
        """Retourne le chemin par défaut du fichier de configuration"""
        current_dir = Path(__file__).parent.parent
        return str(current_dir / "config" / "settings.yaml")
    
    def _create_directories(self):
        """Crée les répertoires nécessaires pour ATLOS"""
        directories = [
            "data",
            "logs", 
            "reports",
            "temp"
        ]
        
        base_path = Path(__file__).parent.parent
        
        for directory in directories:
            dir_path = base_path / directory
            dir_path.mkdir(exist_ok=True)
            self.logger.debug(f"Répertoire créé/vérifié: {dir_path}")
    
    def load_config(self) -> bool:
        """
        Charge la configuration depuis le fichier YAML
        
        Returns:
            bool: True si chargement réussi, False sinon
        """
        try:
            if not self.config_path.exists():
                self.logger.error(f"Fichier de configuration introuvable: {self.config_path}")
                return False
            
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self._config_data = yaml.safe_load(file) or {}
            
            self.logger.info(f"Configuration chargée depuis: {self.config_path}")
            return True
            
        except yaml.YAMLError as e:
            self.logger.error(f"Erreur de syntaxe YAML: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement de la configuration: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Récupère une valeur de configuration avec notation par points
        
        Args:
            key: Clé de configuration (ex: 'scan.timeout')
            default: Valeur par défaut si la clé n'existe pas
            
        Returns:
            Any: Valeur de configuration
        """
        keys = key.split('.')
        value = self._config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """
        Définit une valeur de configuration
        
        Args:
            key: Clé de configuration (ex: 'scan.timeout')
            value: Valeur à définir
            
        Returns:
            bool: True si succès, False sinon
        """
        keys = key.split('.')
        config = self._config_data
        
        try:
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            config[keys[-1]] = value
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la définition de {key}: {e}")
            return False
    
    def save_config(self) -> bool:
        """
        Sauvegarde la configuration dans le fichier YAML
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            # Backup de l'ancienne configuration
            if self.config_path.exists():
                backup_path = self.config_path.with_suffix('.yaml.bak')
                self.config_path.rename(backup_path)
            
            # Sauvegarde de la nouvelle configuration
            with open(self.config_path, 'w', encoding='utf-8') as file:
                yaml.dump(self._config_data, file, default_flow_style=False, 
                         allow_unicode=True, indent=2)
            
            self.logger.info(f"Configuration sauvegardée dans: {self.config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde de la configuration: {e}")
            return False
    
    def validate_config(self) -> List[str]:
        """
        Valide la configuration et retourne la liste des erreurs
        
        Returns:
            List[str]: Liste des erreurs de validation
        """
        errors = []
        
        # Validation scan config
        if self.scan.timeout <= 0:
            errors.append("scan.timeout doit être positif")
        
        if self.scan.max_threads <= 0:
            errors.append("scan.max_threads doit être positif")
        
        if len(self.scan.delay_range) != 2:
            errors.append("scan.delay_range doit contenir 2 valeurs")
        
        # Validation security config
        if self.security.session_timeout <= 0:
            errors.append("security.session_timeout doit être positif")
        
        # Validation database config
        if self.database.type not in ['sqlite', 'postgresql', 'mysql']:
            errors.append("database.type doit être 'sqlite', 'postgresql' ou 'mysql'")
        
        # Validation API config
        if not 1024 <= self.api.port <= 65535:
            errors.append("api.port doit être entre 1024 et 65535")
        
        return errors
    
    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """
        Récupère la configuration spécifique d'un module
        
        Args:
            module_name: Nom du module
            
        Returns:
            Dict[str, Any]: Configuration du module
        """
        modules_config = self._config_data.get('modules', {})
        return modules_config.get(module_name, {})
    
    def is_module_enabled(self, module_name: str) -> bool:
        """
        Vérifie si un module est activé
        
        Args:
            module_name: Nom du module
            
        Returns:
            bool: True si le module est activé
        """
        enabled_modules = self._config_data.get('modules', {}).get('enabled', [])
        optional_modules = self._config_data.get('modules', {}).get('optional', [])
        
        return module_name in enabled_modules or module_name in optional_modules
    
    def reload(self) -> bool:
        """
        Recharge la configuration depuis le fichier
        
        Returns:
            bool: True si succès, False sinon
        """
        self.logger.info("Rechargement de la configuration...")
        return self.load_config()

# Instance globale du gestionnaire de configuration
config_manager = None

def get_config() -> ConfigManager:
    """Retourne l'instance globale du gestionnaire de configuration"""
    global config_manager
    if config_manager is None:
        config_manager = ConfigManager()
    return config_manager

def init_config(config_path: Optional[str] = None) -> ConfigManager:
    """Initialise le gestionnaire de configuration"""
    global config_manager
    config_manager = ConfigManager(config_path)
    return config_manager
