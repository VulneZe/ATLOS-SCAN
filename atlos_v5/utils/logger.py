#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Système de logging structuré ATLOS v5.0
Logging avancé avec rotation, formattage JSON et audit trail
"""

import os
import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from enum import Enum
import threading
import hashlib
import hmac
import sys

class LogLevel(Enum):
    """Niveaux de log personnalisés"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL
    SECURITY = 35  # Niveau personnalisé pour les événements de sécurité
    AUDIT = 40     # Niveau personnalisé pour les audits

class ATLOSLogFormatter(logging.Formatter):
    """Formateur personnalisé pour les logs ATLOS"""
    
    # Mapping des couleurs pour la console
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Vert
        'WARNING': '\033[33m',    # Jaune
        'ERROR': '\033[31m',      # Rouge
        'CRITICAL': '\033[35m',   # Magenta
        'SECURITY': '\033[91m',   # Rouge vif
        'AUDIT': '\033[94m',      # Bleu vif
        'RESET': '\033[0m'        # Reset
    }
    
    def __init__(self, use_colors: bool = True, use_json: bool = False):
        super().__init__()
        self.use_colors = use_colors
        self.use_json = use_json
        
        if use_json:
            self.format_str = "%(asctime)s %(name)s %(levelname)s %(message)s %(filename)s %(lineno)d %(funcName)s"
        else:
            self.format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    def format(self, record):
        """Formate un enregistrement de log"""
        # Ajout de champs personnalisés
        if not hasattr(record, 'module'):
            record.module = record.name.split('.')[-1] if '.' in record.name else record.name
        
        if not hasattr(record, 'thread_id'):
            record.thread_id = threading.current_thread().ident
        
        if not hasattr(record, 'process_id'):
            record.process_id = os.getpid()
        
        # Formatage JSON
        if self.use_json:
            log_data = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'module': record.module,
                'message': record.getMessage(),
                'filename': record.filename,
                'line': record.lineno,
                'function': record.funcName,
                'thread_id': record.thread_id,
                'process_id': record.process_id
            }
            
            # Ajout des champs supplémentaires
            if hasattr(record, 'target'):
                log_data['target'] = record.target
            if hasattr(record, 'user'):
                log_data['user'] = record.user
            if hasattr(record, 'session_id'):
                log_data['session_id'] = record.session_id
            if hasattr(record, 'ip_address'):
                log_data['ip_address'] = record.ip_address
            
            return json.dumps(log_data, ensure_ascii=False)
        
        # Formatage texte avec couleurs
        formatted = super().format(record)
        
        if self.use_colors and hasattr(record, 'levelname'):
            color = self.COLORS.get(record.levelname, '')
            reset = self.COLORS['RESET']
            formatted = f"{color}{formatted}{reset}"
        
        return formatted

class ATLOSLogger:
    """Logger principal ATLOS avec fonctionnalités avancées"""
    
    def __init__(self, name: str = "atlos", config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(name)
        self._setup_logger()
        
        # Cache pour les événements de sécurité
        self._security_events = []
        self._audit_trail = []
        self._lock = threading.Lock()
    
    def _setup_logger(self):
        """Configure le logger avec les handlers appropriés"""
        self.logger.setLevel(logging.DEBUG)
        
        # Nettoyage des handlers existants
        self.logger.handlers.clear()
        
        # Niveau de log depuis la configuration
        level_str = self.config.get('level', 'INFO').upper()
        level = getattr(logging, level_str, logging.INFO)
        self.logger.setLevel(level)
        
        # Handler console
        if self.config.get('console_handler', {}).get('enabled', True):
            self._setup_console_handler()
        
        # Handler fichier
        if self.config.get('file_handler', {}).get('enabled', True):
            self._setup_file_handler()
        
        # Handler d'audit séparé
        if self.config.get('audit_log', True):
            self._setup_audit_handler()
    
    def _setup_console_handler(self):
        """Configure le handler pour la console"""
        console_config = self.config.get('console_handler', {})
        
        handler = logging.StreamHandler()
        
        # Formateur avec couleurs
        use_colors = console_config.get('colored', True)
        formatter = ATLOSLogFormatter(use_colors=use_colors, use_json=False)
        
        handler.setFormatter(formatter)
        
        # Niveau de log pour la console
        level = getattr(logging, console_config.get('level', 'INFO').upper(), logging.INFO)
        handler.setLevel(level)
        
        self.logger.addHandler(handler)
    
    def _setup_file_handler(self):
        """Configure le handler pour les fichiers"""
        file_config = self.config.get('file_handler', {})
        
        # Création du répertoire de logs
        log_file = Path(file_config.get('file', 'logs/atlos.log'))
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configuration de la rotation
        max_size = self._parse_size(file_config.get('max_size', '10MB'))
        backup_count = file_config.get('backup_count', 5)
        
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        # Formateur JSON pour les fichiers
        formatter = ATLOSLogFormatter(use_colors=False, use_json=True)
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def _setup_audit_handler(self):
        """Configure le handler spécial pour les audits"""
        audit_file = Path('logs/atlos_audit.log')
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        
        handler = logging.handlers.RotatingFileHandler(
            audit_file,
            maxBytes=50*1024*1024,  # 50MB
            backupCount=10,
            encoding='utf-8'
        )
        
        # Formateur JSON pour l'audit
        formatter = ATLOSLogFormatter(use_colors=False, use_json=True)
        handler.setFormatter(formatter)
        
        # Handler dédié pour les audits
        self.audit_handler = handler
        self.audit_logger = logging.getLogger(f"{self.name}.audit")
        self.audit_logger.addHandler(handler)
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.propagate = False
    
    def _parse_size(self, size_str: str) -> int:
        """Convertit une taille en chaîne vers des octets"""
        if not isinstance(size_str, str):
            return int(size_str) if isinstance(size_str, (int, float)) else 10485760  # 10MB default
        
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str) if size_str.isdigit() else 10485760
    
    def _log_with_context(self, level: int, message: str, **kwargs):
        """Log avec contexte supplémentaire"""
        extra = {}
        
        # Ajout du contexte aux champs extra
        for key, value in kwargs.items():
            if key in ['target', 'user', 'session_id', 'ip_address']:
                extra[key] = value
        
        self.logger.log(level, message, extra=extra)
    
    # Méthodes de log standards
    def debug(self, message: str, **kwargs):
        """Log de niveau DEBUG"""
        self._log_with_context(LogLevel.DEBUG.value, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log de niveau INFO"""
        self._log_with_context(LogLevel.INFO.value, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log de niveau WARNING"""
        self._log_with_context(LogLevel.WARNING.value, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log de niveau ERROR"""
        self._log_with_context(LogLevel.ERROR.value, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log de niveau CRITICAL"""
        self._log_with_context(LogLevel.CRITICAL.value, message, **kwargs)
    
    # Méthodes de log spécialisées
    def security(self, message: str, **kwargs):
        """Log pour les événements de sécurité"""
        with self._lock:
            event = {
                'timestamp': datetime.now().isoformat(),
                'type': 'security',
                'message': message,
                **kwargs
            }
            self._security_events.append(event)
        
        self._log_with_context(LogLevel.SECURITY.value, f"[SECURITY] {message}", **kwargs)
    
    def audit(self, message: str, action: str, user: Optional[str] = None, **kwargs):
        """Log pour les événements d'audit"""
        with self._lock:
            audit_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'message': message,
                'user': user,
                **kwargs
            }
            self._audit_trail.append(audit_entry)
        
        # Log dans le fichier d'audit
        audit_message = f"[AUDIT] {action}: {message}"
        if user:
            audit_message += f" (user: {user})"
        
        self.audit_logger.info(audit_message, extra={'user': user, 'action': action})
    
    def scan_start(self, target: str, scan_type: str, **kwargs):
        """Log du début d'un scan"""
        message = f"Début du scan {scan_type} sur {target}"
        self.info(message, target=target, scan_type=scan_type, **kwargs)
        self.audit(message, action="scan_start", target=target, scan_type=scan_type)
    
    def scan_complete(self, target: str, scan_type: str, results_count: int, **kwargs):
        """Log de la fin d'un scan"""
        message = f"Scan {scan_type} terminé sur {target} - {results_count} résultats"
        self.info(message, target=target, scan_type=scan_type, results_count=results_count, **kwargs)
        self.audit(message, action="scan_complete", target=target, scan_type=scan_type, results_count=results_count)
    
    def vulnerability_found(self, target: str, vulnerability: Dict[str, Any], **kwargs):
        """Log d'une vulnérabilité découverte"""
        cve = vulnerability.get('cve', 'Unknown')
        severity = vulnerability.get('severity', 'Unknown')
        message = f"Vulnérabilité découverte sur {target}: {cve} ({severity})"
        
        self.warning(message, target=target, vulnerability=vulnerability, **kwargs)
        self.audit(message, action="vulnerability_found", target=target, cve=cve, severity=severity)
    
    def unauthorized_access_attempt(self, source_ip: str, target: str, **kwargs):
        """Log d'une tentative d'accès non autorisée"""
        message = f"Tentative d'accès non autorisée depuis {source_ip} vers {target}"
        
        self.security(message, source_ip=source_ip, target=target, **kwargs)
        self.audit(message, action="unauthorized_access", source_ip=source_ip, target=target)
    
    def credential_usage(self, user: str, service: str, success: bool, **kwargs):
        """Log d'utilisation de credentials"""
        status = "succès" if success else "échec"
        message = f"Utilisation des credentials pour {user} sur {service}: {status}"
        
        if not success:
            self.security(message, user=user, service=service, success=success, **kwargs)
        
        self.audit(message, action="credential_usage", user=user, service=service, success=success)
    
    def get_security_events(self, limit: int = 100) -> list:
        """Retourne les événements de sécurité récents"""
        with self._lock:
            return self._security_events[-limit:]
    
    def get_audit_trail(self, limit: int = 100) -> list:
        """Retourne le trail d'audit récent"""
        with self._lock:
            return self._audit_trail[-limit:]
    
    def clear_logs(self):
        """Nettoie les logs en mémoire"""
        with self._lock:
            self._security_events.clear()
            self._audit_trail.clear()
        
        self.info("Logs en mémoire nettoyés")

# Fonctions utilitaires pour faciliter l'utilisation
def get_logger(name: str = "atlos", config: Optional[Dict[str, Any]] = None) -> ATLOSLogger:
    """Retourne une instance de ATLOSLogger"""
    return ATLOSLogger(name, config)

def setup_logging(config: Dict[str, Any]) -> ATLOSLogger:
    """Configure le logging global ATLOS"""
    logger = get_logger("atlos", config.get('logging', {}))
    return logger

# Logger global par défaut
default_logger = get_logger()
