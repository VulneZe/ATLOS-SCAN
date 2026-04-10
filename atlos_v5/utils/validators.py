#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Validateurs ATLOS v5.0
Validation des entrées et sécurité des données
"""

import re
import ipaddress
from typing import Any, Optional, List, Dict, Union
from urllib.parse import urlparse

from .exceptions import ValidationError

class NetworkValidator:
    """Validateur pour les adresses IP et réseaux"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Valide une adresse IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_network(network: str) -> bool:
        """Valide un réseau (CIDR)"""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """Valide un numéro de port"""
        try:
            port_int = int(port)
            return 1 <= port_int <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_port_range(port_range: str) -> bool:
        """Valide une plage de ports (ex: 1-1000,80,443)"""
        if not port_range:
            return False
        
        # Séparation par virgules
        ranges = port_range.split(',')
        
        for range_part in ranges:
            range_part = range_part.strip()
            
            # Plage (ex: 1-1000)
            if '-' in range_part:
                start, end = range_part.split('-', 1)
                try:
                    start_int = int(start.strip())
                    end_int = int(end.strip())
                    if not (1 <= start_int <= end_int <= 65535):
                        return False
                except ValueError:
                    return False
            # Port unique
            else:
                if not NetworkValidator.validate_port(range_part):
                    return False
        
        return True
    
    @staticmethod
    def validate_mac(mac: str) -> bool:
        """Valide une adresse MAC"""
        mac_patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # xx:xx:xx:xx:xx:xx
            r'^([0-9A-Fa-f]{2}){6}$',  # xxxxxxxxxxxx
            r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$'  # xxxx.xxxx.xxxx
        ]
        
        return any(re.match(pattern, mac) for pattern in mac_patterns)

class StringValidator:
    """Validateur pour les chaînes de caractères"""
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Valide un nom d'utilisateur"""
        if not username or len(username) < 3 or len(username) > 50:
            return False
        
        # Alphanumérique + underscore + tiret
        pattern = r'^[a-zA-Z0-9_-]+$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def validate_password(password: str) -> bool:
        """Valide un mot de passe (basique)"""
        if not password or len(password) < 8:
            return False
        
        # Au moins une lettre et un chiffre
        has_letter = bool(re.search(r'[a-zA-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        
        return has_letter and has_digit
    
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """Valide un hostname"""
        if not hostname or len(hostname) > 253:
            return False
        
        # Pattern hostname RFC
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, hostname))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Valide un nom de domaine"""
        if not domain or len(domain) > 253:
            return False
        
        # Pattern domaine
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Valide une adresse email"""
        if not email or len(email) > 254:
            return False
        
        # Pattern email basique
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Nettoie un nom de fichier"""
        if not filename:
            return "unnamed"
        
        # Suppression des caractères dangereux
        dangerous_chars = r'[<>:"/\\|?*\x00-\x1f]'
        clean_name = re.sub(dangerous_chars, '_', filename)
        
        # Limitation de longueur
        return clean_name[:255]
    
    @staticmethod
    def validate_path(path: str) -> bool:
        """Valide un chemin de fichier"""
        if not path:
            return False
        
        # Pas de caractères null
        if '\x00' in path:
            return False
        
        # Vérification des patterns dangereux (basique)
        dangerous_patterns = [
            r'\.\./',  # Directory traversal
            r'^\.\.',  # Commence par ..
            r'//',     # Double slash
        ]
        
        return not any(re.search(pattern, path) for pattern in dangerous_patterns)

class SecurityValidator:
    """Validateur pour la sécurité"""
    
    @staticmethod
    def validate_command(command: str) -> bool:
        """Valide une commande système (sécurité)"""
        if not command:
            return False
        
        # Commandes dangereuses interdites
        dangerous_commands = [
            'rm -rf /',
            'dd if=',
            'mkfs.',
            'format',
            'fdisk',
            'shutdown',
            'reboot',
            'halt',
            'poweroff',
            'passwd',
            'su ',
            'sudo ',
            'chmod 777',
            'chown root',
            'crontab',
            'systemctl',
            'service ',
            'iptables',
            'ufw',
            'firewall',
        ]
        
        command_lower = command.lower()
        return not any(dangerous_cmd in command_lower for dangerous_cmd in dangerous_commands)
    
    @staticmethod
    def validate_sql_query(query: str) -> bool:
        """Validation basique contre les injections SQL"""
        if not query:
            return False
        
        # Patterns d'injection SQL
        injection_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)',
            r'(\b(UNION|OR|AND)\b.*\b(1\s*=\s*1|true|false)\b)',
            r'(\b(SCRIPT|JAVASCRIPT|VBSCRIPT)\b)',
            r'(\b(EXEC|EXECUTE|SP_)\b)',
            r'(\-\-|\#|\/\*|\*\/)',
            r'(\b(XOR|LIKE|ILIKE)\b.*\b(%|_)\b)',
        ]
        
        # Autoriser seulement les requêtes SELECT basiques
        if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b', query, re.IGNORECASE):
            # Si c'est un SELECT, vérifier qu'il n'y a pas d'injection
            if query.strip().upper().startswith('SELECT'):
                return not any(re.search(pattern, query, re.IGNORECASE) for pattern in injection_patterns[1:])
            else:
                # Autres commandes SQL non autorisées
                return False
        
        return True
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1000) -> str:
        """Nettoie une entrée utilisateur"""
        if not input_str:
            return ""
        
        # Limitation de longueur
        sanitized = input_str[:max_length]
        
        # Suppression des caractères de contrôle
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', sanitized)
        
        # Normalisation des espaces
        sanitized = ' '.join(sanitized.split())
        
        return sanitized

class ConfigValidator:
    """Validateur pour les configurations"""
    
    @staticmethod
    def validate_scan_config(config: Dict[str, Any]) -> List[str]:
        """Valide la configuration de scan"""
        errors = []
        
        # Validation timeout
        timeout = config.get('timeout')
        if timeout is not None:
            if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 3600:
                errors.append("timeout doit être un nombre entre 1 et 3600")
        
        # Validation max_threads
        max_threads = config.get('max_threads')
        if max_threads is not None:
            if not isinstance(max_threads, int) or max_threads < 1 or max_threads > 1000:
                errors.append("max_threads doit être un entier entre 1 et 1000")
        
        # Validation ports
        ports = config.get('ports')
        if ports is not None:
            if not isinstance(ports, str) or not NetworkValidator.validate_port_range(ports):
                errors.append("ports doit être une plage de ports valide")
        
        # Validation exclude_hosts
        exclude_hosts = config.get('exclude_hosts')
        if exclude_hosts is not None:
            if not isinstance(exclude_hosts, list):
                errors.append("exclude_hosts doit être une liste")
            else:
                for host in exclude_hosts:
                    if not NetworkValidator.validate_ip(host):
                        errors.append(f"IP invalide dans exclude_hosts: {host}")
        
        return errors
    
    @staticmethod
    def validate_database_config(config: Dict[str, Any]) -> List[str]:
        """Valide la configuration de base de données"""
        errors = []
        
        # Type de base de données
        db_type = config.get('type')
        if not db_type or db_type not in ['sqlite', 'postgresql', 'mysql']:
            errors.append("type doit être 'sqlite', 'postgresql' ou 'mysql'")
        
        # Configuration SQLite
        if db_type == 'sqlite':
            sqlite_path = config.get('sqlite_path')
            if not sqlite_path or not isinstance(sqlite_path, str):
                errors.append("sqlite_path est requis pour SQLite")
        
        # Configuration PostgreSQL/MySQL
        elif db_type in ['postgresql', 'mysql']:
            required_fields = ['host', 'port', 'name', 'user']
            for field in required_fields:
                if not config.get(field):
                    errors.append(f"{field} est requis pour {db_type}")
            
            port = config.get('port')
            if port and (not isinstance(port, int) or not (1 <= port <= 65535)):
                errors.append(f"port doit être un entier entre 1 et 65535")
        
        return errors
    
    @staticmethod
    def validate_api_config(config: Dict[str, Any]) -> List[str]:
        """Valide la configuration API"""
        errors = []
        
        # Port
        port = config.get('port')
        if port and (not isinstance(port, int) or not (1024 <= port <= 65535)):
            errors.append("port doit être un entier entre 1024 et 65535")
        
        # Host
        host = config.get('host')
        if host and not isinstance(host, str):
            errors.append("host doit être une chaîne de caractères")
        
        # Rate limit
        rate_limit = config.get('rate_limit')
        if rate_limit and (not isinstance(rate_limit, int) or rate_limit < 1):
            errors.append("rate_limit doit être un entier positif")
        
        return errors

def validate_and_sanitize(data: Any, validator_type: str, **kwargs) -> Any:
    """Fonction générique de validation et nettoyage"""
    
    validators = {
        'ip': NetworkValidator.validate_ip,
        'network': NetworkValidator.validate_network,
        'port': NetworkValidator.validate_port,
        'port_range': NetworkValidator.validate_port_range,
        'mac': NetworkValidator.validate_mac,
        'username': StringValidator.validate_username,
        'password': StringValidator.validate_password,
        'hostname': StringValidator.validate_hostname,
        'domain': StringValidator.validate_domain,
        'email': StringValidator.validate_email,
        'filename': StringValidator.sanitize_filename,
        'path': StringValidator.validate_path,
        'command': SecurityValidator.validate_command,
        'sql_query': SecurityValidator.validate_sql_query,
        'input': SecurityValidator.sanitize_input,
    }
    
    validator = validators.get(validator_type)
    if not validator:
        raise ValidationError(f"Validateur inconnu: {validator_type}")
    
    # Validation
    if validator_type in ['filename', 'input']:
        # Pour ces types, la fonction retourne une valeur nettoyée
        return validator(data, **kwargs)
    else:
        # Pour les autres, c'est une validation booléenne
        if not validator(data, **kwargs):
            field_name = kwargs.get('field_name', validator_type)
            raise ValidationError(f"Valeur invalide pour {field_name}: {data}")
        return data

def validate_config_section(section_name: str, config: Dict[str, Any]) -> List[str]:
    """Valide une section de configuration"""
    validators = {
        'scan': ConfigValidator.validate_scan_config,
        'database': ConfigValidator.validate_database_config,
        'api': ConfigValidator.validate_api_config,
    }
    
    validator = validators.get(section_name)
    if not validator:
        return [f"Section de configuration inconnue: {section_name}"]
    
    return validator(config)
