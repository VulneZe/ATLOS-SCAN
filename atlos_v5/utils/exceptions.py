#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exceptions personnalisées ATLOS v5.0
Gestion d'erreurs structurée et professionnelle
"""

class ATLOSException(Exception):
    """Exception de base pour ATLOS"""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = None
        
        # Import évité pour éviter les dépendances circulaires
        from datetime import datetime, timezone
        self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> dict:
        """Convertit l'exception en dictionnaire"""
        return {
            'error': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code,
            'details': self.details,
            'timestamp': self.timestamp
        }
    
    def __str__(self) -> str:
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message

class ConfigurationError(ATLOSException):
    """Erreur de configuration"""
    
    def __init__(self, message: str, config_key: str = None, config_value: str = None):
        super().__init__(message, "CONFIG_ERROR")
        self.details.update({
            'config_key': config_key,
            'config_value': config_value
        })

class NetworkError(ATLOSException):
    """Erreur réseau"""
    
    def __init__(self, message: str, target: str = None, port: int = None):
        super().__init__(message, "NETWORK_ERROR")
        self.details.update({
            'target': target,
            'port': port
        })

class ScanError(ATLOSException):
    """Erreur lors du scan"""
    
    def __init__(self, message: str, scan_id: str = None, target: str = None):
        super().__init__(message, "SCAN_ERROR")
        self.details.update({
            'scan_id': scan_id,
            'target': target
        })

class AuthenticationError(ATLOSException):
    """Erreur d'authentification"""
    
    def __init__(self, message: str, service: str = None, username: str = None):
        super().__init__(message, "AUTH_ERROR")
        self.details.update({
            'service': service,
            'username': username
        })

class CredentialError(ATLOSException):
    """Erreur de gestion des credentials"""
    
    def __init__(self, message: str, credential_id: str = None):
        super().__init__(message, "CREDENTIAL_ERROR")
        self.details.update({
            'credential_id': credential_id
        })

class DatabaseError(ATLOSException):
    """Erreur de base de données"""
    
    def __init__(self, message: str, operation: str = None, table: str = None):
        super().__init__(message, "DATABASE_ERROR")
        self.details.update({
            'operation': operation,
            'table': table
        })

class PerformanceError(ATLOSException):
    """Erreur de performance"""
    
    def __init__(self, message: str, metric: str = None, threshold: float = None, current_value: float = None):
        super().__init__(message, "PERFORMANCE_ERROR")
        self.details.update({
            'metric': metric,
            'threshold': threshold,
            'current_value': current_value
        })

class SecurityError(ATLOSException):
    """Erreur de sécurité"""
    
    def __init__(self, message: str, security_event: str = None, source_ip: str = None):
        super().__init__(message, "SECURITY_ERROR")
        self.details.update({
            'security_event': security_event,
            'source_ip': source_ip
        })

class ModuleError(ATLOSException):
    """Erreur de module"""
    
    def __init__(self, message: str, module_name: str = None, function_name: str = None):
        super().__init__(message, "MODULE_ERROR")
        self.details.update({
            'module_name': module_name,
            'function_name': function_name
        })

class ValidationError(ATLOSException):
    """Erreur de validation"""
    
    def __init__(self, message: str, field_name: str = None, field_value: str = None):
        super().__init__(message, "VALIDATION_ERROR")
        self.details.update({
            'field_name': field_name,
            'field_value': field_value
        })

class PermissionError(ATLOSException):
    """Erreur de permissions"""
    
    def __init__(self, message: str, required_permission: str = None, current_user: str = None):
        super().__init__(message, "PERMISSION_ERROR")
        self.details.update({
            'required_permission': required_permission,
            'current_user': current_user
        })

class TimeoutError(ATLOSException):
    """Erreur de timeout"""
    
    def __init__(self, message: str, operation: str = None, timeout_seconds: float = None):
        super().__init__(message, "TIMEOUT_ERROR")
        self.details.update({
            'operation': operation,
            'timeout_seconds': timeout_seconds
        })

class ResourceError(ATLOSException):
    """Erreur de ressources"""
    
    def __init__(self, message: str, resource_type: str = None, resource_limit: int = None):
        super().__init__(message, "RESOURCE_ERROR")
        self.details.update({
            'resource_type': resource_type,
            'resource_limit': resource_limit
        })

# Fonction utilitaire pour la gestion des exceptions
def handle_exception(func):
    """Décorateur pour la gestion centralisée des exceptions"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ATLOSException as e:
            # Logger l'exception ATLOS
            import logging
            logger = logging.getLogger(func.__module__)
            logger.error(f"ATLOS Exception in {func.__name__}: {e.to_dict()}")
            raise
        except Exception as e:
            # Convertir en ATLOSException
            import logging
            logger = logging.getLogger(func.__module__)
            atlos_error = ATLOSException(
                f"Unexpected error in {func.__name__}: {str(e)}",
                "UNEXPECTED_ERROR",
                {'original_error': str(e), 'function': func.__name__}
            )
            logger.error(f"Unexpected error in {func.__name__}: {atlos_error.to_dict()}")
            raise atlos_error
    return wrapper

def safe_execute(func, default_return=None, log_errors=True):
    """Exécute une fonction en toute sécurité avec gestion des erreurs"""
    try:
        return func()
    except ATLOSException as e:
        if log_errors:
            import logging
            logger = logging.getLogger()
            logger.error(f"ATLOS Error: {e.to_dict()}")
        return default_return
    except Exception as e:
        if log_errors:
            import logging
            logger = logging.getLogger()
            logger.error(f"Unexpected error: {str(e)}")
        return default_return
