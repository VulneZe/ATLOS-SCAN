#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion sécurisée des credentials ATLOS v5.0
Chiffrement, déchiffrement et gestion sécurisée des mots de passe
"""

import os
import base64
import secrets
import hashlib
import hmac
from typing import Optional, Dict, Any, Tuple, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json
import logging
import sys

class CredentialManager:
    """Gestionnaire sécurisé des credentials ATLOS"""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.logger = logging.getLogger(__name__)
        
        # Initialisation de la clé de chiffrement
        if encryption_key is None:
            encryption_key = self._generate_or_load_key()
        
        self.fernet = Fernet(encryption_key)
        self._validate_key()
    
    def _generate_or_load_key(self) -> bytes:
        """Génère ou charge une clé de chiffrement"""
        key_file = "data/.atlos_key"
        
        try:
            # Vérifier si une clé existe déjà
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key_data = f.read()
                    
                # Vérifier que la clé est valide (32 bytes pour Fernet)
                if len(key_data) == 44:  # Base64 de 32 bytes
                    return base64.urlsafe_b64decode(key_data)
                else:
                    self.logger.warning("Clé existante invalide, génération d'une nouvelle clé")
            
            # Générer une nouvelle clé
            key = Fernet.generate_key()
            
            # Sauvegarder la clé avec permissions restrictives
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(base64.urlsafe_b64encode(key))
            
            # Permissions restrictives (lecture/écriture uniquement pour le propriétaire)
            os.chmod(key_file, 0o600)
            
            self.logger.info("Nouvelle clé de chiffrement générée et sauvegardée")
            return key
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la gestion de la clé: {e}")
            # En cas d'erreur, générer une clé temporaire
            return Fernet.generate_key()
    
    def _validate_key(self):
        """Valide que la clé de chiffrement est valide"""
        try:
            # Test de chiffrement/déchiffrement
            test_data = b"test_validation"
            encrypted = self.fernet.encrypt(test_data)
            decrypted = self.fernet.decrypt(encrypted)
            
            if decrypted != test_data:
                raise ValueError("La clé de chiffrement est invalide")
                
        except Exception as e:
            self.logger.error(f"Validation de la clé échouée: {e}")
            raise
    
    def encrypt(self, data: str) -> str:
        """
        Chiffre une chaîne de caractères
        
        Args:
            data: Données à chiffrer
            
        Returns:
            str: Données chiffrées en base64
        """
        try:
            if not isinstance(data, str):
                data = str(data)
            
            encrypted_data = self.fernet.encrypt(data.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Erreur lors du chiffrement: {e}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Déchiffre une chaîne de caractères
        
        Args:
            encrypted_data: Données chiffrées en base64
            
        Returns:
            str: Données déchiffrées
        """
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Erreur lors du déchiffrement: {e}")
            raise
    
    def encrypt_credentials(self, username: str, password: str, **metadata) -> Dict[str, Any]:
        """
        Chiffre un jeu de credentials avec métadonnées
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
            **metadata: Métadonnées supplémentaires
            
        Returns:
            Dict[str, Any]: Credentials chiffrés avec métadonnées
        """
        try:
            credential_data = {
                'username': username,
                'password': password,
                **metadata
            }
            
            # Génération d'un identifiant unique
            credential_id = secrets.token_urlsafe(16)
            
            # Chiffrement des données
            encrypted_json = self.encrypt(json.dumps(credential_data))
            
            # Calcul du hash pour vérification d'intégrité
            integrity_hash = self._calculate_hash(encrypted_json)
            
            result = {
                'id': credential_id,
                'encrypted_data': encrypted_json,
                'integrity_hash': integrity_hash,
                'created_at': self._get_timestamp(),
                'version': '1.0'
            }
            
            self.logger.info(f"Credentials chiffrés avec succès (ID: {credential_id})")
            return result
            
        except Exception as e:
            self.logger.error(f"Erreur lors du chiffrement des credentials: {e}")
            raise
    
    def decrypt_credentials(self, encrypted_credential: Dict[str, Any]) -> Dict[str, Any]:
        """
        Déchiffre un jeu de credentials
        
        Args:
            encrypted_credential: Dictionnaire contenant les credentials chiffrés
            
        Returns:
            Dict[str, Any]: Credentials déchiffrés
        """
        try:
            # Vérification de l'intégrité
            stored_hash = encrypted_credential.get('integrity_hash')
            calculated_hash = self._calculate_hash(encrypted_credential.get('encrypted_data'))
            
            if not hmac.compare_digest(stored_hash, calculated_hash):
                raise ValueError("Intégrité des credentials compromise")
            
            # Déchiffrement
            decrypted_json = self.decrypt(encrypted_credential['encrypted_data'])
            credential_data = json.loads(decrypted_json)
            
            self.logger.info(f"Credentials déchiffrés avec succès (ID: {encrypted_credential.get('id')})")
            return credential_data
            
        except Exception as e:
            self.logger.error(f"Erreur lors du déchiffrement des credentials: {e}")
            raise
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[str, bytes]:
        """
        Hash un mot de passe avec PBKDF2
        
        Args:
            password: Mot de passe à hasher
            salt: Sel optionnel (généré si non fourni)
            
        Returns:
            Tuple[str, bytes]: Hash du mot de passe et sel utilisé
        """
        try:
            if salt is None:
                salt = os.urandom(32)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            hashed_password = kdf.derive(password.encode('utf-8'))
            return base64.urlsafe_b64encode(hashed_password).decode('utf-8'), salt
            
        except Exception as e:
            self.logger.error(f"Erreur lors du hashage du mot de passe: {e}")
            raise
    
    def verify_password(self, password: str, hashed_password: str, salt: bytes) -> bool:
        """
        Vérifie un mot de passe contre son hash
        
        Args:
            password: Mot de passe à vérifier
            hashed_password: Hash stocké
            salt: Sel utilisé pour le hash
            
        Returns:
            bool: True si le mot de passe est correct
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            new_hash = kdf.derive(password.encode('utf-8'))
            stored_hash = base64.urlsafe_b64decode(hashed_password.encode('utf-8'))
            
            return hmac.compare_digest(new_hash, stored_hash)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification du mot de passe: {e}")
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Génère un token sécurisé aléatoire
        
        Args:
            length: Longueur du token en bytes
            
        Returns:
            str: Token sécurisé en base64
        """
        return secrets.token_urlsafe(length)
    
    def _calculate_hash(self, data: str) -> str:
        """Calcule le hash SHA-256 pour vérification d'intégrité"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def _get_timestamp(self) -> str:
        """Retourne le timestamp actuel au format ISO"""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    
    def rotate_key(self) -> bool:
        """
        Effectue la rotation de la clé de chiffrement
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            # Sauvegarde de l'ancienne clé
            old_key_file = "data/.atlos_key"
            backup_key_file = f"data/.atlos_key.backup.{self._get_timestamp()}"
            
            if os.path.exists(old_key_file):
                os.rename(old_key_file, backup_key_file)
            
            # Génération de la nouvelle clé
            new_key = Fernet.generate_key()
            self.fernet = Fernet(new_key)
            
            # Sauvegarde de la nouvelle clé
            with open(old_key_file, 'wb') as f:
                f.write(base64.urlsafe_b64encode(new_key))
            
            os.chmod(old_key_file, 0o600)
            
            self.logger.info("Rotation de la clé de chiffrement effectuée avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la rotation de la clé: {e}")
            return False

class SecureStorage:
    """Stockage sécurisé pour les credentials chiffrés"""
    
    def __init__(self, storage_file: str = "data/credentials.enc"):
        self.storage_file = storage_file
        self.credential_manager = CredentialManager()
        self.logger = logging.getLogger(__name__)
        
        # Créer le répertoire si nécessaire
        os.makedirs(os.path.dirname(storage_file), exist_ok=True)
    
    def store_credentials(self, service: str, username: str, password: str, **metadata) -> str:
        """
        Stocke des credentials de manière sécurisée
        
        Args:
            service: Nom du service
            username: Nom d'utilisateur
            password: Mot de passe
            **metadata: Métadonnées supplémentaires
            
        Returns:
            str: ID des credentials stockés
        """
        try:
            # Charger les credentials existants
            stored_data = self._load_storage()
            
            # Préparer les métadonnées
            credential_metadata = {
                'service': service,
                **metadata
            }
            
            # Chiffrer les credentials
            encrypted_creds = self.credential_manager.encrypt_credentials(
                username, password, **credential_metadata
            )
            
            # Ajouter au stockage
            stored_data[encrypted_creds['id']] = encrypted_creds
            
            # Sauvegarder
            self._save_storage(stored_data)
            
            self.logger.info(f"Credentials stockés pour le service: {service}")
            return encrypted_creds['id']
            
        except Exception as e:
            self.logger.error(f"Erreur lors du stockage des credentials: {e}")
            raise
    
    def retrieve_credentials(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère des credentials stockés
        
        Args:
            credential_id: ID des credentials à récupérer
            
        Returns:
            Optional[Dict[str, Any]]: Credentials déchiffrés ou None
        """
        try:
            stored_data = self._load_storage()
            
            if credential_id not in stored_data:
                self.logger.warning(f"Credentials non trouvés: {credential_id}")
                return None
            
            encrypted_creds = stored_data[credential_id]
            credentials = self.credential_manager.decrypt_credentials(encrypted_creds)
            
            self.logger.info(f"Credentials récupérés pour le service: {credentials.get('service')}")
            return credentials
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des credentials: {e}")
            return None
    
    def list_services(self) -> list:
        """Liste tous les services avec des credentials stockés"""
        try:
            stored_data = self._load_storage()
            services = []
            
            for cred_id, cred_data in stored_data.items():
                # Déchiffrer juste les métadonnées nécessaires
                credentials = self.credential_manager.decrypt_credentials(cred_data)
                services.append({
                    'id': cred_id,
                    'service': credentials.get('service'),
                    'username': credentials.get('username'),
                    'created_at': cred_data.get('created_at')
                })
            
            return services
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la liste des services: {e}")
            return []
    
    def delete_credentials(self, credential_id: str) -> bool:
        """
        Supprime des credentials stockés
        
        Args:
            credential_id: ID des credentials à supprimer
            
        Returns:
            bool: True si succès, False sinon
        """
        try:
            stored_data = self._load_storage()
            
            if credential_id in stored_data:
                del stored_data[credential_id]
                self._save_storage(stored_data)
                self.logger.info(f"Credentials supprimés: {credential_id}")
                return True
            else:
                self.logger.warning(f"Credentials non trouvés pour suppression: {credential_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la suppression des credentials: {e}")
            return False
    
    def _load_storage(self) -> Dict[str, Any]:
        """Charge les données depuis le stockage chiffré"""
        try:
            if not os.path.exists(self.storage_file):
                return {}
            
            with open(self.storage_file, 'r', encoding='utf-8') as f:
                encrypted_json = f.read()
            
            if not encrypted_json.strip():
                return {}
            
            # Le fichier contient du JSON chiffré
            decrypted_json = self.credential_manager.decrypt(encrypted_json)
            return json.loads(decrypted_json)
            
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement du stockage: {e}")
            return {}
    
    def _save_storage(self, data: Dict[str, Any]):
        """Sauvegarde les données dans le stockage chiffré"""
        try:
            json_data = json.dumps(data, ensure_ascii=False, indent=2)
            encrypted_data = self.credential_manager.encrypt(json_data)
            
            with open(self.storage_file, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
            
            # Permissions restrictives
            os.chmod(self.storage_file, 0o600)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde du stockage: {e}")
            raise

# Instance globale pour faciliter l'utilisation
credential_manager = CredentialManager()
secure_storage = SecureStorage()
