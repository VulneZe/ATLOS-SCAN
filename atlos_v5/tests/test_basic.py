#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests de base pour ATLOS v5.0
Validation des fonctionnalités principales
"""

import os
import sys
import unittest
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock

# Ajout du path parent pour les imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils.config import ConfigManager
from utils.logger import ATLOSLogger
from utils.crypto import CredentialManager, SecureStorage
from utils.database import DatabaseManager
from core.scanner import NetworkScanner, ScanConfig

class TestConfigManager(unittest.TestCase):
    """Tests du gestionnaire de configuration"""
    
    def setUp(self):
        """Configuration des tests"""
        self.test_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.test_dir, 'test_config.yaml')
        
        # Création d'un fichier de configuration test
        test_config = """
scan:
  timeout: 10
  max_threads: 20
  stealth_mode: true

security:
  encrypt_credentials: true
  audit_log: true

database:
  type: "sqlite"
  sqlite_path: "test.db"
"""
        
        with open(self.config_file, 'w') as f:
            f.write(test_config)
    
    def tearDown(self):
        """Nettoyage après tests"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_load_config(self):
        """Test du chargement de configuration"""
        config = ConfigManager(self.config_file)
        
        self.assertEqual(config.scan.timeout, 10)
        self.assertEqual(config.scan.max_threads, 20)
        self.assertTrue(config.scan.stealth_mode)
        self.assertTrue(config.security.encrypt_credentials)
        self.assertEqual(config.database.type, "sqlite")
    
    def test_get_method(self):
        """Test de la méthode get"""
        config = ConfigManager(self.config_file)
        
        # Test avec clé existante
        timeout = config.get('scan.timeout')
        self.assertEqual(timeout, 10)
        
        # Test avec clé inexistante
        nonexistent = config.get('nonexistent.key', 'default')
        self.assertEqual(nonexistent, 'default')
    
    def test_validate_config(self):
        """Test de la validation de configuration"""
        config = ConfigManager(self.config_file)
        
        errors = config.validate_config()
        self.assertEqual(len(errors), 0, f"Erreurs de validation: {errors}")

class TestLogger(unittest.TestCase):
    """Tests du système de logging"""
    
    def setUp(self):
        """Configuration des tests"""
        self.test_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.test_dir, 'test.log')
        
        self.config = {
            'level': 'INFO',
            'file_handler': {
                'enabled': True,
                'file': self.log_file,
                'max_size': '1MB',
                'backup_count': 3
            },
            'console_handler': {
                'enabled': False
            }
        }
    
    def tearDown(self):
        """Nettoyage après tests"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_logger_creation(self):
        """Test de la création du logger"""
        logger = ATLOSLogger("test_logger", self.config)
        
        self.assertIsNotNone(logger.logger)
        self.assertEqual(logger.logger.level, 20)  # INFO level
    
    def test_log_methods(self):
        """Test des méthodes de log"""
        logger = ATLOSLogger("test_logger", self.config)
        
        # Test des différentes méthodes
        logger.info("Test info message")
        logger.warning("Test warning message")
        logger.error("Test error message")
        logger.security("Test security message", target="192.168.1.1")
        logger.audit("Test audit message", action="test_action")
        
        # Vérification que le fichier de log a été créé
        self.assertTrue(os.path.exists(self.log_file))

class TestCredentialManager(unittest.TestCase):
    """Tests du gestionnaire de credentials"""
    
    def setUp(self):
        """Configuration des tests"""
        self.test_dir = tempfile.mkdtemp()
        self.key_file = os.path.join(self.test_dir, 'test_key')
        
        # Mock pour éviter la création de fichier réel
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = b'test_key_data_123456789012345678901234'
            with patch('os.chmod'):
                self.credential_manager = CredentialManager()
    
    def tearDown(self):
        """Nettoyage après tests"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_encrypt_decrypt(self):
        """Test du chiffrement/déchiffrement"""
        test_data = "Donnée de test secrète"
        
        # Chiffrement
        encrypted = self.credential_manager.encrypt(test_data)
        self.assertNotEqual(encrypted, test_data)
        self.assertIsInstance(encrypted, str)
        
        # Déchiffrement
        decrypted = self.credential_manager.decrypt(encrypted)
        self.assertEqual(decrypted, test_data)
    
    def test_encrypt_credentials(self):
        """Test du chiffrement de credentials complets"""
        username = "testuser"
        password = "testpass"
        
        encrypted_creds = self.credential_manager.encrypt_credentials(
            username, password, service="test"
        )
        
        self.assertIn('id', encrypted_creds)
        self.assertIn('encrypted_data', encrypted_creds)
        self.assertIn('integrity_hash', encrypted_creds)
        
        # Déchiffrement
        decrypted = self.credential_manager.decrypt_credentials(encrypted_creds)
        self.assertEqual(decrypted['username'], username)
        self.assertEqual(decrypted['password'], password)
        self.assertEqual(decrypted['service'], "test")
    
    def test_generate_secure_token(self):
        """Test de génération de token sécurisé"""
        token = self.credential_manager.generate_secure_token(32)
        
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 40)  # Base64 encoding

class TestDatabaseManager(unittest.TestCase):
    """Tests du gestionnaire de base de données"""
    
    def setUp(self):
        """Configuration des tests"""
        self.test_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.test_dir, 'test.db')
        
        # Configuration de test
        self.config = Mock()
        self.config.database = Mock()
        self.config.database.type = "sqlite"
        self.config.database.sqlite_path = self.db_file
        self.config.database.pool_size = 5
        self.config.database.max_overflow = 10
        
        self.logger = Mock()
        
        # Création du gestionnaire de base de données
        self.db_manager = DatabaseManager(self.config, self.logger)
    
    def tearDown(self):
        """Nettoyage après tests"""
        self.db_manager.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_database_initialization(self):
        """Test de l'initialisation de la base de données"""
        self.assertIsNotNone(self.db_manager.engine)
        self.assertIsNotNone(self.db_manager.SessionLocal)
        
        # Vérification que le fichier de base de données existe
        self.assertTrue(os.path.exists(self.db_file))
    
    def test_save_scan(self):
        """Test de sauvegarde de scan"""
        scan_data = {
            'scan_id': 'test-scan-123',
            'target_network': '192.168.1.0/24',
            'scan_type': 'network_discovery',
            'status': 'running',
            'start_time': '2024-01-01T12:00:00',
            'total_hosts': 254,
            'hosts_scanned': 0,
            'hosts_online': 0,
            'vulnerabilities_found': 0
        }
        
        scan_id = self.db_manager.save_scan(scan_data)
        self.assertEqual(scan_id, 'test-scan-123')
        
        # Vérification de la sauvegarde
        retrieved_scan = self.db_manager.get_scan(scan_id)
        self.assertIsNotNone(retrieved_scan)
        self.assertEqual(retrieved_scan['scan_id'], 'test-scan-123')
        self.assertEqual(retrieved_scan['target_network'], '192.168.1.0/24')
    
    def test_save_hosts(self):
        """Test de sauvegarde d'hôtes"""
        # D'abord sauvegarder un scan
        scan_data = {
            'scan_id': 'test-scan-hosts',
            'target_network': '192.168.1.0/24',
            'scan_type': 'network_discovery',
            'status': 'running',
            'start_time': '2024-01-01T12:00:00',
            'total_hosts': 2,
            'hosts_scanned': 0,
            'hosts_online': 0,
            'vulnerabilities_found': 0
        }
        
        self.db_manager.save_scan(scan_data)
        
        # Sauvegarde des hôtes
        hosts_data = [
            {
                'ip': '192.168.1.1',
                'hostname': 'router',
                'mac': '00:11:22:33:44:55',
                'vendor': 'TestVendor',
                'os_guess': 'Linux',
                'status': 'online',
                'ports_open': [22, 80],
                'services': {'22/tcp': 'SSH', '80/tcp': 'HTTP'},
                'vulnerabilities': [],
                'metadata': {}
            },
            {
                'ip': '192.168.1.2',
                'hostname': 'server',
                'mac': 'aa:bb:cc:dd:ee:ff',
                'vendor': 'AnotherVendor',
                'os_guess': 'Windows',
                'status': 'online',
                'ports_open': [445, 3389],
                'services': {'445/tcp': 'SMB', '3389/tcp': 'RDP'},
                'vulnerabilities': [{'cve': 'CVE-2024-1234', 'severity': 'High'}],
                'metadata': {}
            }
        ]
        
        saved_count = self.db_manager.save_hosts('test-scan-hosts', hosts_data)
        self.assertEqual(saved_count, 2)
        
        # Vérification de la sauvegarde
        retrieved_hosts = self.db_manager.get_scan_hosts('test-scan-hosts')
        self.assertEqual(len(retrieved_hosts), 2)
        
        # Vérification des données
        host1 = next(h for h in retrieved_hosts if h['ip'] == '192.168.1.1')
        self.assertEqual(host1['hostname'], 'router')
        self.assertEqual(host1['ports_open'], [22, 80])

class TestNetworkScanner(unittest.TestCase):
    """Tests du scanner réseau"""
    
    def setUp(self):
        """Configuration des tests"""
        self.test_dir = tempfile.mkdtemp()
        
        # Mock de la configuration
        self.config = Mock()
        self.config.scan = Mock()
        self.config.scan.timeout = 5
        self.config.scan.max_threads = 10
        self.config.scan.stealth_mode = False
        self.config.scan.random_delay = True
        self.config.scan.delay_range = [0.1, 1.0]
        self.config.scan.retry_attempts = 3
        self.config.scan.default_ports = "22,80,443"
        self.config.scan.exclude_hosts = []
        
        self.config._config_data = {}
        
        # Mock du logger
        self.logger = Mock()
        
        # Mock de l'optimiseur
        with patch('core.scanner.ATLOSOptimizer'):
            self.scanner = NetworkScanner(self.config, self.logger)
    
    def tearDown(self):
        """Nettoyage après tests"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_scanner_initialization(self):
        """Test de l'initialisation du scanner"""
        self.assertIsNotNone(self.scanner.config)
        self.assertIsNotNone(self.scanner.logger)
        self.assertFalse(self.scanner.is_scanning)
        self.assertIsNone(self.scanner.current_scan_id)
    
    def test_create_default_scan_config(self):
        """Test de la création de configuration par défaut"""
        with patch.object(self.scanner, '_get_current_network', return_value='192.168.1.0/24'):
            scan_config = self.scanner._create_default_scan_config()
            
            self.assertIsInstance(scan_config, ScanConfig)
            self.assertEqual(scan_config.target_network, '192.168.1.0/24')
            self.assertEqual(scan_config.timeout, 5)
            self.assertEqual(scan_config.max_threads, 10)
    
    def test_generate_scan_id(self):
        """Test de génération d'ID de scan"""
        scan_id1 = self.scanner._generate_scan_id()
        scan_id2 = self.scanner._generate_scan_id()
        
        self.assertIsInstance(scan_id1, str)
        self.assertIsInstance(scan_id2, str)
        self.assertNotEqual(scan_id1, scan_id2)
        self.assertEqual(len(scan_id1), 36)  # UUID length
    
    @patch('socket.gethostbyaddr')
    def test_get_hostname(self, mock_gethostbyaddr):
        """Test de récupération du hostname"""
        # Test avec hostname trouvé
        mock_gethostbyaddr.return_value = ('test-hostname', [], ['192.168.1.1'])
        hostname = self.scanner._get_hostname('192.168.1.1')
        self.assertEqual(hostname, 'test-hostname')
        
        # Test avec erreur
        mock_gethostbyaddr.side_effect = Exception("Erreur")
        hostname = self.scanner._get_hostname('192.168.1.2')
        self.assertEqual(hostname, 'Inconnu')
    
    @patch('subprocess.run')
    def test_get_mac_and_vendor(self, mock_subprocess):
        """Test de récupération MAC et vendor"""
        # Mock de la sortie de la commande arp
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout.decode.return_value = """
192.168.1.1 ether 00:11:22:33:44:55 C eth0
"""
        
        mac, vendor = self.scanner._get_mac_and_vendor('192.168.1.1')
        self.assertEqual(mac, '00:11:22:33:44:55')
        self.assertEqual(vendor, 'Inconnu')  # Vendor par défaut sans API
        
        # Test avec erreur
        mock_subprocess.side_effect = Exception("Erreur")
        mac, vendor = self.scanner._get_mac_and_vendor('192.168.1.2')
        self.assertEqual(mac, 'Inconnu')
        self.assertEqual(vendor, 'Inconnu')

class TestIntegration(unittest.TestCase):
    """Tests d'intégration"""
    
    def setUp(self):
        """Configuration des tests"""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Nettoyage après tests"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_config_logger_integration(self):
        """Test d'intégration config + logger"""
        config_file = os.path.join(self.test_dir, 'integration_config.yaml')
        
        config_content = """
logging:
  level: "DEBUG"
  file_handler:
    enabled: true
    file: "test_integration.log"
    max_size: "1MB"
    backup_count: 2
"""
        
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        # Initialisation
        config = ConfigManager(config_file)
        logger_config = config.get('logging', {})
        logger = ATLOSLogger("integration_test", logger_config)
        
        # Test
        self.assertIsNotNone(logger)
        logger.info("Test d'intégration")
        
        # Vérification
        log_file = os.path.join(self.test_dir, 'test_integration.log')
        self.assertTrue(os.path.exists(log_file))
    
    def test_crypto_database_integration(self):
        """Test d'intégration crypto + database"""
        # Configuration
        config = Mock()
        config.database = Mock()
        config.database.type = "sqlite"
        config.database.sqlite_path = os.path.join(self.test_dir, 'crypto_test.db')
        config.database.pool_size = 5
        config.database.max_overflow = 10
        
        logger = Mock()
        
        # Initialisation
        with patch('builtins.open', create=True):
            credential_manager = CredentialManager()
            db_manager = DatabaseManager(config, logger)
        
        # Test de chiffrement et sauvegarde
        test_credentials = {
            'username': 'testuser',
            'password': 'testpass',
            'service': 'test_service'
        }
        
        encrypted = credential_manager.encrypt_credentials(
            test_credentials['username'],
            test_credentials['password'],
            service=test_credentials['service']
        )
        
        self.assertIsNotNone(encrypted)
        
        # Nettoyage
        db_manager.close()

if __name__ == '__main__':
    # Configuration des tests
    unittest.main(verbosity=2)
