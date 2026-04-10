#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base de données ATLOS v5.0
Gestion de la persistance avec SQLAlchemy et migrations
"""

import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.sqlite import JSON
import logging
import sys

from .config import ConfigManager
from .logger import ATLOSLogger

Base = declarative_base()

class Scan(Base):
    """Table des scans"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, nullable=False)
    target_network = Column(String(45), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(20), default='running')
    start_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    end_time = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    total_hosts = Column(Integer, default=0)
    hosts_scanned = Column(Integer, default=0)
    hosts_online = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    config = Column(JSON, nullable=True)
    metadata = Column(JSON, nullable=True)
    
    # Relations
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'objet en dictionnaire"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'target_network': self.target_network,
            'scan_type': self.scan_type,
            'status': self.status,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'total_hosts': self.total_hosts,
            'hosts_scanned': self.hosts_scanned,
            'hosts_online': self.hosts_online,
            'vulnerabilities_found': self.vulnerabilities_found,
            'config': self.config,
            'metadata': self.metadata
        }

class Host(Base):
    """Table des hôtes scannés"""
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), ForeignKey('scans.scan_id'), nullable=False)
    ip = Column(String(45), nullable=False)
    hostname = Column(String(255), default='Unknown')
    mac = Column(String(17), default='Unknown')
    vendor = Column(String(255), default='Unknown')
    os_guess = Column(String(255), default='Unknown')
    status = Column(String(20), default='unknown')
    scan_time = Column(Float, default=0.0)
    ports_open = Column(JSON, default=list)
    services = Column(JSON, default=dict)
    vulnerabilities = Column(JSON, default=list)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relations
    scan = relationship("Scan", back_populates="hosts")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'objet en dictionnaire"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'ip': self.ip,
            'hostname': self.hostname,
            'mac': self.mac,
            'vendor': self.vendor,
            'os_guess': self.os_guess,
            'status': self.status,
            'scan_time': self.scan_time,
            'ports_open': self.ports_open,
            'services': self.services,
            'vulnerabilities': self.vulnerabilities,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Vulnerability(Base):
    """Table des vulnérabilités"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    cve = Column(String(20), nullable=True)
    name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=True)
    port = Column(Integer, nullable=True)
    service = Column(String(100), nullable=True)
    exploit_available = Column(Boolean, default=False)
    metasploit_module = Column(String(255), nullable=True)
    raw_output = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'objet en dictionnaire"""
        return {
            'id': self.id,
            'host_id': self.host_id,
            'cve': self.cve,
            'name': self.name,
            'severity': self.severity,
            'description': self.description,
            'port': self.port,
            'service': self.service,
            'exploit_available': self.exploit_available,
            'metasploit_module': self.metasploit_module,
            'raw_output': self.raw_output,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }

class Credential(Base):
    """Table des credentials chiffrés"""
    __tablename__ = 'credentials'
    
    id = Column(Integer, primary_key=True)
    service = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    encrypted_password = Column(Text, nullable=False)
    salt = Column(String(64), nullable=False)
    domain = Column(String(255), nullable=True)
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'objet en dictionnaire (sans mot de passe)"""
        return {
            'id': self.id,
            'service': self.service,
            'username': self.username,
            'domain': self.domain,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'is_active': self.is_active
        }

class DatabaseManager:
    """Gestionnaire de base de données ATLOS"""
    
    def __init__(self, config: ConfigManager, logger: ATLOSLogger):
        self.config = config
        self.logger = logger
        self.engine = None
        self.SessionLocal = None
        
        # Initialisation de la base de données
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialise la connexion à la base de données"""
        try:
            db_config = self.config.database
            
            # Construction de l'URL de connexion
            if db_config.type == 'sqlite':
                # Créer le répertoire si nécessaire
                db_path = db_config.sqlite_path
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                
                database_url = f"sqlite:///{db_path}"
                
                # Configuration SQLite spécifique
                self.engine = create_engine(
                    database_url,
                    pool_pre_ping=True,
                    echo=self.config.get('logging.level') == 'DEBUG'
                )
            
            elif db_config.type == 'postgresql':
                database_url = (
                    f"postgresql://{db_config.user}:{db_config.password}"
                    f"@{db_config.host}:{db_config.port}/{db_config.name}"
                )
                
                self.engine = create_engine(
                    database_url,
                    pool_size=db_config.pool_size,
                    max_overflow=db_config.max_overflow,
                    pool_pre_ping=True
                )
            
            elif db_config.type == 'mysql':
                database_url = (
                    f"mysql+pymysql://{db_config.user}:{db_config.password}"
                    f"@{db_config.host}:{db_config.port}/{db_config.name}"
                )
                
                self.engine = create_engine(
                    database_url,
                    pool_size=db_config.pool_size,
                    max_overflow=db_config.max_overflow,
                    pool_pre_ping=True
                )
            
            else:
                raise ValueError(f"Type de base de données non supporté: {db_config.type}")
            
            # Création de la session factory
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            
            # Création des tables
            self._create_tables()
            
            self.logger.info(f"Base de données initialisée: {db_config.type}")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
            raise
    
    def _create_tables(self):
        """Crée les tables de la base de données"""
        try:
            Base.metadata.create_all(bind=self.engine)
            self.logger.info("Tables créées avec succès")
        except Exception as e:
            self.logger.error(f"Erreur lors de la création des tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """Retourne une session de base de données"""
        if self.SessionLocal is None:
            raise RuntimeError("Base de données non initialisée")
        
        return self.SessionLocal()
    
    def save_scan(self, scan_data: Dict[str, Any]) -> str:
        """
        Sauvegarde un scan dans la base de données
        
        Args:
            scan_data: Données du scan
            
        Returns:
            str: ID du scan sauvegardé
        """
        session = self.get_session()
        
        try:
            # Création de l'objet Scan
            scan = Scan(
                scan_id=scan_data['scan_id'],
                target_network=scan_data['target_network'],
                scan_type=scan_data['scan_type'],
                status=scan_data.get('status', 'running'),
                start_time=self._parse_datetime(scan_data.get('start_time')),
                end_time=self._parse_datetime(scan_data.get('end_time')),
                duration=scan_data.get('duration'),
                total_hosts=scan_data.get('total_hosts', 0),
                hosts_scanned=scan_data.get('hosts_scanned', 0),
                hosts_online=scan_data.get('hosts_online', 0),
                vulnerabilities_found=scan_data.get('vulnerabilities_found', 0),
                config=scan_data.get('config'),
                metadata=scan_data.get('metadata')
            )
            
            session.add(scan)
            session.commit()
            
            self.logger.info(f"Scan sauvegardé: {scan.scan_id}")
            return scan.scan_id
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Erreur lors de la sauvegarde du scan: {e}")
            raise
        finally:
            session.close()
    
    def update_scan(self, scan_id: str, updates: Dict[str, Any]) -> bool:
        """
        Met à jour un scan existant
        
        Args:
            scan_id: ID du scan à mettre à jour
            updates: Données à mettre à jour
            
        Returns:
            bool: True si succès, False sinon
        """
        session = self.get_session()
        
        try:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            
            if not scan:
                self.logger.warning(f"Scan non trouvé: {scan_id}")
                return False
            
            # Mise à jour des champs
            for key, value in updates.items():
                if hasattr(scan, key):
                    if key in ['start_time', 'end_time'] and isinstance(value, str):
                        value = datetime.fromisoformat(value)
                    setattr(scan, key, value)
            
            session.commit()
            self.logger.info(f"Scan mis à jour: {scan_id}")
            return True
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Erreur lors de la mise à jour du scan: {e}")
            return False
        finally:
            session.close()
    
    def save_hosts(self, scan_id: str, hosts_data: List[Dict[str, Any]]) -> int:
        """
        Sauvegarde les hôtes d'un scan
        
        Args:
            scan_id: ID du scan
            hosts_data: Liste des données des hôtes
            
        Returns:
            int: Nombre d'hôtes sauvegardés
        """
        session = self.get_session()
        
        try:
            saved_count = 0
            
            for host_data in hosts_data:
                host = Host(
                    scan_id=scan_id,
                    ip=host_data['ip'],
                    hostname=host_data.get('hostname', 'Unknown'),
                    mac=host_data.get('mac', 'Unknown'),
                    vendor=host_data.get('vendor', 'Unknown'),
                    os_guess=host_data.get('os_guess', 'Unknown'),
                    status=host_data.get('status', 'unknown'),
                    scan_time=host_data.get('scan_time', 0.0),
                    ports_open=host_data.get('ports_open', []),
                    services=host_data.get('services', {}),
                    vulnerabilities=host_data.get('vulnerabilities', []),
                    metadata=host_data.get('metadata', {})
                )
                
                session.add(host)
                saved_count += 1
            
            session.commit()
            self.logger.info(f"{saved_count} hôtes sauvegardés pour le scan {scan_id}")
            return saved_count
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Erreur lors de la sauvegarde des hôtes: {e}")
            raise
        finally:
            session.close()
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère un scan par son ID
        
        Args:
            scan_id: ID du scan
            
        Returns:
            Optional[Dict[str, Any]]: Données du scan ou None
        """
        session = self.get_session()
        
        try:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            
            if scan:
                return scan.to_dict()
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération du scan {scan_id}: {e}")
            return None
        finally:
            session.close()
    
    def get_scan_hosts(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Récupère les hôtes d'un scan
        
        Args:
            scan_id: ID du scan
            
        Returns:
            List[Dict[str, Any]]: Liste des hôtes
        """
        session = self.get_session()
        
        try:
            hosts = session.query(Host).filter(Host.scan_id == scan_id).all()
            return [host.to_dict() for host in hosts]
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des hôtes du scan {scan_id}: {e}")
            return []
        finally:
            session.close()
    
    def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Liste les scans récents
        
        Args:
            limit: Nombre maximum de résultats
            offset: Décalage pour la pagination
            
        Returns:
            List[Dict[str, Any]]: Liste des scans
        """
        session = self.get_session()
        
        try:
            scans = session.query(Scan).order_by(Scan.start_time.desc()).offset(offset).limit(limit).all()
            return [scan.to_dict() for scan in scans]
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la liste des scans: {e}")
            return []
        finally:
            session.close()
    
    def get_vulnerabilities_by_severity(self, severity: str = None) -> List[Dict[str, Any]]:
        """
        Récupère les vulnérabilités par sévérité
        
        Args:
            severity: Sévérité filtrée (Critical, High, Medium, Low)
            
        Returns:
            List[Dict[str, Any]]: Liste des vulnérabilités
        """
        session = self.get_session()
        
        try:
            query = session.query(Vulnerability)
            
            if severity:
                query = query.filter(Vulnerability.severity == severity)
            
            vulnerabilities = query.order_by(Vulnerability.discovered_at.desc()).all()
            return [vuln.to_dict() for vuln in vulnerabilities]
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des vulnérabilités: {e}")
            return []
        finally:
            session.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Retourne des statistiques sur les scans
        
        Returns:
            Dict[str, Any]: Statistiques
        """
        session = self.get_session()
        
        try:
            # Statistiques générales
            total_scans = session.query(Scan).count()
            total_hosts = session.query(Host).count()
            total_vulnerabilities = session.query(Vulnerability).count()
            
            # Vulnérabilités par sévérité
            vuln_by_severity = {}
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = session.query(Vulnerability).filter(Vulnerability.severity == severity).count()
                vuln_by_severity[severity] = count
            
            # Scans récents
            recent_scans = session.query(Scan).order_by(Scan.start_time.desc()).limit(5).all()
            recent_scan_data = [scan.to_dict() for scan in recent_scans]
            
            return {
                'total_scans': total_scans,
                'total_hosts': total_hosts,
                'total_vulnerabilities': total_vulnerabilities,
                'vulnerabilities_by_severity': vuln_by_severity,
                'recent_scans': recent_scan_data
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors du calcul des statistiques: {e}")
            return {}
        finally:
            session.close()
    
    def cleanup_old_data(self, days: int = 30) -> int:
        """
        Nettoie les anciennes données
        
        Args:
            days: Nombre de jours de rétention
            
        Returns:
            int: Nombre d'enregistrements supprimés
        """
        session = self.get_session()
        
        try:
            cutoff_date = datetime.utcnow().timestamp() - (days * 24 * 3600)
            cutoff_datetime = datetime.fromtimestamp(cutoff_date)
            
            # Suppression des anciens scans
            old_scans = session.query(Scan).filter(Scan.start_time < cutoff_datetime).all()
            deleted_count = len(old_scans)
            
            for scan in old_scans:
                session.delete(scan)  # Cascade supprimera aussi les hôtes
            
            session.commit()
            self.logger.info(f"Nettoyage: {deleted_count} scans supprimés")
            return deleted_count
            
        except Exception as e:
            session.rollback()
            self.logger.error(f"Erreur lors du nettoyage des anciennes données: {e}")
            return 0
        finally:
            session.close()
    
    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse une chaîne de caractères en datetime"""
        if not dt_str:
            return None
        
        try:
            if isinstance(dt_str, datetime):
                return dt_str
            
            # Support des formats ISO et autres
            if 'T' in dt_str:
                return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            else:
                return datetime.fromisoformat(dt_str)
        except (ValueError, TypeError):
            self.logger.warning(f"Format de date invalide: {dt_str}")
            return datetime.now(timezone.utc)
    
    def close(self):
        """Ferme la connexion à la base de données"""
        if self.engine:
            self.engine.dispose()
            self.logger.info("Connexion à la base de données fermée")

# Instance globale pour faciliter l'utilisation
database_manager = None

def get_database(config: ConfigManager, logger: ATLOSLogger) -> DatabaseManager:
    """Retourne l'instance du gestionnaire de base de données"""
    global database_manager
    if database_manager is None:
        database_manager = DatabaseManager(config, logger)
    return database_manager

def init_database(config: ConfigManager, logger: ATLOSLogger) -> DatabaseManager:
    """Initialise le gestionnaire de base de données"""
    global database_manager
    database_manager = DatabaseManager(config, logger)
    return database_manager
