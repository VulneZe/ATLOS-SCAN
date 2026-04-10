#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API REST ATLOS v5.0
Endpoints FastAPI pour l'intégration externe
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
import uuid
import logging

from ..utils.config import ConfigManager
from ..utils.logger import ATLOSLogger
from ..core.scanner import NetworkScanner, ScanConfig
from ..utils.database import DatabaseManager

# Modèles Pydantic pour l'API
class ScanRequest(BaseModel):
    target_network: str = Field(..., description="Réseau cible (ex: 192.168.1.0/24)")
    ports: Optional[str] = Field(None, description="Ports à scanner")
    timeout: Optional[int] = Field(None, description="Timeout en secondes")
    max_threads: Optional[int] = Field(None, description="Nombre de threads")
    stealth_mode: Optional[bool] = Field(False, description="Mode furtif")
    exclude_hosts: Optional[List[str]] = Field(None, description="Hôtes à exclure")

class ScanResponse(BaseModel):
    scan_id: str = Field(..., description="ID unique du scan")
    status: str = Field(..., description="Statut du scan")
    target_network: str = Field(..., description="Réseau scanné")
    start_time: datetime = Field(..., description="Heure de début")
    estimated_duration: Optional[int] = Field(None, description="Durée estimée (secondes)")

class HostResult(BaseModel):
    ip: str = Field(..., description="Adresse IP")
    hostname: str = Field(..., description="Hostname")
    mac: str = Field(..., description="Adresse MAC")
    vendor: str = Field(..., description="Vendor MAC")
    os_guess: str = Field(..., description="OS détecté")
    status: str = Field(..., description="Statut (online/offline)")
    ports_open: List[int] = Field(default_factory=list, description="Ports ouverts")
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list, description="Vulnérabilités")

class ScanResult(BaseModel):
    scan_id: str = Field(..., description="ID du scan")
    status: str = Field(..., description="Statut final")
    target_network: str = Field(..., description="Réseau scanné")
    start_time: datetime = Field(..., description="Heure de début")
    end_time: Optional[datetime] = Field(None, description="Heure de fin")
    duration: Optional[float] = Field(None, description="Durée totale")
    total_hosts: int = Field(..., description="Nombre total d'hôtes")
    hosts_online: int = Field(..., description="Hôtes en ligne")
    vulnerabilities_found: int = Field(..., description="Vulnérabilités trouvées")
    hosts: List[HostResult] = Field(..., description="Résultats détaillés")

class StatisticsResponse(BaseModel):
    total_scans: int = Field(..., description="Nombre total de scans")
    total_hosts: int = Field(..., description="Nombre total d'hôtes scannés")
    total_vulnerabilities: int = Field(..., description="Nombre total de vulnérabilités")
    vulnerabilities_by_severity: Dict[str, int] = Field(..., description="Vulnérabilités par sévérité")
    recent_scans: List[Dict[str, Any]] = Field(..., description="Scans récents")

# Sécurité
security = HTTPBearer()

def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Vérifie la clé API"""
    # Implémentation basique - à améliorer avec une vraie authentification
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Clé API manquante")
    
    # Vérification basique (dans une vraie implémentation, vérifier en base)
    return credentials.credentials

# Gestionnaire de scans en cours
class ScanManager:
    """Gestionnaire des scans asynchrones"""
    
    def __init__(self, config: ConfigManager, logger: ATLOSLogger, database: DatabaseManager):
        self.config = config
        self.logger = logger
        self.database = database
        self.scanner = NetworkScanner(config, logger)
        self.running_scans = {}  # scan_id -> task
        
    async def start_scan(self, scan_request: ScanRequest) -> ScanResponse:
        """Démarre un scan en arrière-plan"""
        scan_id = str(uuid.uuid4())
        
        # Configuration du scan
        scan_config = ScanConfig(
            target_network=scan_request.target_network,
            ports=scan_request.ports or self.config.scan.default_ports,
            timeout=scan_request.timeout or self.config.scan.timeout,
            max_threads=scan_request.max_threads or self.config.scan.max_threads,
            stealth_mode=scan_request.stealth_mode,
            exclude_hosts=scan_request.exclude_hosts or []
        )
        
        # Sauvegarde initiale du scan
        scan_data = {
            'scan_id': scan_id,
            'target_network': scan_request.target_network,
            'scan_type': 'network_discovery',
            'status': 'running',
            'start_time': datetime.utcnow().isoformat(),
            'config': scan_config.__dict__
        }
        
        self.database.save_scan(scan_data)
        
        # Démarrage du scan en arrière-plan
        task = asyncio.create_task(self._run_scan(scan_id, scan_config))
        self.running_scans[scan_id] = task
        
        self.logger.info(f"Scan démarré: {scan_id} sur {scan_request.target_network}")
        
        return ScanResponse(
            scan_id=scan_id,
            status="running",
            target_network=scan_request.target_network,
            start_time=datetime.utcnow(),
            estimated_duration=300  # Estimation basique
        )
    
    async def _run_scan(self, scan_id: str, scan_config: ScanConfig):
        """Exécute le scan en arrière-plan"""
        try:
            # Lancement du scan
            results = self.scanner.scan_network(scan_config)
            
            # Conversion des résultats
            hosts_data = []
            for result in results:
                host_data = {
                    'ip': result.ip,
                    'hostname': result.hostname,
                    'mac': result.mac,
                    'vendor': result.vendor,
                    'os_guess': result.os_guess,
                    'status': result.status,
                    'scan_time': result.scan_time,
                    'ports_open': result.ports_open,
                    'services': result.services,
                    'vulnerabilities': result.vulnerabilities,
                    'metadata': result.metadata
                }
                hosts_data.append(host_data)
            
            # Sauvegarde des hôtes
            self.database.save_hosts(scan_id, hosts_data)
            
            # Mise à jour du scan
            stats = self.scanner.get_scan_stats()
            updates = {
                'status': 'completed',
                'end_time': datetime.utcnow().isoformat(),
                'duration': stats.get('scan_duration'),
                'total_hosts': stats.get('total_hosts'),
                'hosts_scanned': stats.get('hosts_scanned'),
                'hosts_online': stats.get('hosts_online'),
                'vulnerabilities_found': stats.get('vulnerabilities_found')
            }
            
            self.database.update_scan(scan_id, updates)
            
            self.logger.info(f"Scan terminé: {scan_id}")
            
        except Exception as e:
            # Gestion des erreurs
            updates = {
                'status': 'failed',
                'end_time': datetime.utcnow().isoformat(),
                'metadata': {'error': str(e)}
            }
            
            self.database.update_scan(scan_id, updates)
            self.logger.error(f"Scan échoué: {scan_id} - {e}")
        
        finally:
            # Nettoyage
            if scan_id in self.running_scans:
                del self.running_scans[scan_id]
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retourne le statut d'un scan"""
        scan_data = self.database.get_scan(scan_id)
        
        if not scan_data:
            return None
        
        return {
            'scan_id': scan_data['scan_id'],
            'status': scan_data['status'],
            'target_network': scan_data['target_network'],
            'start_time': scan_data['start_time'],
            'end_time': scan_data['end_time'],
            'duration': scan_data['duration'],
            'total_hosts': scan_data['total_hosts'],
            'hosts_scanned': scan_data['hosts_scanned'],
            'hosts_online': scan_data['hosts_online'],
            'vulnerabilities_found': scan_data['vulnerabilities_found']
        }
    
    def get_scan_results(self, scan_id: str) -> Optional[ScanResult]:
        """Retourne les résultats complets d'un scan"""
        scan_data = self.database.get_scan(scan_id)
        
        if not scan_data:
            return None
        
        hosts_data = self.database.get_scan_hosts(scan_id)
        
        # Conversion des hôtes en HostResult
        hosts = []
        for host_data in hosts_data:
            hosts.append(HostResult(**host_data))
        
        return ScanResult(
            scan_id=scan_data['scan_id'],
            status=scan_data['status'],
            target_network=scan_data['target_network'],
            start_time=datetime.fromisoformat(scan_data['start_time']) if scan_data['start_time'] else None,
            end_time=datetime.fromisoformat(scan_data['end_time']) if scan_data['end_time'] else None,
            duration=scan_data['duration'],
            total_hosts=scan_data['total_hosts'],
            hosts_online=scan_data['hosts_online'],
            vulnerabilities_found=scan_data['vulnerabilities_found'],
            hosts=hosts
        )
    
    def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Liste les scans récents"""
        return self.database.list_scans(limit, offset)
    
    def get_statistics(self) -> StatisticsResponse:
        """Retourne des statistiques"""
        stats = self.database.get_statistics()
        
        return StatisticsResponse(**stats)

# Création de l'application FastAPI
def create_app(config: ConfigManager, logger: ATLOSLogger) -> FastAPI:
    """Crée l'application FastAPI"""
    
    app = FastAPI(
        title="ATLOS v5.0 API",
        description="Advanced Threat Landscape Observation System - REST API",
        version="5.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Configuration CORS
    if config.api.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.api.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    # Initialisation du gestionnaire de scans
    database = DatabaseManager(config, logger)
    scan_manager = ScanManager(config, logger, database)
    
    @app.get("/")
    async def root():
        """Endpoint racine"""
        return {
            "name": "ATLOS v5.0 API",
            "version": "5.0.0",
            "status": "running",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @app.post("/api/v1/scans", response_model=ScanResponse)
    async def create_scan(
        scan_request: ScanRequest,
        api_key: str = Depends(verify_api_key)
    ):
        """Démarre un nouveau scan réseau"""
        try:
            return await scan_manager.start_scan(scan_request)
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du scan: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v1/scans/{scan_id}/status")
    async def get_scan_status(
        scan_id: str,
        api_key: str = Depends(verify_api_key)
    ):
        """Retourne le statut d'un scan"""
        status = scan_manager.get_scan_status(scan_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Scan non trouvé")
        
        return status
    
    @app.get("/api/v1/scans/{scan_id}", response_model=ScanResult)
    async def get_scan_results(
        scan_id: str,
        api_key: str = Depends(verify_api_key)
    ):
        """Retourne les résultats complets d'un scan"""
        results = scan_manager.get_scan_results(scan_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="Scan non trouvé")
        
        return results
    
    @app.get("/api/v1/scans")
    async def list_scans(
        limit: int = 50,
        offset: int = 0,
        api_key: str = Depends(verify_api_key)
    ):
        """Liste les scans récents"""
        try:
            return scan_manager.list_scans(limit, offset)
        except Exception as e:
            logger.error(f"Erreur lors de la liste des scans: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v1/statistics", response_model=StatisticsResponse)
    async def get_statistics(api_key: str = Depends(verify_api_key)):
        """Retourne des statistiques sur les scans"""
        try:
            return scan_manager.get_statistics()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.delete("/api/v1/scans/{scan_id}")
    async def delete_scan(
        scan_id: str,
        api_key: str = Depends(verify_api_key)
    ):
        """Supprime un scan et ses résultats"""
        try:
            # Implémentation de la suppression à ajouter dans DatabaseManager
            raise HTTPException(status_code=501, detail="Non implémenté")
        except Exception as e:
            logger.error(f"Erreur lors de la suppression du scan: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/v1/health")
    async def health_check():
        """Endpoint de health check"""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "5.0.0"
        }
    
    # Gestion des erreurs
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "status_code": exc.status_code}
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request, exc):
        logger.error(f"Erreur non gérée: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": "Erreur interne du serveur", "status_code": 500}
        )
    
    return app
