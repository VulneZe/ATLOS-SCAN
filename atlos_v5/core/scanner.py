#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moteur de scan réseau ATLOS v5.0
Scanner réseau avancé avec threading, timeout management et furtivité
"""

import os
import time
import socket
import threading
import subprocess
import ipaddress
from typing import List, Dict, Any, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from queue import Queue, Empty
import random
import logging
import sys

from ..utils.logger import ATLOSLogger
from ..utils.config import ConfigManager
from ..utils.performance import performance_monitor, memory_efficient, ATLOSOptimizer

@dataclass
class ScanResult:
    """Résultat d'un scan"""
    ip: str
    hostname: str = "Inconnu"
    mac: str = "Inconnu"
    vendor: str = "Inconnu"
    ports_open: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    os_guess: str = "Inconnu"
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    scan_time: float = 0.0
    status: str = "unknown"  # online, offline, filtered
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanConfig:
    """Configuration pour un scan"""
    target_network: str
    ports: str = "1-1000"
    timeout: int = 5
    max_threads: int = 50
    stealth_mode: bool = False
    random_delay: bool = True
    delay_range: Tuple[float, float] = (0.1, 2.0)
    retry_attempts: int = 3
    exclude_hosts: List[str] = field(default_factory=list)

class NetworkScanner:
    """Scanner réseau principal ATLOS"""
    
    def __init__(self, config: ConfigManager, logger: ATLOSLogger):
        self.config = config
        self.logger = logger
        self.scan_config = config.scan
        
        # Optimisation des performances
        self.optimizer = ATLOSOptimizer(config._config_data, logger)
        
        # État du scan
        self.is_scanning = False
        self.current_scan_id = None
        self.scan_results = []
        self.scan_queue = Queue()
        
        # Threading
        self.executor = None
        self.scan_lock = threading.Lock()
        
        # Statistiques
        self.stats = {
            'total_hosts': 0,
            'hosts_scanned': 0,
            'hosts_online': 0,
            'vulnerabilities_found': 0,
            'scan_duration': 0.0,
            'errors': 0
        }
    
    @performance_monitor
    def scan_network(self, scan_config: Optional[ScanConfig] = None) -> List[ScanResult]:
        """
        Scan complet d'un réseau
        
        Args:
            scan_config: Configuration personnalisée du scan
            
        Returns:
            List[ScanResult]: Résultats du scan
        """
        if scan_config is None:
            scan_config = self._create_default_scan_config()
        
        # Optimisation des paramètres selon les ressources
        optimized_params = self.optimizer.optimize_scan_parameters(scan_config.target_network)
        scan_config.max_threads = optimized_params['max_threads']
        scan_config.timeout = optimized_params['timeout']
        scan_config.stealth_mode = optimized_params['stealth_mode']
        
        with self.scan_lock:
            if self.is_scanning:
                raise RuntimeError("Un scan est déjà en cours")
            
            self.is_scanning = True
            self.current_scan_id = self._generate_scan_id()
            self.scan_results.clear()
            self.stats = {k: 0 for k in self.stats}
        
        try:
            self.logger.scan_start(
                scan_config.target_network, 
                "network_discovery",
                scan_id=self.current_scan_id
            )
            
            start_time = time.time()
            
            # Phase 1: Découverte des hôtes
            hosts = self._discover_hosts(scan_config)
            self.stats['total_hosts'] = len(hosts)
            
            if not hosts:
                self.logger.warning(f"Aucun hôte découvert sur {scan_config.target_network}")
                return []
            
            # Phase 2: Scan des hôtes découverts
            results = self._scan_hosts(hosts, scan_config)
            
            # Phase 3: Post-traitement
            processed_results = self._post_process_results(results, scan_config)
            
            # Statistiques finales
            end_time = time.time()
            self.stats['scan_duration'] = end_time - start_time
            self.stats['hosts_scanned'] = len(processed_results)
            self.stats['hosts_online'] = len([r for r in processed_results if r.status == 'online'])
            
            self.logger.scan_complete(
                scan_config.target_network,
                "network_discovery", 
                len(processed_results),
                scan_id=self.current_scan_id,
                duration=self.stats['scan_duration']
            )
            
            return processed_results
            
        except Exception as e:
            self.logger.error(f"Erreur lors du scan réseau: {e}")
            raise
        finally:
            with self.scan_lock:
                self.is_scanning = False
                self.current_scan_id = None
    
    def _create_default_scan_config(self) -> ScanConfig:
        """Crée une configuration de scan par défaut"""
        current_network = self._get_current_network()
        
        return ScanConfig(
            target_network=current_network or "192.168.1.0/24",
            ports=self.scan_config.default_ports,
            timeout=self.scan_config.timeout,
            max_threads=self.scan_config.max_threads,
            stealth_mode=self.scan_config.stealth_mode,
            random_delay=self.scan_config.random_delay,
            delay_range=tuple(self.scan_config.delay_range),
            retry_attempts=self.scan_config.retry_attempts,
            exclude_hosts=self.scan_config.exclude_hosts
        )
    
    def _get_current_network(self) -> Optional[str]:
        """Détecte le réseau actuel"""
        try:
            # Utiliser ip route pour obtenir l'interface et le réseau
            result = subprocess.run(
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'dev' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'dev' and i + 1 < len(parts):
                                interface = parts[i + 1]
                                # Obtenir l'IP de l'interface
                                ip_result = subprocess.run(
                                    ["ip", "addr", "show", interface],
                                    capture_output=True,
                                    text=True,
                                    timeout=10
                                )
                                
                                if ip_result.returncode == 0:
                                    for ip_line in ip_result.stdout.split('\n'):
                                        if 'inet ' in ip_line and '127.0.0.1' not in ip_line:
                                            ip_cidr = ip_line.split()[1]
                                            network = ipaddress.ip_network(ip_cidr, strict=False)
                                            return str(network)
            
        except FileNotFoundError:
            # Fallback pour Windows ou systèmes sans ip
            return self._get_windows_network()
        except Exception as e:
            self.logger.debug(f"Impossible de détecter le réseau actuel: {e}")
        
        return None
    
    def _get_windows_network(self) -> Optional[str]:
        """Détection réseau pour Windows"""
        try:
            # Utiliser ipconfig pour Windows
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parser la sortie ipconfig
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'IPv4' in line and 'Address' in line:
                        # Extraire l'IP
                        ip_match = line.split(':')[-1].strip()
                        ip = ip_match.split()[0] if ip_match else None
                        
                        if ip and ip != '127.0.0.1':
                            # Déterminer le réseau (assumer /24 pour Windows)
                            ip_parts = ip.split('.')
                            if len(ip_parts) == 4:
                                network_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                                return network_ip
            
        except Exception as e:
            self.logger.debug(f"Impossible de détecter le réseau Windows: {e}")
        
        return None
    
    def _discover_hosts(self, scan_config: ScanConfig) -> List[str]:
        """
        Phase 1: Découverte des hôtes actifs
        
        Args:
            scan_config: Configuration du scan
            
        Returns:
            List[str]: Liste des IP des hôtes actifs
        """
        self.logger.info(f"Découverte des hôtes sur {scan_config.target_network}")
        
        try:
            network = ipaddress.ip_network(scan_config.target_network, strict=False)
            hosts = [str(host) for host in network.hosts()]
            
            # Filtrer les hôtes exclus
            if scan_config.exclude_hosts:
                hosts = [h for h in hosts if h not in scan_config.exclude_hosts]
            
            # Utiliser ARP scan pour la découverte
            active_hosts = self._arp_scan(hosts, scan_config)
            
            self.logger.info(f"{len(active_hosts)} hôtes actifs découverts")
            return active_hosts
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la découverte des hôtes: {e}")
            return []
    
    def _arp_scan(self, hosts: List[str], scan_config: ScanConfig) -> List[str]:
        """
        Scan ARP pour découvrir les hôtes actifs
        
        Args:
            hosts: Liste des hôtes à scanner
            scan_config: Configuration du scan
            
        Returns:
            List[str]: Liste des hôtes répondant à l'ARP
        """
        active_hosts = []
        
        try:
            from scapy.all import srp, Ether, ARP, conf
            
            # Configuration pour le mode furtif
            if scan_config.stealth_mode:
                conf.verb = 0
            
            # Préparation du paquet ARP
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=scan_config.target_network)
            
            # Envoi et réception
            ans, _ = srp(arp_request, timeout=scan_config.timeout, verbose=False)
            
            # Extraction des hôtes répondants
            for _, rcv in ans:
                ip = rcv.psrc
                if ip in hosts:
                    active_hosts.append(ip)
            
        except ImportError:
            self.logger.warning("Scapy non disponible, utilisation de ping fallback")
            active_hosts = self._ping_fallback(hosts, scan_config)
        except Exception as e:
            self.logger.error(f"Erreur lors du scan ARP: {e}")
            active_hosts = self._ping_fallback(hosts, scan_config)
        
        return active_hosts
    
    def _ping_fallback(self, hosts: List[str], scan_config: ScanConfig) -> List[str]:
        """
        Fallback ping si Scapy n'est pas disponible
        
        Args:
            hosts: Liste des hôtes à pinguer
            scan_config: Configuration du scan
            
        Returns:
            List[str]: Liste des hôtes répondant au ping
        """
        active_hosts = []
        
        def ping_host(ip: str) -> bool:
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(scan_config.timeout), ip],
                    capture_output=True,
                    timeout=scan_config.timeout + 2
                )
                return result.returncode == 0
            except:
                return False
        
        # Ping en parallèle
        with ThreadPoolExecutor(max_workers=min(50, len(hosts))) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        active_hosts.append(ip)
                except Exception as e:
                    self.logger.debug(f"Erreur ping pour {ip}: {e}")
        
        return active_hosts
    
    @memory_efficient(max_items=1000)
    def _scan_hosts(self, hosts: List[str], scan_config: ScanConfig) -> List[ScanResult]:
        """
        Phase 2: Scan détaillé des hôtes
        
        Args:
            hosts: Liste des hôtes à scanner
            scan_config: Configuration du scan
            
        Returns:
            List[ScanResult]: Résultats détaillés du scan
        """
        self.logger.info(f"Scan détaillé de {len(hosts)} hôtes")
        
        results = []
        
        # Utilisation de ThreadPoolExecutor pour le parallélisme
        max_workers = min(scan_config.max_threads, len(hosts))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Soumission des tâches de scan
            future_to_host = {
                executor.submit(self._scan_single_host, host, scan_config): host 
                for host in hosts
            }
            
            # Traitement des résultats
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        
                        # Délai aléatoire si mode furtif
                        if scan_config.random_delay and scan_config.stealth_mode:
                            delay = random.uniform(*scan_config.delay_range)
                            time.sleep(delay)
                
                except Exception as e:
                    self.logger.error(f"Erreur lors du scan de {host}: {e}")
                    self.stats['errors'] += 1
                    
                    # Créer un résultat d'erreur
                    error_result = ScanResult(
                        ip=host,
                        status="error",
                        metadata={"error": str(e)}
                    )
                    results.append(error_result)
        
        return results
    
    def _scan_single_host(self, host: str, scan_config: ScanConfig) -> Optional[ScanResult]:
        """
        Scan d'un hôte individuel
        
        Args:
            host: IP de l'hôte à scanner
            scan_config: Configuration du scan
            
        Returns:
            Optional[ScanResult]: Résultat du scan
        """
        start_time = time.time()
        
        try:
            result = ScanResult(ip=host)
            
            # Informations de base
            result.hostname = self._get_hostname(host)
            result.mac, result.vendor = self._get_mac_and_vendor(host)
            
            # Scan de ports
            ports_info = self._scan_ports(host, scan_config)
            result.ports_open = ports_info['open_ports']
            result.services = ports_info['services']
            
            # Détection OS
            result.os_guess = self._detect_os(host, result.ports_open)
            
            # Scan de vulnérabilités
            if scan_config.ports and "vuln" in scan_config.ports.lower():
                result.vulnerabilities = self._scan_vulnerabilities(host, result.ports_open)
            
            # Statut
            result.status = "online" if result.ports_open else "filtered"
            
            # Temps de scan
            result.scan_time = time.time() - start_time
            
            # Logging des résultats significatifs
            if result.vulnerabilities:
                for vuln in result.vulnerabilities:
                    self.logger.vulnerability_found(host, vuln)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Erreur lors du scan de {host}: {e}")
            return ScanResult(
                ip=host,
                status="error",
                metadata={"error": str(e)},
                scan_time=time.time() - start_time
            )
    
    def _get_hostname(self, ip: str) -> str:
        """Récupère le hostname d'une IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Inconnu"
    
    def _get_mac_and_vendor(self, ip: str) -> Tuple[str, str]:
        """Récupère l'adresse MAC et le vendor"""
        try:
            # Utiliser ARP table pour obtenir le MAC
            result = subprocess.run(
                ["arp", "-n", ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            mac = parts[2]
                            vendor = self._get_mac_vendor(mac)
                            return mac, vendor
        except:
            pass
        
        return "Inconnu", "Inconnu"
    
    def _get_mac_vendor(self, mac: str) -> str:
        """Récupère le vendor à partir du MAC"""
        try:
            import requests
            response = requests.get(
                f"https://api.macvendors.com/{mac}",
                timeout=5
            )
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass
        
        return "Inconnu"
    
    def _scan_ports(self, host: str, scan_config: ScanConfig) -> Dict[str, Any]:
        """Scan des ports de l'hôte"""
        try:
            # Utiliser nmap si disponible
            cmd = [
                "nmap", "-sS", "-sV", "-O", "--open",
                "-p", scan_config.ports,
                "-T" + ("2" if scan_config.stealth_mode else "3"),
                "--host-timeout", f"{scan_config.timeout}s",
                host
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_config.timeout * 2
            )
            
            if result.returncode == 0:
                return self._parse_nmap_output(result.stdout)
            else:
                self.logger.warning(f"Nmap a échoué pour {host}: {result.stderr}")
                return {"open_ports": [], "services": {}}
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout du scan nmap pour {host}")
            return {"open_ports": [], "services": {}}
        except FileNotFoundError:
            self.logger.warning("Nmap non trouvé, utilisation de socket fallback")
            return self._socket_port_scan(host, scan_config)
        except Exception as e:
            self.logger.error(f"Erreur lors du scan de ports pour {host}: {e}")
            return {"open_ports": [], "services": {}}
    
    def _parse_nmap_output(self, nmap_output: str) -> Dict[str, Any]:
        """Parse la sortie de nmap"""
        open_ports = []
        services = {}
        
        for line in nmap_output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_service = parts[0]
                    state = parts[1]
                    service = ' '.join(parts[2:])
                    
                    if state == 'open':
                        port = int(port_service.split('/')[0])
                        open_ports.append(port)
                        services[port_service] = service
        
        return {"open_ports": open_ports, "services": services}
    
    def _socket_port_scan(self, host: str, scan_config: ScanConfig) -> Dict[str, Any]:
        """Scan de ports basique avec sockets"""
        open_ports = []
        services = {}
        
        # Ports courants à vérifier
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(scan_config.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    services[f"{port}/tcp"] = "open"
                    
            except:
                pass
        
        return {"open_ports": open_ports, "services": services}
    
    def _detect_os(self, host: str, open_ports: List[int]) -> str:
        """Détection basique de l'OS"""
        try:
            # Basé sur les ports ouverts
            if 3389 in open_ports:
                return "Windows (RDP)"
            elif 22 in open_ports and 445 not in open_ports:
                return "Linux/Unix (SSH)"
            elif 445 in open_ports:
                return "Windows (SMB)"
            elif 80 in open_ports or 443 in open_ports:
                return "Serveur Web"
            else:
                return "Inconnu"
        except:
            return "Inconnu"
    
    def _scan_vulnerabilities(self, host: str, open_ports: List[int]) -> List[Dict[str, Any]]:
        """Scan de vulnérabilités basique"""
        vulnerabilities = []
        
        try:
            # Vulnérabilités connues basées sur les ports
            if 445 in open_ports:
                vulnerabilities.append({
                    "port": 445,
                    "service": "SMB",
                    "cve": "CVE-2017-0144",
                    "name": "EternalBlue",
                    "severity": "Critical",
                    "description": "SMB Remote Code Execution Vulnerability"
                })
            
            if 3389 in open_ports:
                vulnerabilities.append({
                    "port": 3389,
                    "service": "RDP",
                    "cve": "CVE-2019-0708",
                    "name": "BlueKeep",
                    "severity": "Critical",
                    "description": "Remote Desktop Services Remote Code Execution"
                })
            
            # Utiliser nmap vuln scan si disponible
            try:
                cmd = [
                    "nmap", "--script", "vuln",
                    "-p", ",".join(map(str, open_ports)),
                    host
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    # Parser les résultats de vulnérabilités
                    vuln_info = self._parse_vuln_output(result.stdout)
                    vulnerabilities.extend(vuln_info)
                    
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"Erreur lors du scan de vulnérabilités pour {host}: {e}")
        
        return vulnerabilities
    
    def _parse_vuln_output(self, vuln_output: str) -> List[Dict[str, Any]]:
        """Parse la sortie du scan de vulnérabilités"""
        vulnerabilities = []
        
        for line in vuln_output.split('\n'):
            if 'VULNERABLE' in line or 'CVE-' in line:
                # Extraction basique des informations de vulnérabilité
                vulnerabilities.append({
                    "raw_output": line.strip(),
                    "severity": "Unknown",
                    "source": "nmap_vuln_scan"
                })
        
        return vulnerabilities
    
    def _post_process_results(self, results: List[ScanResult], scan_config: ScanConfig) -> List[ScanResult]:
        """Post-traitement des résultats du scan"""
        # Tri par IP
        results.sort(key=lambda x: ipaddress.ip_address(x.ip))
        
        # Mise à jour des statistiques
        self.stats['vulnerabilities_found'] = sum(len(r.vulnerabilities) for r in results)
        
        # Logging des statistiques
        self.logger.info(
            f"Scan terminé: {len(results)} hôtes, "
            f"{self.stats['hosts_online']} en ligne, "
            f"{self.stats['vulnerabilities_found']} vulnérabilités"
        )
        
        return results
    
    def _generate_scan_id(self) -> str:
        """Génère un ID unique pour le scan"""
        import uuid
        return str(uuid.uuid4())
    
    def get_scan_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du scan courant"""
        return self.stats.copy()
    
    def stop_scan(self):
        """Arrête le scan en cours"""
        with self.scan_lock:
            if self.is_scanning:
                self.is_scanning = False
                if self.executor:
                    self.executor.shutdown(wait=False)
                self.logger.info("Scan arrêté par l'utilisateur")
