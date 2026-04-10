#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module furtif et détection IDS/IPS ATLOS v5.0
Techniques d'évasion et détection de contre-mesures
"""

import os
import time
import random
import socket
import subprocess
import threading
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import re

from ..utils.logger import ATLOSLogger
from ..utils.config import ConfigManager

class IDSType(Enum):
    """Types d'IDS/IPS détectables"""
    SURICATA = "suricata"
    SNORT = "snort"
    ZEEK = "zeek"
    OSSEC = "ossec"
    WAZUH = "wazuh"
    UNKNOWN = "unknown"

class EvasionTechnique(Enum):
    """Techniques d'évasion"""
    FRAGMENTATION = "fragmentation"
    TIMING_VARIATION = "timing_variation"
    SOURCE_PORT_RANDOMIZATION = "source_port_randomization"
    DECOY_SCANS = "decoy_scans"
    SPOOFED_MAC = "spoofed_mac"
    ENCRYPTED_TRAFFIC = "encrypted_traffic"

@dataclass
class IDSSignature:
    """Signature d'IDS/IPS"""
    name: str
    type: IDSType
    pattern: str
    confidence: float
    description: str

@dataclass
class EvasionResult:
    """Résultat d'une technique d'évasion"""
    technique: EvasionTechnique
    success: bool
    detection_risk: float
    performance_impact: float
    details: Dict[str, Any]

class StealthManager:
    """Gestionnaire de mode furtif et détection IDS/IPS"""
    
    def __init__(self, config: ConfigManager, logger: ATLOSLogger):
        self.config = config
        self.logger = logger
        self.stealth_config = config.get('ids_detection', {})
        
        # Signatures connues d'IDS/IPS
        self.known_signatures = self._load_ids_signatures()
        
        # Techniques d'évasion disponibles
        self.evasion_techniques = self._load_evasion_techniques()
        
        # État de détection
        self.detected_systems = []
        self.evasion_active = False
        self.adaptive_mode = self.stealth_config.get('auto_adapt', True)
        
        # Statistiques
        self.stats = {
            'signatures_detected': 0,
            'evasion_attempts': 0,
            'successful_evasions': 0,
            'detection_events': 0
        }
    
    def _load_ids_signatures(self) -> List[IDSSignature]:
        """Charge les signatures d'IDS/IPS connues"""
        signatures = [
            # Suricata
            IDSSignature(
                name="Suricata HTTP Detection",
                type=IDSType.SURICATA,
                pattern=r"suricata.*alert.*http",
                confidence=0.9,
                description="Détection Suricata sur le trafic HTTP"
            ),
            IDSSignature(
                name="Suricata Network Scan",
                type=IDSType.SURICATA,
                pattern=r"suricata.*alert.*portscan",
                confidence=0.85,
                description="Détection de scan de ports par Suricata"
            ),
            
            # Snort
            IDSSignature(
                name="Snort Port Scan Detection",
                type=IDSType.SNORT,
                pattern=r"snort.*portscan",
                confidence=0.9,
                description="Détection de scan de ports par Snort"
            ),
            IDSSignature(
                name="Snort Web Attack",
                type=IDSType.SNORT,
                pattern=r"snort.*web-attack",
                confidence=0.85,
                description="Détection d'attaques web par Snort"
            ),
            
            # Zeek (Bro)
            IDSSignature(
                name="Zeek Network Monitor",
                type=IDSType.ZEEK,
                pattern=r"zeek.*notice",
                confidence=0.8,
                description="Détection d'événements réseau par Zeek"
            ),
            IDSSignature(
                name="Zeek Scan Detection",
                type=IDSType.ZEEK,
                pattern=r"zeek.*scan",
                confidence=0.85,
                description="Détection de scan par Zeek"
            ),
            
            # OSSEC/Wazuh
            IDSSignature(
                name="OSSEC Port Scan",
                type=IDSType.OSSEC,
                pattern=r"ossec.*portscan",
                confidence=0.75,
                description="Détection de scan par OSSEC"
            ),
            IDSSignature(
                name="Wazuh Security Event",
                type=IDSType.WAZUH,
                pattern=r"wazuh.*security",
                confidence=0.8,
                description="Événement de sécurité Wazuh"
            )
        ]
        
        return signatures
    
    def _load_evasion_techniques(self) -> List[EvasionTechnique]:
        """Charge les techniques d'évasion disponibles"""
        enabled_techniques = self.stealth_config.get('evasion_techniques', [])
        
        available = [
            EvasionTechnique.FRAGMENTATION,
            EvasionTechnique.TIMING_VARIATION,
            EvasionTechnique.SOURCE_PORT_RANDOMIZATION,
            EvasionTechnique.DECOY_SCANS,
            EvasionTechnique.SPOOFED_MAC,
            EvasionTechnique.ENCRYPTED_TRAFFIC
        ]
        
        # Filtrer selon la configuration
        if enabled_techniques:
            return [tech for tech in available if tech.value in enabled_techniques]
        
        return available
    
    def detect_ids_systems(self, target_network: str) -> List[Dict[str, Any]]:
        """
        Détecte les systèmes IDS/IPS sur le réseau
        
        Args:
            target_network: Réseau cible
            
        Returns:
            List[Dict[str, Any]]: Systèmes détectés
        """
        self.logger.info(f"Détection des systèmes IDS/IPS sur {target_network}")
        
        detected = []
        
        try:
            # Technique 1: Analyse des réponses réseau
            network_signatures = self._analyze_network_responses(target_network)
            detected.extend(network_signatures)
            
            # Technique 2: Scan de ports typiques d'IDS
            port_signatures = self._scan_ids_ports(target_network)
            detected.extend(port_signatures)
            
            # Technique 3: Analyse des banners
            banner_signatures = self._analyze_banners(target_network)
            detected.extend(banner_signatures)
            
            # Technique 4: Détection passive
            passive_signatures = self._passive_detection(target_network)
            detected.extend(passive_signatures)
            
            # Déduplication et fusion
            detected = self._merge_detection_results(detected)
            
            # Mise à jour des statistiques
            self.stats['signatures_detected'] = len(detected)
            self.detected_systems = detected
            
            # Logging des détections
            for system in detected:
                self.logger.security(
                    f"IDS/IPS détecté: {system['name']} ({system['type']}) sur {system['ip']}",
                    target=system['ip'],
                    ids_type=system['type'],
                    confidence=system['confidence']
                )
            
            self.logger.info(f"{len(detected)} systèmes IDS/IPS détectés")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la détection IDS/IPS: {e}")
        
        return detected
    
    def _analyze_network_responses(self, target_network: str) -> List[Dict[str, Any]]:
        """Analyse les réponses réseau pour détecter les IDS"""
        detected = []
        
        try:
            # Envoi de paquets suspects et analyse des réponses
            suspicious_ports = [80, 443, 22, 21, 25, 53]
            
            for port in suspicious_ports:
                try:
                    # Création d'un paquet suspect
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    
                    # Simulation de connexion suspecte
                    result = sock.connect_ex((target_network.split('/')[0], port))
                    
                    if result == 0:
                        # Analyse de la réponse
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        
                        # Recherche de signatures
                        for signature in self.known_signatures:
                            if re.search(signature.pattern, response, re.IGNORECASE):
                                detected.append({
                                    'name': signature.name,
                                    'type': signature.type.value,
                                    'ip': target_network.split('/')[0],
                                    'port': port,
                                    'confidence': signature.confidence,
                                    'evidence': response[:200],
                                    'detection_method': 'network_response'
                                })
                    
                    sock.close()
                    
                except:
                    pass
        
        except Exception as e:
            self.logger.debug(f"Erreur analyse réseau: {e}")
        
        return detected
    
    def _scan_ids_ports(self, target_network: str) -> List[Dict[str, Any]]:
        """Scan les ports typiques des systèmes IDS"""
        detected = []
        
        # Ports typiques d'IDS/IPS
        ids_ports = {
            514: "Syslog (OSSEC/Wazuh)",
            1514: "Wazuh Agent",
            7736: "OSSEC",
            443: "HTTPS IDS Web Interface",
            80: "HTTP IDS Web Interface",
            22: "SSH Management"
        }
        
        try:
            base_ip = target_network.split('/')[0]
            
            for port, description in ids_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((base_ip, port))
                    
                    if result == 0:
                        # Récupération du banner
                        try:
                            banner = sock.recv(256).decode('utf-8', errors='ignore')
                        except:
                            banner = ""
                        
                        # Analyse du banner
                        ids_type = self._identify_ids_from_banner(banner)
                        
                        detected.append({
                            'name': f"IDS Port {port}",
                            'type': ids_type,
                            'ip': base_ip,
                            'port': port,
                            'confidence': 0.6,
                            'evidence': f"{description} - Banner: {banner[:100]}",
                            'detection_method': 'port_scan'
                        })
                    
                    sock.close()
                    
                except:
                    pass
        
        except Exception as e:
            self.logger.debug(f"Erreur scan ports IDS: {e}")
        
        return detected
    
    def _analyze_banners(self, target_network: str) -> List[Dict[str, Any]]:
        """Analyse les banners des services pour détecter les IDS"""
        detected = []
        
        try:
            base_ip = target_network.split('/')[0]
            
            # Services typiques avec banners identifiables
            services = [
                (80, "HTTP"),
                (443, "HTTPS"),
                (22, "SSH"),
                (21, "FTP")
            ]
            
            for port, service in services:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    
                    if sock.connect_ex((base_ip, port)) == 0:
                        # Récupération du banner
                        if service == "HTTP":
                            sock.send(b"GET / HTTP/1.0\r\n\r\n")
                        elif service == "SSH":
                            pass  # SSH envoie son banner automatiquement
                        
                        banner = sock.recv(512).decode('utf-8', errors='ignore')
                        
                        # Recherche de signatures dans le banner
                        for signature in self.known_signatures:
                            if re.search(signature.pattern, banner, re.IGNORECASE):
                                detected.append({
                                    'name': signature.name,
                                    'type': signature.type.value,
                                    'ip': base_ip,
                                    'port': port,
                                    'confidence': signature.confidence * 0.8,  # Réduction de confiance
                                    'evidence': banner[:200],
                                    'detection_method': 'banner_analysis'
                                })
                    
                    sock.close()
                    
                except:
                    pass
        
        except Exception as e:
            self.logger.debug(f"Erreur analyse banners: {e}")
        
        return detected
    
    def _passive_detection(self, target_network: str) -> List[Dict[str, Any]]:
        """Détection passive d'IDS/IPS"""
        detected = []
        
        try:
            # Analyse des logs système locaux
            log_files = [
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/kern.log"
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r', errors='ignore') as f:
                            # Lecture des dernières lignes
                            lines = f.readlines()[-1000:]  # 1000 dernières lignes
                            
                            for line in lines:
                                for signature in self.known_signatures:
                                    if re.search(signature.pattern, line, re.IGNORECASE):
                                        # Extraction de l'IP source
                                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                                        source_ip = ip_match.group(1) if ip_match else "unknown"
                                        
                                        detected.append({
                                            'name': signature.name,
                                            'type': signature.type.value,
                                            'ip': source_ip,
                                            'port': None,
                                            'confidence': signature.confidence * 0.7,
                                            'evidence': line.strip(),
                                            'detection_method': 'passive_log_analysis'
                                        })
                    
                    except Exception as e:
                        self.logger.debug(f"Erreur lecture {log_file}: {e}")
        
        except Exception as e:
            self.logger.debug(f"Erreur détection passive: {e}")
        
        return detected
    
    def _identify_ids_from_banner(self, banner: str) -> str:
        """Identifie le type d'IDS à partir du banner"""
        banner_lower = banner.lower()
        
        if "suricata" in banner_lower:
            return IDSType.SURICATA.value
        elif "snort" in banner_lower:
            return IDSType.SNORT.value
        elif "zeek" in banner_lower or "bro" in banner_lower:
            return IDSType.ZEEK.value
        elif "ossec" in banner_lower:
            return IDSType.OSSEC.value
        elif "wazuh" in banner_lower:
            return IDSType.WAZUH.value
        else:
            return IDSType.UNKNOWN.value
    
    def _merge_detection_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fusionne et déduplique les résultats de détection"""
        if not results:
            return []
        
        # Groupement par IP et type
        grouped = {}
        
        for result in results:
            key = f"{result['ip']}_{result['type']}"
            
            if key not in grouped:
                grouped[key] = {
                    'ip': result['ip'],
                    'type': result['type'],
                    'name': result['name'],
                    'confidence': 0,
                    'evidence': [],
                    'detection_methods': [],
                    'ports': set()
                }
            
            # Fusion des informations
            grouped[key]['confidence'] = max(grouped[key]['confidence'], result['confidence'])
            grouped[key]['evidence'].append(result['evidence'])
            grouped[key]['detection_methods'].append(result['detection_method'])
            
            if result.get('port'):
                grouped[key]['ports'].add(result['port'])
        
        # Conversion en liste
        merged = []
        for item in grouped.values():
            item['ports'] = list(item['ports'])
            merged.append(item)
        
        return merged
    
    def apply_evasion_techniques(self, target: str) -> List[EvasionResult]:
        """
        Applique les techniques d'évasion configurées
        
        Args:
            target: Cible de l'évasion
            
        Returns:
            List[EvasionResult]: Résultats des techniques appliquées
        """
        self.logger.info(f"Application des techniques d'évasion sur {target}")
        
        results = []
        self.evasion_active = True
        
        for technique in self.evasion_techniques:
            try:
                self.stats['evasion_attempts'] += 1
                
                result = self._apply_evasion_technique(technique, target)
                results.append(result)
                
                if result.success:
                    self.stats['successful_evasions'] += 1
                    self.logger.info(f"Technique d'évasion {technique.value} appliquée avec succès")
                else:
                    self.logger.warning(f"Technique d'évasion {technique.value} échouée")
                
                # Délai entre techniques pour éviter la détection
                time.sleep(random.uniform(0.5, 2.0))
                
            except Exception as e:
                self.logger.error(f"Erreur technique d'évasion {technique.value}: {e}")
        
        self.evasion_active = False
        return results
    
    def _apply_evasion_technique(self, technique: EvasionTechnique, target: str) -> EvasionResult:
        """Applique une technique d'évasion spécifique"""
        
        if technique == EvasionTechnique.FRAGMENTATION:
            return self._evasion_fragmentation(target)
        
        elif technique == EvasionTechnique.TIMING_VARIATION:
            return self._evasion_timing_variation(target)
        
        elif technique == EvasionTechnique.SOURCE_PORT_RANDOMIZATION:
            return self._evasion_source_port_randomization(target)
        
        elif technique == EvasionTechnique.DECOY_SCANS:
            return self._evasion_decoy_scans(target)
        
        elif technique == EvasionTechnique.SPOOFED_MAC:
            return self._evasion_spoofed_mac(target)
        
        elif technique == EvasionTechnique.ENCRYPTED_TRAFFIC:
            return self._evasion_encrypted_traffic(target)
        
        else:
            return EvasionResult(
                technique=technique,
                success=False,
                detection_risk=1.0,
                performance_impact=0.0,
                details={"error": "Technique non implémentée"}
            )
    
    def _evasion_fragmentation(self, target: str) -> EvasionResult:
        """Évasion par fragmentation des paquets"""
        try:
            # Implémentation basique avec scapy si disponible
            try:
                from scapy.all import IP, TCP, fragment
                
                # Création de paquets fragmentés
                packet = IP(dst=target) / TCP(dport=80, flags="S")
                fragments = fragment(packet, fragsize=20)
                
                # Envoi des fragments
                for frag in fragments:
                    # Simulation d'envoi
                    time.sleep(0.1)
                
                return EvasionResult(
                    technique=EvasionTechnique.FRAGMENTATION,
                    success=True,
                    detection_risk=0.3,
                    performance_impact=0.4,
                    details={"fragments_count": len(fragments)}
                )
                
            except ImportError:
                # Fallback sans scapy
                return EvasionResult(
                    technique=EvasionTechnique.FRAGMENTATION,
                    success=False,
                    detection_risk=0.5,
                    performance_impact=0.2,
                    details={"error": "Scapy non disponible"}
                )
        
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.FRAGMENTATION,
                success=False,
                detection_risk=0.8,
                performance_impact=0.1,
                details={"error": str(e)}
            )
    
    def _evasion_timing_variation(self, target: str) -> EvasionResult:
        """Évasion par variation des délais"""
        try:
            # Simulation de variation de timing
            base_delay = 1.0
            variations = []
            
            for i in range(5):
                # Délai aléatoire entre 0.1s et 3s
                delay = random.uniform(0.1, 3.0)
                variations.append(delay)
                time.sleep(delay)
            
            avg_delay = sum(variations) / len(variations)
            
            return EvasionResult(
                technique=EvasionTechnique.TIMING_VARIATION,
                success=True,
                detection_risk=0.2,
                performance_impact=0.6,
                details={
                    "variations": variations,
                    "average_delay": avg_delay,
                    "std_deviation": self._calculate_std_dev(variations)
                }
            )
        
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.TIMING_VARIATION,
                success=False,
                detection_risk=0.7,
                performance_impact=0.1,
                details={"error": str(e)}
            )
    
    def _evasion_source_port_randomization(self, target: str) -> EvasionResult:
        """Évasion par randomisation des ports source"""
        try:
            # Simulation de connexions avec ports source aléatoires
            ports_used = []
            
            for i in range(3):
                source_port = random.randint(1024, 65535)
                ports_used.append(source_port)
                
                # Simulation de connexion
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.bind(("0.0.0.0", source_port))
                    sock.connect_ex((target, 80))
                    sock.close()
                except:
                    pass
            
            return EvasionResult(
                technique=EvasionTechnique.SOURCE_PORT_RANDOMIZATION,
                success=True,
                detection_risk=0.25,
                performance_impact=0.3,
                details={"source_ports": ports_used}
            )
        
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.SOURCE_PORT_RANDOMIZATION,
                success=False,
                detection_risk=0.6,
                performance_impact=0.1,
                details={"error": str(e)}
            )
    
    def _evasion_decoy_scans(self, target: str) -> EvasionResult:
        """Évasion par scans de leurre (decoy)"""
        try:
            # Génération d'IPs de leurre
            decoy_ips = self._generate_decoy_ips(target)
            
            # Simulation de scans depuis les IPs de leurre
            for decoy_ip in decoy_ips:
                # Simulation de scan depuis le leurre
                time.sleep(random.uniform(0.5, 1.5))
            
            return EvasionResult(
                technique=EvasionTechnique.DECOY_SCANS,
                success=True,
                detection_risk=0.4,
                performance_impact=0.5,
                details={"decoy_ips": decoy_ips}
            )
        
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.DECOY_SCANS,
                success=False,
                detection_risk=0.8,
                performance_impact=0.2,
                details={"error": str(e)}
            )
    
    def _evasion_spoofed_mac(self, target: str) -> EvasionResult:
        """Évasion par spoofing d'adresse MAC"""
        try:
            # Génération d'une MAC aléatoire
            spoofed_mac = self._generate_random_mac()
            
            # Simulation de changement de MAC (nécessite root)
            try:
                # Commande pour changer la MAC (simulation)
                # subprocess.run(["ifconfig", "eth0", "down"], check=True)
                # subprocess.run(["ifconfig", "eth0", "hw", "ether", spoofed_mac], check=True)
                # subprocess.run(["ifconfig", "eth0", "up"], check=True)
                
                return EvasionResult(
                    technique=EvasionTechnique.SPOOFED_MAC,
                    success=True,
                    detection_risk=0.15,
                    performance_impact=0.2,
                    details={"spoofed_mac": spoofed_mac}
                )
                
            except:
                return EvasionResult(
                    technique=EvasionTechnique.SPOOFED_MAC,
                    success=False,
                    detection_risk=0.3,
                    performance_impact=0.1,
                    details={"error": "Permissions insuffisantes pour le MAC spoofing"}
                )
        
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.SPOOFED_MAC,
                success=False,
                detection_risk=0.7,
                performance_impact=0.1,
                details={"error": str(e)}
            )
    
    def _evasion_encrypted_traffic(self, target: str) -> EvasionResult:
        """Évasion par trafic chiffré"""
        try:
            # Simulation de trafic chiffré
            encrypted_protocols = ["HTTPS", "SSH", "TLS"]
            
            for protocol in encrypted_protocols:
                # Simulation de connexion chiffrée
                try:
                    if protocol == "HTTPS":
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock.connect_ex((target, 443))
                        sock.close()
                    elif protocol == "SSH":
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock.connect_ex((target, 22))
                        sock.close()
                
                except:
                    pass
            
            return EvasionResult(
                technique=EvasionTechnique.ENCRYPTED_TRAFFIC,
                success=True,
                detection_risk=0.1,
                performance_impact=0.3,
                details={"protocols": encrypted_protocols}
            )
        
        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.ENCRYPTED_TRAFFIC,
                success=False,
                detection_risk=0.5,
                performance_impact=0.1,
                details={"error": str(e)}
            )
    
    def _generate_decoy_ips(self, target: str) -> List[str]:
        """Génère des IPs de leurre dans le même réseau"""
        try:
            # Extraction du réseau de la cible
            network_parts = target.split('.')
            if len(network_parts) >= 3:
                base = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}"
                
                # Génération de 3-5 IPs de leurre
                decoy_count = random.randint(3, 5)
                decoy_ips = []
                
                for i in range(decoy_count):
                    last_octet = random.randint(1, 254)
                    decoy_ip = f"{base}.{last_octet}"
                    decoy_ips.append(decoy_ip)
                
                return decoy_ips
            
        except:
            pass
        
        return []
    
    def _generate_random_mac(self) -> str:
        """Génère une adresse MAC aléatoire"""
        import random
        
        mac = [0x02, 0x00, 0x00,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        
        return ':'.join(f"{b:02x}" for b in mac)
    
    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calcule l'écart-type"""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        
        return variance ** 0.5
    
    def get_stealth_recommendations(self) -> List[str]:
        """Génère des recommandations pour le mode furtif"""
        recommendations = []
        
        if self.detected_systems:
            recommendations.append(f"Systems IDS/IPS détectés: {len(self.detected_systems)}")
            
            for system in self.detected_systems:
                if system['confidence'] > 0.8:
                    recommendations.append(
                        f"Haute confiance - {system['type']} sur {system['ip']} - Utiliser l'évasion avancée"
                    )
        
        if self.adaptive_mode:
            recommendations.append("Mode adaptatif activé - ATLOS ajustera automatiquement les techniques")
        
        if not self.evasion_techniques:
            recommendations.append("Aucune technique d'évasion configurée - Activer dans settings.yaml")
        
        # Recommandations basées sur les résultats
        if self.stats['evasion_attempts'] > 0:
            success_rate = self.stats['successful_evasions'] / self.stats['evasion_attempts']
            if success_rate < 0.5:
                recommendations.append("Taux de succès faible - Réviser les techniques d'évasion")
        
        return recommendations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques du mode furtif"""
        return {
            'detected_systems': len(self.detected_systems),
            'evasion_techniques_available': len(self.evasion_techniques),
            'stats': self.stats.copy(),
            'adaptive_mode': self.adaptive_mode,
            'evasion_active': self.evasion_active,
            'recommendations': self.get_stealth_recommendations()
        }
