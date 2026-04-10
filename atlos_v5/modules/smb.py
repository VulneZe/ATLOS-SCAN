#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'énumération SMB ATLOS v5.0
Énumération avancée des partages SMB, vulnérabilités et exploitation
"""

import os
import subprocess
import socket
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging
import re

from ..utils.logger import ATLOSLogger
from ..utils.config import ConfigManager
from ..utils.crypto import CredentialManager

@dataclass
class SMBShare:
    """Représentation d'un partage SMB"""
    name: str
    type: str
    comment: str
    permissions: str = "Unknown"
    size: int = 0
    accessible: bool = False
    anonymous_access: bool = False
    files: List[str] = None

@dataclass
class SMBVulnerability:
    """Vulnérabilité SMB détectée"""
    cve: str
    name: str
    severity: str
    description: str
    exploit_available: bool = False
    metasploit_module: Optional[str] = None

class SMBEnumerator:
    """Énumérateur SMB avancé"""
    
    def __init__(self, config: ConfigManager, logger: ATLOSLogger):
        self.config = config
        self.logger = logger
        self.smb_config = config.get_module_config('smb')
        self.credential_manager = CredentialManager()
        
        # Configuration
        self.timeout = self.smb_config.get('timeout', 10)
        self.max_shares = self.smb_config.get('max_shares', 10)
        self.anonymous_only = self.smb_config.get('anonymous_only', True)
        
        # Vulnérabilités SMB connues
        self.known_vulnerabilities = {
            "EternalBlue": {
                "cve": "CVE-2017-0144",
                "severity": "Critical",
                "description": "SMBv1 Remote Code Execution Vulnerability",
                "metasploit": "exploit/windows/smb/ms17_010_eternalblue"
            },
            "BlueKeep": {
                "cve": "CVE-2019-0708", 
                "severity": "Critical",
                "description": "Remote Desktop Services RCE",
                "metasploit": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
            },
            "SMBGhost": {
                "cve": "CVE-2020-0796",
                "severity": "Critical", 
                "description": "SMBv3 Compression Remote Code Execution",
                "metasploit": "exploit/windows/smb/cve_2020_0796_smbghost"
            },
            "ZeroLogon": {
                "cve": "CVE-2020-1472",
                "severity": "Critical",
                "description": "Netlogon Elevation of Privilege",
                "metasploit": "exploit/windows/dcerpc/cve_2020_1472_zero_logon"
            }
        }
    
    def enumerate_smb(self, target_ip: str, credentials: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Énumération complète SMB d'une cible
        
        Args:
            target_ip: IP de la cible
            credentials: Credentials optionnels (username, password, domain)
            
        Returns:
            Dict[str, Any]: Résultats de l'énumération SMB
        """
        self.logger.info(f"Début de l'énumération SMB sur {target_ip}")
        
        results = {
            'target': target_ip,
            'smb_version': None,
            'shares': [],
            'vulnerabilities': [],
            'anonymous_access': False,
            'null_session': False,
            'domain_info': {},
            'users': [],
            'groups': [],
            'policies': {},
            'recommendations': []
        }
        
        try:
            # Vérification si le port SMB est ouvert
            if not self._is_smb_open(target_ip):
                self.logger.info(f"Port SMB fermé sur {target_ip}")
                return results
            
            # Détection de la version SMB
            results['smb_version'] = self._detect_smb_version(target_ip)
            
            # Test de session null
            results['null_session'] = self._test_null_session(target_ip)
            
            # Énumération des partages
            results['shares'] = self._enumerate_shares(target_ip, credentials)
            
            # Vérification de l'accès anonyme
            results['anonymous_access'] = any(
                share.anonymous_access for share in results['shares']
            )
            
            # Scan de vulnérabilités
            results['vulnerabilities'] = self._scan_smb_vulnerabilities(
                target_ip, results['smb_version']
            )
            
            # Énumération avancée si accès
            if results['null_session'] or credentials:
                results.update(self._advanced_enumeration(target_ip, credentials))
            
            # Génération des recommandations
            results['recommendations'] = self._generate_recommendations(results)
            
            # Logging des découvertes importantes
            self._log_findings(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'énumération SMB sur {target_ip}: {e}")
            results['error'] = str(e)
            return results
    
    def _is_smb_open(self, target_ip: str) -> bool:
        """Vérifie si le port SMB (445) est ouvert"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target_ip, 445))
            sock.close()
            return result == 0
        except:
            return False
    
    def _detect_smb_version(self, target_ip: str) -> Optional[str]:
        """Détecte la version du protocole SMB"""
        try:
            # Utiliser nmap pour détecter la version SMB
            cmd = [
                "nmap", "-sV", "-p", "445,139",
                "--script", "smb-protocols",
                "-Pn", target_ip
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parser la version SMB
                if "SMBv1" in output:
                    return "SMBv1 (Vulnérable)"
                elif "SMBv2" in output:
                    return "SMBv2"
                elif "SMBv3" in output:
                    return "SMBv3"
                else:
                    return "Unknown"
            
        except Exception as e:
            self.logger.debug(f"Impossible de détecter la version SMB: {e}")
        
        return None
    
    def _test_null_session(self, target_ip: str) -> bool:
        """Test si une session null est possible"""
        try:
            # Utiliser smbclient pour tester une session null
            cmd = ["smbclient", "-L", target_ip, "-N", "--quiet"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Vérifier si on a obtenu une liste de partages
            if result.returncode == 0 and "Sharename" in result.stdout:
                return True
            
            # Alternative avec rpcclient
            cmd = ["rpcclient", target_ip, "-U", "%", "-c", "srvinfo"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Test de session null échoué: {e}")
        
        return False
    
    def _enumerate_shares(self, target_ip: str, credentials: Optional[Dict[str, str]]) -> List[SMBShare]:
        """Énumère les partages SMB"""
        shares = []
        
        try:
            # Construction de la commande smbclient
            cmd = ["smbclient", "-L", target_ip, "--quiet"]
            
            if credentials:
                # Ajout des credentials
                username = credentials.get('username', '')
                password = credentials.get('password', '')
                domain = credentials.get('domain', '')
                
                if domain:
                    cmd.extend(["-U", f"{domain}\\{username}%{password}"])
                else:
                    cmd.extend(["-U", f"{username}%{password}"])
            else:
                # Session anonyme
                cmd.append("-N")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                shares = self._parse_smbclient_output(result.stdout, target_ip, credentials)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'énumération des partages: {e}")
        
        return shares[:self.max_shares]  # Limiter le nombre de partages
    
    def _parse_smbclient_output(self, output: str, target_ip: str, credentials: Optional[Dict[str, str]]) -> List[SMBShare]:
        """Parse la sortie de smbclient pour extraire les partages"""
        shares = []
        
        try:
            lines = output.split('\n')
            parsing = False
            
            for line in lines:
                line = line.strip()
                
                if "Sharename" in line and "Type" in line:
                    parsing = True
                    continue
                
                if parsing and line.startswith("---"):
                    continue
                
                if parsing and line:
                    # Format: Sharename  Type  Comment
                    parts = line.split(None, 2)
                    
                    if len(parts) >= 2 and not line.startswith("$"):
                        share_name = parts[0]
                        share_type = parts[1]
                        comment = parts[2] if len(parts) > 2 else ""
                        
                        # Ignorer les partages système
                        if share_name.startswith('$'):
                            continue
                        
                        # Créer l'objet partage
                        share = SMBShare(
                            name=share_name,
                            type=share_type,
                            comment=comment
                        )
                        
                        # Tester l'accès
                        share.accessible = self._test_share_access(target_ip, share_name, credentials)
                        share.anonymous_access = share.accessible and credentials is None
                        
                        # Lister les fichiers si accessible
                        if share.accessible and not share.anonymous_access:
                            share.files = self._list_share_files(target_ip, share_name, credentials)
                        
                        shares.append(share)
        
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing de la sortie smbclient: {e}")
        
        return shares
    
    def _test_share_access(self, target_ip: str, share_name: str, credentials: Optional[Dict[str, str]]) -> bool:
        """Test si un partage est accessible"""
        try:
            cmd = ["smbclient", f"//{target_ip}/{share_name}", "--quiet"]
            
            if credentials:
                username = credentials.get('username', '')
                password = credentials.get('password', '')
                domain = credentials.get('domain', '')
                
                if domain:
                    cmd.extend(["-U", f"{domain}\\{username}%{password}"])
                else:
                    cmd.extend(["-U", f"{username}%{password}"])
            else:
                cmd.append("-N")
            
            # Tenter de lister le contenu
            result = subprocess.run(
                cmd,
                input="ls\nquit",
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            return result.returncode == 0
            
        except:
            return False
    
    def _list_share_files(self, target_ip: str, share_name: str, credentials: Optional[Dict[str, str]]) -> List[str]:
        """Liste les fichiers dans un partage (limité)"""
        files = []
        
        try:
            cmd = ["smbclient", f"//{target_ip}/{share_name}", "--quiet"]
            
            if credentials:
                username = credentials.get('username', '')
                password = credentials.get('password', '')
                domain = credentials.get('domain', '')
                
                if domain:
                    cmd.extend(["-U", f"{domain}\\{username}%{password}"])
                else:
                    cmd.extend(["-U", f"{username}%{password}"])
            
            result = subprocess.run(
                cmd,
                input="ls\nquit",
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                # Parser la liste de fichiers
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('  ') and '.' in line:
                        files.append(line.strip())
                
                # Limiter le nombre de fichiers retournés
                files = files[:20]
        
        except Exception as e:
            self.logger.debug(f"Erreur lors du listage des fichiers: {e}")
        
        return files
    
    def _scan_smb_vulnerabilities(self, target_ip: str, smb_version: Optional[str]) -> List[SMBVulnerability]:
        """Scan des vulnérabilités SMB connues"""
        vulnerabilities = []
        
        try:
            # Vulnérabilités basées sur la version
            if smb_version and "SMBv1" in smb_version:
                vuln = self.known_vulnerabilities.get("EternalBlue")
                if vuln:
                    vulnerabilities.append(SMBVulnerability(
                        cve=vuln['cve'],
                        name=vuln['name'],
                        severity=vuln['severity'],
                        description=vuln['description'],
                        exploit_available=True,
                        metasploit_module=vuln['metasploit']
                    ))
            
            # Scan avec nmap pour détecter d'autres vulnérabilités
            cmd = [
                "nmap", "--script", "smb-vuln-*",
                "-p", "445", "-Pn", target_ip
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2
            )
            
            if result.returncode == 0:
                vuln_info = self._parse_nmap_vuln_output(result.stdout)
                vulnerabilities.extend(vuln_info)
        
        except Exception as e:
            self.logger.debug(f"Erreur lors du scan de vulnérabilités: {e}")
        
        return vulnerabilities
    
    def _parse_nmap_vuln_output(self, output: str) -> List[SMBVulnerability]:
        """Parse la sortie de nmap pour les vulnérabilités"""
        vulnerabilities = []
        
        for line in output.split('\n'):
            if 'VULNERABLE' in line or 'CVE-' in line:
                # Extraction basique
                if 'CVE-' in line:
                    cve_match = re.search(r'CVE-\d{4}-\d{4,}', line)
                    if cve_match:
                        cve = cve_match.group()
                        vulnerabilities.append(SMBVulnerability(
                            cve=cve,
                            name="SMB Vulnerability",
                            severity="Unknown",
                            description=line.strip(),
                            exploit_available=False
                        ))
        
        return vulnerabilities
    
    def _advanced_enumeration(self, target_ip: str, credentials: Optional[Dict[str, str]]) -> Dict[str, Any]:
        """Énumération avancée avec accès"""
        advanced_results = {
            'domain_info': {},
            'users': [],
            'groups': [],
            'policies': {}
        }
        
        if not credentials and not self._test_null_session(target_ip):
            return advanced_results
        
        try:
            # Utiliser rpcclient pour l'énumération avancée
            cmd = ["rpcclient", target_ip, "-U", "%", "-c"]
            
            if credentials:
                username = credentials.get('username', '')
                password = credentials.get('password', '')
                domain = credentials.get('domain', '')
                
                if domain:
                    cmd = ["rpcclient", target_ip, "-U", f"{domain}\\{username}%{password}", "-c"]
                else:
                    cmd = ["rpcclient", target_ip, "-U", f"{username}%{password}", "-c"]
            
            # Informations sur le domaine
            commands = {
                'domain_info': 'srvinfo',
                'users': 'enumdomusers',
                'groups': 'enumdomgroups'
            }
            
            for key, rpc_cmd in commands.items():
                try:
                    full_cmd = cmd + [rpc_cmd]
                    result = subprocess.run(
                        full_cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout
                    )
                    
                    if result.returncode == 0:
                        advanced_results[key] = self._parse_rpc_output(result.stdout, key)
                
                except Exception as e:
                    self.logger.debug(f"Erreur RPC {rpc_cmd}: {e}")
        
        except Exception as e:
            self.logger.debug(f"Erreur lors de l'énumération avancée: {e}")
        
        return advanced_results
    
    def _parse_rpc_output(self, output: str, output_type: str) -> Any:
        """Parse la sortie de rpcclient"""
        if output_type == 'domain_info':
            return {'raw_output': output}
        elif output_type == 'users':
            users = []
            for line in output.split('\n'):
                if '[User:' in line:
                    user_match = re.search(r'\[User:(.*?)\]', line)
                    if user_match:
                        users.append(user_match.group(1))
            return users[:50]  # Limiter à 50 utilisateurs
        elif output_type == 'groups':
            groups = []
            for line in output.split('\n'):
                if '[Group:' in line:
                    group_match = re.search(r'\[Group:(.*?)\]', line)
                    if group_match:
                        groups.append(group_match.group(1))
            return groups[:50]  # Limiter à 50 groupes
        
        return output
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Génère des recommandations de sécurité"""
        recommendations = []
        
        # Recommandations basées sur les découvertes
        if results['anonymous_access']:
            recommendations.append(
                "🔴 Désactiver l'accès anonyme aux partages SMB"
            )
        
        if results['null_session']:
            recommendations.append(
                "🔴 Désactiver les sessions null via les restrictions de l'annuaire"
            )
        
        if results['smb_version'] and 'SMBv1' in results['smb_version']:
            recommendations.append(
                "🔴 Désactiver SMBv1 (vulnérable à EternalBlue)"
            )
        
        # Vulnérabilités critiques
        critical_vulns = [v for v in results['vulnerabilities'] if v.severity == 'Critical']
        if critical_vulns:
            recommendations.append(
                f"🔴 {len(critical_vulns)} vulnérabilité(s) critique(s) détectée(s) - Appliquer les patches immédiatement"
            )
        
        # Partages sensibles
        sensitive_shares = ['ADMIN$', 'C$', 'IPC$']
        found_sensitive = [s for s in results['shares'] if s.name in sensitive_shares and s.accessible]
        if found_sensitive:
            recommendations.append(
                "🔴 Restreindre l'accès aux partages administratifs (ADMIN$, C$)"
            )
        
        return recommendations
    
    def _log_findings(self, results: Dict[str, Any]):
        """Log les découvertes importantes"""
        target = results['target']
        
        # Vulnérabilités critiques
        for vuln in results['vulnerabilities']:
            if vuln.severity == 'Critical':
                self.logger.vulnerability_found(target, {
                    'type': 'SMB',
                    'cve': vuln.cve,
                    'name': vuln.name,
                    'severity': vuln.severity
                })
        
        # Accès anonyme
        if results['anonymous_access']:
            self.logger.security(
                f"Accès anonyme SMB détecté sur {target}",
                target=target,
                service="SMB",
                access_type="anonymous"
            )
        
        # Session null
        if results['null_session']:
            self.logger.security(
                f"Session null possible sur {target}",
                target=target,
                service="SMB",
                access_type="null_session"
            )
