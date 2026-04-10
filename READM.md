# ATLOS - Advanced Threat Landscape Observation System

**Version :** 4.0  
**Auteur :** Baptiste Rouault  
**Site :** [atlos.fr](https://atlos.fr)

ATLOS est un outil complet de reconnaissance réseau et d’attaques Red Team développé en Python.  
Il permet de scanner rapidement un réseau (WiFi + Ethernet), de découvrir les machines, d’effectuer des scans approfondis (Nmap + vulnérabilités), d’énumérer les DNS, LDAP, HTTP, SNMP, et de lancer des attaques MITM via ARP Poisoning.

Conçu pour les **TP de cybersécurité**, les **pentests internes** et les **exercices Red Team éthiques**.

---

## Fonctionnalités principales

- Scan complet des réseaux WiFi (visibles + connecté)
- Détection automatique du réseau actuel (Ethernet / WiFi)
- Scan ARP rapide des hôtes
- Scan Nmap complet (`-sV -O --script vuln`)
- **DNS Enumeration** avancée (Zone Transfer, records, détection Active Directory)
- **HTTP/HTTPS** banner + title recovery
- **SNMP** enumeration (community "public")
- **MAC Vendor** lookup
- **LDAP Enumeration** (anonyme ou avec credentials)
- **ARP Poisoning MITM** avec restauration automatique
- Suggestions d’attaques Red Team intelligentes
- Génération automatique d’un rapport HTML professionnel
- Menu interactif via arguments (`--mode`)

---

## Installation

```bash
# Installation des dépendances
pip3 install scapy rich requests ldap3

# Installation des outils système
sudo apt update
sudo apt install nmap dnsutils snmp -y

Utilisation
1. Scan complet (mode recommandé)
Bashsudo python3 atlos.py --mode recon
2. ARP Poisoning MITM
Bashsudo python3 atlos.py --mode mitm -t 192.168.1.50 -g 192.168.1.1 -i eth0
3. LDAP Enumeration
Bash# Anonyme
sudo python3 atlos.py --mode ldap -t 192.168.1.10

# Avec credentials
sudo python3 atlos.py --mode ldap -t 192.168.1.10 -d company.local -u pentest -p Password123
4. Mode complet (recon + tout)
Bashsudo python3 atlos.py --mode full

Options disponibles




OptionDescription--mode reconScan reconnaissance complet--mode mitmARP Poisoning MITM--mode ldapLDAP Enumeration--mode fullMode complet-i, --interfaceInterface réseau (ex: eth0, wlan0)-t, --targetIP cible (MITM ou DC LDAP)-g, --gatewayIP de la gateway (pour MITM)-d, --domainDomaine Active Directory-u, --userNom d’utilisateur LDAP-p, --passwordMot de passe LDAP

Rapport
À la fin du scan, un fichier ATLOS_RedTeam_Report.html est généré automatiquement dans le dossier.

Avertissement important (Disclaimer)
ATLOS est un outil à usage éducatif et éthique uniquement.
Utilisez-le uniquement sur des réseaux et des machines pour lesquels vous avez une autorisation explicite.
Toute utilisation illégale est strictement interdite. L’auteur décline toute responsabilité en cas de mauvaise utilisation.

Améliorations futures possibles

Intégration Bettercap
Export PDF du rapport
Mode furtif (slow scan)
Graphique du réseau (NetworkX)
Auto IP forwarding pendant le MITM


Développé avec  pour la formation en cybersécurité
Baptiste Rouault – atlos.fr