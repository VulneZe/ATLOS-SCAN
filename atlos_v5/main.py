#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ATLOS v5.0 - Point d'entrée principal
Advanced Threat Landscape Observation System
"""

import os
import sys
import argparse
import signal
import time
from pathlib import Path

# Ajout du répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).parent))

from utils.config import init_config, get_config
from utils.logger import setup_logging, get_logger
from core.scanner import NetworkScanner, ScanConfig
from modules.smb import SMBEnumerator
from utils.crypto import CredentialManager, SecureStorage

# Variables globales
config = None
logger = None
scanner = None

def signal_handler(signum, frame):
    """Gestionnaire de signaux pour arrêt propre"""
    global logger, scanner
    
    print("\n⛔ Arrêt d'ATLOS demandé...")
    
    if scanner:
        scanner.stop_scan()
    
    if logger:
        logger.info("ATLOS arrêté par l'utilisateur")
    
    sys.exit(0)

def check_root():
    """Vérifie si le script est exécuté en root"""
    if os.name == 'posix':  # Linux/Unix
        if os.geteuid() != 0:
            print("❌ Ce script doit être lancé en root ! → sudo python3 main.py")
            sys.exit(1)
    else:
        print("⚠️  Pour des fonctionnalités complètes, exécutez en tant qu'administrateur")

def banner():
    """Affiche la bannière ATLOS"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
    █████╗ ████████╗██╗      ██████╗ ███████╗
    ██╔══██╗╚══██╔══╝██║     ██╔═══██╗██╔════╝
    ███████║   ██║   ██║     ██║   ██║███████╗
    ██╔══██║   ██║   ██║     ██║   ██║╚════██║
    ██║  ██║   ██║   ███████╗╚██████╔╝███████║
    ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚══════╝
    
    ATLOS v5.0 - Enterprise Red Team Edition
    By Baptiste Rouault - atlos.fr
    ========================================
    """)

def init_atlos():
    """Initialise ATLOS"""
    global config, logger, scanner
    
    try:
        # Initialisation de la configuration
        config = init_config()
        
        # Validation de la configuration
        errors = config.validate_config()
        if errors:
            print("❌ Erreurs de configuration:")
            for error in errors:
                print(f"   - {error}")
            sys.exit(1)
        
        # Initialisation du logging
        logger = setup_logging(config._config_data)
        logger.info("ATLOS v5.0 initialisé")
        
        # Initialisation du scanner
        scanner = NetworkScanner(config, logger)
        
        logger.info("Composants ATLOS initialisés avec succès")
        
    except Exception as e:
        print(f"❌ Erreur lors de l'initialisation: {e}")
        sys.exit(1)

def cmd_scan(args):
    """Commande de scan réseau"""
    global scanner, logger
    
    try:
        logger.info(f"Lancement du scan réseau sur {args.target}")
        
        # Configuration du scan
        scan_config = ScanConfig(
            target_network=args.target,
            ports=args.ports or config.scan.default_ports,
            timeout=args.timeout or config.scan.timeout,
            max_threads=args.threads or config.scan.max_threads,
            stealth_mode=args.stealth,
            random_delay=not args.no_delay,
            exclude_hosts=args.exclude.split(',') if args.exclude else []
        )
        
        # Lancement du scan
        results = scanner.scan_network(scan_config)
        
        # Affichage des résultats
        display_scan_results(results)
        
        # Génération du rapport
        if args.report:
            generate_report(results, args.format)
        
        logger.info(f"Scan terminé: {len(results)} hôtes analysés")
        
    except KeyboardInterrupt:
        logger.info("Scan interrompu par l'utilisateur")
    except Exception as e:
        logger.error(f"Erreur lors du scan: {e}")
        print(f"❌ Erreur: {e}")

def cmd_smb(args):
    """Commande d'énumération SMB"""
    global logger
    
    try:
        logger.info(f"Énumération SMB sur {args.target}")
        
        # Initialisation de l'énumérateur SMB
        smb_enumerator = SMBEnumerator(config, logger)
        
        # Credentials si fournis
        credentials = None
        if args.username:
            credentials = {
                'username': args.username,
                'password': args.password or '',
                'domain': args.domain or ''
            }
        
        # Lancement de l'énumération
        results = smb_enumerator.enumerate_smb(args.target, credentials)
        
        # Affichage des résultats
        display_smb_results(results)
        
        # Génération du rapport
        if args.report:
            generate_smb_report(results, args.format)
        
        logger.info(f"Énumération SMB terminée pour {args.target}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'énumération SMB: {e}")
        print(f"❌ Erreur: {e}")

def cmd_api(args):
    """Commande de démarrage de l'API REST"""
    global config, logger
    
    try:
        logger.info("Démarrage de l'API REST ATLOS")
        
        # Import dynamique pour éviter les dépendances circulaires
        from api.rest import create_app
        
        app = create_app(config, logger)
        
        import uvicorn
        
        uvicorn.run(
            app,
            host=config.api.host,
            port=config.api.port,
            log_level="info"
        )
        
    except ImportError:
        print("❌ Module API non disponible. Installez les dépendances: pip install fastapi uvicorn")
    except Exception as e:
        logger.error(f"Erreur lors du démarrage de l'API: {e}")
        print(f"❌ Erreur: {e}")

def cmd_config(args):
    """Commande de gestion de la configuration"""
    global config
    
    if args.action == 'show':
        print("Configuration ATLOS actuelle:")
        print(f"  Scan timeout: {config.scan.timeout}s")
        print(f"  Max threads: {config.scan.max_threads}")
        print(f"  Stealth mode: {config.scan.stealth_mode}")
        print(f"  API enabled: {config.api.enabled}")
        print(f"  Database type: {config.database.type}")
    
    elif args.action == 'validate':
        errors = config.validate_config()
        if errors:
            print("❌ Erreurs de configuration:")
            for error in errors:
                print(f"   - {error}")
        else:
            print("✅ Configuration valide")
    
    elif args.action == 'reload':
        if config.reload():
            print("✅ Configuration rechargée")
        else:
            print("❌ Erreur lors du rechargement")

def display_scan_results(results):
    """Affiche les résultats du scan"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    if not results:
        console.print(Panel("Aucun résultat trouvé", title="Scan Results"))
        return
    
    # Tableau des résultats
    table = Table(title="🔥 ATLOS v5.0 - Résultats du Scan")
    table.add_column("IP", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("MAC/Vendor", style="yellow")
    table.add_column("OS", style="magenta")
    table.add_column("Ports Ouverts", style="red")
    table.add_column("Vulnérabilités", style="bold red")
    
    for result in results:
        ports = ", ".join(map(str, result.ports_open[:5]))  # Limiter à 5 ports
        if len(result.ports_open) > 5:
            ports += f" (+{len(result.ports_open) - 5})"
        
        vulns = f"{len(result.vulnerabilities)} trouvées"
        if result.vulnerabilities:
            critical_vulns = [v for v in result.vulnerabilities if v.get('severity') == 'Critical']
            if critical_vulns:
                vulns = f"🔴 {len(critical_vulns)} CRITIQUES"
        
        table.add_row(
            result.ip,
            result.hostname,
            f"{result.mac}\n{result.vendor}",
            result.os_guess,
            ports,
            vulns
        )
    
    console.print(table)
    
    # Statistiques
    online_hosts = len([r for r in results if r.status == 'online'])
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    
    stats_panel = Panel(
        f"Hôtes en ligne: {online_hosts}/{len(results)}\n"
        f"Vulnérabilités totales: {total_vulns}\n"
        f"Durée du scan: {scanner.get_scan_stats().get('scan_duration', 0):.2f}s",
        title="📊 Statistiques"
    )
    console.print(stats_panel)

def display_smb_results(results):
    """Affiche les résultats SMB"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    # Informations générales
    info_panel = Panel(
        f"Target: {results['target']}\n"
        f"SMB Version: {results['smb_version'] or 'Unknown'}\n"
        f"Session Null: {'✅' if results['null_session'] else '❌'}\n"
        f"Accès Anonyme: {'✅' if results['anonymous_access'] else '❌'}",
        title="🔍 Informations SMB"
    )
    console.print(info_panel)
    
    # Partages
    if results['shares']:
        table = Table(title="📁 Partages SMB")
        table.add_column("Nom", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Accès", style="yellow")
        table.add_column("Anonyme", style="red")
        table.add_column("Commentaire")
        
        for share in results['shares']:
            access = "✅" if share.accessible else "❌"
            anonymous = "✅" if share.anonymous_access else "❌"
            
            table.add_row(
                share.name,
                share.type,
                access,
                anonymous,
                share.comment
            )
        
        console.print(table)
    
    # Vulnérabilités
    if results['vulnerabilities']:
        vuln_table = Table(title="🚨 Vulnérabilités SMB")
        vuln_table.add_column("CVE", style="red")
        vuln_table.add_column("Nom", style="yellow")
        vuln_table.add_column("Sévérité", style="bold red")
        vuln_table.add_column("Description")
        
        for vuln in results['vulnerabilities']:
            vuln_table.add_row(
                vuln.cve,
                vuln.name,
                vuln.severity,
                vuln.description[:80] + "..." if len(vuln.description) > 80 else vuln.description
            )
        
        console.print(vuln_table)
    
    # Recommandations
    if results['recommendations']:
        rec_panel = Panel(
            "\n".join(results['recommendations']),
            title="💡 Recommandations de Sécurité"
        )
        console.print(rec_panel)

def generate_report(results, format_type='html'):
    """Génère un rapport de scan"""
    try:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"reports/atlos_scan_{timestamp}.{format_type}"
        
        # Création du répertoire de rapports
        Path('reports').mkdir(exist_ok=True)
        
        if format_type == 'json':
            import json
            report_data = []
            for result in results:
                report_data.append({
                    'ip': result.ip,
                    'hostname': result.hostname,
                    'mac': result.mac,
                    'vendor': result.vendor,
                    'os': result.os_guess,
                    'ports_open': result.ports_open,
                    'services': result.services,
                    'vulnerabilities': result.vulnerabilities,
                    'status': result.status,
                    'scan_time': result.scan_time
                })
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        elif format_type == 'html':
            # Rapport HTML basique
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>ATLOS v5.0 Scan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .critical {{ color: red; font-weight: bold; }}
                </style>
            </head>
            <body>
                <h1>ATLOS v5.0 Scan Report</h1>
                <p>Généré le: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Ports Ouverts</th>
                        <th>Vulnérabilités</th>
                    </tr>
            """
            
            for result in results:
                vuln_count = len(result.vulnerabilities)
                vuln_class = "critical" if vuln_count > 0 else ""
                
                html_content += f"""
                    <tr>
                        <td>{result.ip}</td>
                        <td>{result.hostname}</td>
                        <td>{result.os_guess}</td>
                        <td>{', '.join(map(str, result.ports_open))}</td>
                        <td class="{vuln_class}">{vuln_count}</td>
                    </tr>
                """
            
            html_content += """
                </table>
            </body>
            </html>
            """
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        print(f"✅ Rapport généré: {filename}")
        
    except Exception as e:
        print(f"❌ Erreur lors de la génération du rapport: {e}")

def generate_smb_report(results, format_type='html'):
    """Génère un rapport SMB"""
    try:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"reports/atlos_smb_{timestamp}.{format_type}"
        
        # Création du répertoire de rapports
        Path('reports').mkdir(exist_ok=True)
        
        if format_type == 'json':
            import json
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        elif format_type == 'html':
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>ATLOS v5.0 SMB Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .critical {{ color: red; font-weight: bold; }}
                </style>
            </head>
            <body>
                <h1>ATLOS v5.0 SMB Report</h1>
                <p>Cible: {results['target']}</p>
                <p>Généré le: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Informations SMB</h2>
                <table>
                    <tr><th>Version SMB</th><td>{results.get('smb_version', 'Unknown')}</td></tr>
                    <tr><th>Session Null</th><td>{'Oui' if results.get('null_session') else 'Non'}</td></tr>
                    <tr><th>Accès Anonyme</th><td>{'Oui' if results.get('anonymous_access') else 'Non'}</td></tr>
                </table>
            </body>
            </html>
            """
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        print(f"Rapport SMB généré: {filename}")
        
    except Exception as e:
        print(f"Erreur lors de la génération du rapport SMB: {e}")

def main():
    """Fonction principale"""
    global config, logger
    
    # Configuration des signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Vérification root
    check_root()
    
    # Bannière
    banner()
    
    # Parseur d'arguments
    parser = argparse.ArgumentParser(
        description="ATLOS v5.0 - Advanced Threat Landscape Observation System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande scan
    scan_parser = subparsers.add_parser('scan', help='Scan réseau')
    scan_parser.add_argument('target', help='Réseau cible (ex: 192.168.1.0/24)')
    scan_parser.add_argument('-p', '--ports', help='Ports à scanner (ex: 1-1000,3389)')
    scan_parser.add_argument('-t', '--timeout', type=int, help='Timeout en secondes')
    scan_parser.add_argument('-T', '--threads', type=int, help='Nombre de threads')
    scan_parser.add_argument('-s', '--stealth', action='store_true', help='Mode furtif')
    scan_parser.add_argument('--no-delay', action='store_true', help='Désactiver les délais aléatoires')
    scan_parser.add_argument('--exclude', help='Hôtes à exclure (séparés par des virgules)')
    scan_parser.add_argument('-r', '--report', action='store_true', help='Générer un rapport')
    scan_parser.add_argument('-f', '--format', choices=['json', 'html'], default='html', help='Format du rapport')
    
    # Commande smb
    smb_parser = subparsers.add_parser('smb', help='Énumération SMB')
    smb_parser.add_argument('target', help='IP cible')
    smb_parser.add_argument('-u', '--username', help='Nom d\'utilisateur')
    smb_parser.add_argument('-p', '--password', help='Mot de passe')
    smb_parser.add_argument('-d', '--domain', help='Domaine')
    smb_parser.add_argument('-r', '--report', action='store_true', help='Générer un rapport')
    smb_parser.add_argument('-f', '--format', choices=['json', 'html'], default='html', help='Format du rapport')
    
    # Commande api
    api_parser = subparsers.add_parser('api', help='Démarrer l\'API REST')
    
    # Commande config
    config_parser = subparsers.add_parser('config', help='Gestion de la configuration')
    config_parser.add_argument('action', choices=['show', 'validate', 'reload'], help='Action')
    
    # Parse des arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Initialisation d'ATLOS
        init_atlos()
        
        # Exécution de la commande
        if args.command == 'scan':
            cmd_scan(args)
        elif args.command == 'smb':
            cmd_smb(args)
        elif args.command == 'api':
            cmd_api(args)
        elif args.command == 'config':
            cmd_config(args)
    
    except KeyboardInterrupt:
        print("\n⛔ Opération interrompue par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        if logger:
            logger.critical(f"Erreur fatale: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
