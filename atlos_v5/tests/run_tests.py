#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lanceur de tests pour ATLOS v5.0
Exécution et validation des tests unitaires
"""

import os
import sys
import unittest
import time
from pathlib import Path

# Ajout du path parent pour les imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def run_all_tests():
    """Exécute tous les tests"""
    print("=== ATLOS v5.0 - Suite de Tests ===\n")
    
    # Découverte des tests
    loader = unittest.TestLoader()
    start_dir = Path(__file__).parent
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Exécution des tests
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    start_time = time.time()
    
    result = runner.run(suite)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Affichage des résultats
    print(f"\n=== Résultats des Tests ===")
    print(f"Durée totale: {duration:.2f}s")
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    
    if result.failures:
        print(f"\n=== Échecs ===")
        for test, traceback in result.failures:
            print(f"FAIL: {test}")
            print(f"---\n{traceback}\n---")
    
    if result.errors:
        print(f"\n=== Erreurs ===")
        for test, traceback in result.errors:
            print(f"ERROR: {test}")
            print(f"---\n{traceback}\n---")
    
    # Code de sortie
    exit_code = 0 if result.wasSuccessful() else 1
    
    print(f"\n=== Code de sortie: {exit_code} ===")
    return exit_code

def run_specific_test(test_module):
    """Exécute un module de test spécifique"""
    print(f"=== Test du module: {test_module} ===\n")
    
    try:
        suite = unittest.TestLoader().loadTestsFromName(test_module)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return 0 if result.wasSuccessful() else 1
    
    except Exception as e:
        print(f"Erreur lors de l'exécution du test {test_module}: {e}")
        return 1

def check_dependencies():
    """Vérifie les dépendances requises pour les tests"""
    print("Vérification des dépendances...")
    
    required_modules = [
        'unittest',
        'tempfile',
        'shutil',
        'pathlib',
        'yaml',
        'cryptography',
        'sqlalchemy',
        'psutil'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"  {module}: OK")
        except ImportError:
            print(f"  {module}: MANQUANT")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\nModules manquants: {', '.join(missing_modules)}")
        print("Installez-les avec: pip install -r requirements.txt")
        return False
    
    print("Toutes les dépendances sont présentes.\n")
    return True

def main():
    """Fonction principale"""
    # Vérification des dépendances
    if not check_dependencies():
        return 1
    
    # Arguments de ligne de commande
    if len(sys.argv) > 1:
        test_module = sys.argv[1]
        return run_specific_test(test_module)
    else:
        return run_all_tests()

if __name__ == '__main__':
    sys.exit(main())
