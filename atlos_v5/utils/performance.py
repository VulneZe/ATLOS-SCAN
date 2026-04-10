#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'optimisation des performances ATLOS v5.0
Gestion de la mémoire, cache et optimisations réseau
"""

import os
import time
import psutil
import threading
import gc
import weakref
import socket
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from collections import defaultdict, deque
import logging
from functools import lru_cache, wraps
import asyncio

@dataclass
class PerformanceMetrics:
    """Métriques de performance"""
    cpu_percent: float
    memory_percent: float
    memory_mb: int
    threads_count: int
    open_files: int
    network_connections: int

class PerformanceMonitor:
    """Moniteur de performance ATLOS"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.process = psutil.Process()
        self.metrics_history = deque(maxlen=100)
        self.alerts_threshold = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'threads_count': 200,
            'open_files': 1000
        }
        self.monitoring_active = False
        self.monitor_thread = None
    
    def start_monitoring(self, interval: float = 5.0):
        """Démarre le monitoring en arrière-plan"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info("Monitoring des performances démarré")
    
    def stop_monitoring(self):
        """Arrête le monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        self.logger.info("Monitoring des performances arrêté")
    
    def _monitor_loop(self, interval: float):
        """Boucle de monitoring"""
        while self.monitoring_active:
            try:
                metrics = self.get_current_metrics()
                self.metrics_history.append(metrics)
                self._check_alerts(metrics)
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Erreur monitoring: {e}")
                time.sleep(interval)
    
    def get_current_metrics(self) -> PerformanceMetrics:
        """Récupère les métriques actuelles"""
        try:
            # Métriques CPU
            cpu_percent = self.process.cpu_percent()
            
            # Métriques mémoire
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss // 1024 // 1024
            memory_percent = self.process.memory_percent()
            
            # Métriques système
            threads_count = self.process.num_threads()
            open_files = len(self.process.open_files())
            
            # Connexions réseau
            try:
                network_connections = len(self.process.connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                network_connections = 0
            
            return PerformanceMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_mb=memory_mb,
                threads_count=threads_count,
                open_files=open_files,
                network_connections=network_connections
            )
        
        except Exception as e:
            self.logger.error(f"Erreur récupération métriques: {e}")
            return PerformanceMetrics(0, 0, 0, 0, 0, 0)
    
    def _check_alerts(self, metrics: PerformanceMetrics):
        """Vérifie les alertes de performance"""
        alerts = []
        
        if metrics.cpu_percent > self.alerts_threshold['cpu_percent']:
            alerts.append(f"CPU élevé: {metrics.cpu_percent:.1f}%")
        
        if metrics.memory_percent > self.alerts_threshold['memory_percent']:
            alerts.append(f"Mémoire élevée: {metrics.memory_percent:.1f}%")
        
        if metrics.threads_count > self.alerts_threshold['threads_count']:
            alerts.append(f"Threads élevés: {metrics.threads_count}")
        
        if metrics.open_files > self.alerts_threshold['open_files']:
            alerts.append(f"Fichiers ouverts: {metrics.open_files}")
        
        for alert in alerts:
            self.logger.warning(f"Alerte performance: {alert}")
    
    def get_average_metrics(self, last_n: int = 10) -> Optional[PerformanceMetrics]:
        """Calcule la moyenne des dernières métriques"""
        if not self.metrics_history:
            return None
        
        recent_metrics = list(self.metrics_history)[-last_n:]
        
        if not recent_metrics:
            return None
        
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory_mb = sum(m.memory_mb for m in recent_metrics) / len(recent_metrics)
        avg_threads = sum(m.threads_count for m in recent_metrics) / len(recent_metrics)
        avg_files = sum(m.open_files for m in recent_metrics) / len(recent_metrics)
        avg_connections = sum(m.network_connections for m in recent_metrics) / len(recent_metrics)
        
        return PerformanceMetrics(
            cpu_percent=avg_cpu,
            memory_percent=avg_memory,
            memory_mb=int(avg_memory_mb),
            threads_count=int(avg_threads),
            open_files=int(avg_files),
            network_connections=int(avg_connections)
        )
    
    def optimize_memory(self):
        """Optimise l'utilisation mémoire"""
        try:
            # Force garbage collection
            collected = gc.collect()
            
            # Nettoyage des caches
            if hasattr(gc, 'get_count'):
                old_counts = gc.get_count()
                gc.set_threshold(700, 10, 5)  # Plus agressif
                new_counts = gc.get_count()
            
            self.logger.info(f"Optimisation mémoire: {collected} objets collectés")
            
        except Exception as e:
            self.logger.error(f"Erreur optimisation mémoire: {e}")

class MemoryCache:
    """Cache mémoire avec LRU et TTL"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.creation_times = {}
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache"""
        with self.lock:
            if key not in self.cache:
                return None
            
            # Vérification TTL
            if self._is_expired(key):
                self._remove(key)
                return None
            
            # Mise à jour du temps d'accès
            self.access_times[key] = time.time()
            return self.cache[key]
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Définit une valeur dans le cache"""
        with self.lock:
            # Nettoyage si nécessaire
            if len(self.cache) >= self.max_size:
                self._evict_lru()
            
            current_time = time.time()
            self.cache[key] = value
            self.access_times[key] = current_time
            self.creation_times[key] = current_time
            
            # TTL personnalisé
            if ttl is not None:
                self.creation_times[key] = current_time + ttl - self.default_ttl
            
            return True
    
    def _is_expired(self, key: str) -> bool:
        """Vérifie si une clé a expiré"""
        if key not in self.creation_times:
            return True
        
        return time.time() > (self.creation_times[key] + self.default_ttl)
    
    def _evict_lru(self):
        """Évince les éléments les moins récemment utilisés"""
        if not self.access_times:
            return
        
        # Trouver la clé la plus ancienne
        oldest_key = min(self.access_times, key=self.access_times.get)
        self._remove(oldest_key)
    
    def _remove(self, key: str):
        """Supprime une clé du cache"""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
        self.creation_times.pop(key, None)
    
    def clear(self):
        """Vide le cache"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            self.creation_times.clear()
    
    def size(self) -> int:
        """Retourne la taille du cache"""
        return len(self.cache)
    
    def stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du cache"""
        with self.lock:
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'ttl': self.default_ttl,
                'keys': list(self.cache.keys())
            }

class ConnectionPool:
    """Pool de connexions réseau optimisé"""
    
    def __init__(self, max_connections: int = 50, timeout: float = 30.0):
        self.max_connections = max_connections
        self.timeout = timeout
        self.connections = deque()
        self.active_connections = set()
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def get_connection(self, host: str, port: int, timeout: Optional[float] = None) -> socket.socket:
        """Récupère une connexion du pool"""
        conn_timeout = timeout or self.timeout
        
        with self.lock:
            # Vérifier si une connexion existe déjà pour cet hôte
            for conn, (h, p, created_time) in list(self.connections):
                if h == host and p == port and conn not in self.active_connections:
                    # Vérifier si la connexion est toujours valide
                    if self._is_connection_valid(conn):
                        self.active_connections.add(conn)
                        return conn
                    else:
                        # Connexion invalide, la supprimer
                        self.connections.remove((conn, (h, p, created_time)))
                        try:
                            conn.close()
                        except:
                            pass
            
            # Créer une nouvelle connexion
            if len(self.active_connections) >= self.max_connections:
                raise Exception("Nombre maximum de connexions atteint")
            
            try:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(conn_timeout)
                conn.connect((host, port))
                
                # Ajouter au pool
                self.connections.append((conn, (host, port, time.time())))
                self.active_connections.add(conn)
                
                return conn
            
            except Exception as e:
                self.logger.error(f"Erreur connexion {host}:{port}: {e}")
                raise
    
    def release_connection(self, conn: socket.socket):
        """Libère une connexion"""
        with self.lock:
            self.active_connections.discard(conn)
    
    def _is_connection_valid(self, conn: socket.socket) -> bool:
        """Vérifie si une connexion est toujours valide"""
        try:
            # Test simple avec un appel non bloquant
            conn.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            return True
        except:
            return False
    
    def cleanup(self):
        """Nettoie les connexions expirées"""
        current_time = time.time()
        max_age = 300  # 5 minutes
        
        with self.lock:
            to_remove = []
            
            for conn, (host, port, created_time) in self.connections:
                if current_time - created_time > max_age or conn in self.active_connections:
                    continue
                
                if not self._is_connection_valid(conn):
                    to_remove.append(conn)
                    try:
                        conn.close()
                    except:
                        pass
            
            for conn in to_remove:
                # Trouver et supprimer la connexion
                for i, (c, info) in enumerate(self.connections):
                    if c == conn:
                        del self.connections[i]
                        break

def performance_monitor(func: Callable) -> Callable:
    """Décorateur pour monitorer les performances"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            result = func(*args, **kwargs)
            
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            
            execution_time = end_time - start_time
            memory_delta = (end_memory - start_memory) // 1024  # KB
            
            logger = logging.getLogger(func.__module__)
            logger.debug(
                f"Performance {func.__name__}: "
                f"{execution_time:.3f}s, {memory_delta}KB mémoire"
            )
            
            return result
        
        except Exception as e:
            logger = logging.getLogger(func.__module__)
            logger.error(f"Erreur dans {func.__name__}: {e}")
            raise
    
    return wrapper

def memory_efficient(max_items: int = 1000):
    """Décorateur pour optimiser l'utilisation mémoire"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Nettoyage avant exécution
            gc.collect()
            
            try:
                result = func(*args, **kwargs)
                
                # Nettoyage après exécution
                if len(result) > max_items:
                    # Limiter la taille des résultats
                    result = result[:max_items]
                
                gc.collect()
                return result
            
            finally:
                # Forcer le nettoyage
                gc.collect()
        
        return wrapper
    return decorator

# Cache global pour les résultats fréquents
dns_cache = MemoryCache(max_size=1000, default_ttl=300)
port_scan_cache = MemoryCache(max_size=500, default_ttl=600)

# Pool de connexions global
connection_pool = ConnectionPool(max_connections=50)

# Instance du moniteur de performance
performance_monitor_instance = None

def init_performance_monitor(logger: logging.Logger) -> PerformanceMonitor:
    """Initialise le moniteur de performance"""
    global performance_monitor_instance
    performance_monitor_instance = PerformanceMonitor(logger)
    return performance_monitor_instance

def get_performance_monitor() -> Optional[PerformanceMonitor]:
    """Retourne l'instance du moniteur de performance"""
    return performance_monitor_instance

# Optimisations spécifiques à ATLOS
class ATLOSOptimizer:
    """Optimiseur spécifique pour ATLOS"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.performance_monitor = init_performance_monitor(logger)
        
        # Configuration des optimisations
        self.enable_caching = config.get('performance', {}).get('cache_enabled', True)
        self.enable_monitoring = config.get('performance', {}).get('monitoring_enabled', True)
        self.max_threads = config.get('scan', {}).get('max_threads', 50)
        
        if self.enable_monitoring:
            self.performance_monitor.start_monitoring()
    
    def optimize_scan_parameters(self, target_network: str) -> Dict[str, Any]:
        """Optimise les paramètres de scan selon les ressources"""
        metrics = self.performance_monitor.get_current_metrics()
        
        optimized_params = {
            'max_threads': self.max_threads,
            'timeout': 5,
            'stealth_mode': False
        }
        
        # Ajustement selon la charge CPU
        if metrics.cpu_percent > 70:
            optimized_params['max_threads'] = max(10, self.max_threads // 2)
            self.logger.info(f"Réduction threads due CPU élevé: {optimized_params['max_threads']}")
        
        # Ajustement selon la mémoire
        if metrics.memory_percent > 80:
            optimized_params['stealth_mode'] = True
            optimized_params['timeout'] = 10
            self.logger.info("Mode furtif activé due mémoire élevée")
        
        # Ajustement selon la taille du réseau
        try:
            import ipaddress
            network = ipaddress.ip_network(target_network, strict=False)
            host_count = network.num_addresses
            
            if host_count > 1000:
                optimized_params['max_threads'] = min(optimized_params['max_threads'], 100)
                optimized_params['timeout'] = 3
            elif host_count < 100:
                optimized_params['max_threads'] = min(optimized_params['max_threads'], 20)
        
        except:
            pass
        
        return optimized_params
    
    def cleanup(self):
        """Nettoyage des ressources"""
        if self.performance_monitor:
            self.performance_monitor.stop_monitoring()
        
        # Nettoyage des caches
        dns_cache.clear()
        port_scan_cache.clear()
        
        # Nettoyage du pool de connexions
        connection_pool.cleanup()
        
        # Optimisation mémoire
        gc.collect()
        
        self.logger.info("Nettoyage des ressources terminé")
