# engine/src/utils/logger.py
"""Configuration du logger"""

import sys
from loguru import logger

def setup_logger():
    """Configure le logger pour l'application"""
    logger.remove()
    
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level="DEBUG"
    )
    
    logger.add(
        "/app/data/engine.log",
        rotation="10 MB",
        retention="7 days",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="INFO"
    )
    
    logger.info("✅ Logger configuré")
