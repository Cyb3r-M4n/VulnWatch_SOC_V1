# engine/tests/test_correlation.py
"""Tests de la fonction de corrélation"""

import pytest
import asyncio
from ..src.database.connection import init_db, close_db, execute_query_row

@pytest.mark.asyncio
async def test_run_correlation():
    """Test l'exécution de la corrélation"""
    await init_db()
    
    try:
        query = "SELECT * FROM run_correlation()"
        row = await execute_query_row(query)
        
        assert 'new_findings' in row
        assert 'updated_findings' in row
        assert 'process_findings' in row
        assert isinstance(row['new_findings'], int)
        assert isinstance(row['updated_findings'], int)
        assert isinstance(row['process_findings'], int)
        
        print(f"✅ Corrélation testée: {row}")
        
    finally:
        await close_db()
