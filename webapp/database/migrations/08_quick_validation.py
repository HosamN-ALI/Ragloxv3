#!/usr/bin/env python3
"""
Quick database validation check - simpler version
"""
import asyncio
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv('.env.test')
load_dotenv()

db_url = os.getenv('DATABASE_URL', 'postgresql://raglox:raglox_dev_password_2026@localhost:5432/raglox')

async def main():
    print("\n🔍 RAGLOX V3 - Quick Database Validation\n" + "="*70)
    
    conn = await asyncpg.connect(db_url)
    
    # Check tables
    print("\n📋 Tables:")
    tables = await conn.fetch("""
        SELECT table_name, 
               (SELECT COUNT(*) FROM information_schema.columns 
                WHERE table_name = t.table_name) as columns
        FROM information_schema.tables t
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name
    """)
    
    for t in tables:
        print(f"  ✓ {t['table_name']:20s} ({t['columns']} columns)")
    
    # Count records
    print("\n📊 Record Counts:")
    for t in tables:
        try:
            count = await conn.fetchval(f'SELECT COUNT(*) FROM {t["table_name"]}')
            print(f"  {t['table_name']:20s}: {count:6d} records")
        except Exception as e:
            print(f"  {t['table_name']:20s}: ERROR - {e}")
    
    # Check foreign keys
    print("\n🔗 Foreign Keys:")
    fks = await conn.fetch("""
        SELECT
            tc.table_name,
            kcu.column_name,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
        ORDER BY tc.table_name
    """)
    
    for fk in fks:
        print(f"  ✓ {fk['table_name']}.{fk['column_name']} → {fk['foreign_table_name']}.{fk['foreign_column_name']}")
    
    # Check indexes
    indexes = await conn.fetch("SELECT * FROM pg_indexes WHERE schemaname = 'public'")
    print(f"\n📑 Indexes: {len(indexes)} total")
    
    await conn.close()
    
    print("\n" + "="*70)
    print("✅ Validation complete!")
    print(f"📊 Total tables: {len(tables)}")
    print(f"🔗 Total foreign keys: {len(fks)}\n")

asyncio.run(main())
