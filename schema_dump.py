import os
from contextlib import contextmanager
import psycopg2

@contextmanager
def get_db():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL not set")
        yield None
        return

    conn = psycopg2.connect(database_url)
    try:
        yield conn
    finally:
        conn.close()

with get_db() as conn:
    if conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'server_subscriptions';
        """)
        columns = cursor.fetchall()
        print("server_subscriptions columns:")
        for col in columns:
            print(f"- {col[0]} ({col[1]})")
