import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()
database_url = os.getenv("DATABASE_URL")

conn = psycopg2.connect(database_url)
cursor = conn.cursor()
cursor.execute("""
    SELECT column_name, data_type 
    FROM information_schema.columns 
    WHERE table_name = 'guild_settings';
""")
columns = cursor.fetchall()
print("guild_settings columns:")
for col in columns:
    print(f"- {col[0]} ({col[1]})")
conn.close()
