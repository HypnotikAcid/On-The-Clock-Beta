import os
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import logging

logger = logging.getLogger('timewarden.db')

DATABASE_URL = os.getenv("DATABASE_URL")
app_db_pool = None

def init_app_db_pool():
    """Initialize PostgreSQL connection pool for Flask app"""
    global app_db_pool
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is not set")
    app_db_pool = psycopg2.pool.ThreadedConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=DATABASE_URL
    )
    logger.info("[OK] PostgreSQL connection pool initialized for Flask")

class FlaskConnectionWrapper:
    """Wrapper to make psycopg2 connection behave like sqlite3 connection with Row factory"""
    def __init__(self, conn):
        self._conn = conn
        self._cursor = None
    
    def execute(self, query, params=None):
        """Execute a query and return a cursor (mimics sqlite3 behavior)"""
        # Use RealDictCursor for dict-like row access (like RealDictCursor)
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        if params:
            self._cursor.execute(query, params)
        else:
            self._cursor.execute(query)
        return self._cursor
    
    def executemany(self, query, params_list):
        """Execute a query with multiple parameter sets"""
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        self._cursor.executemany(query, params_list)
        return self._cursor
    
    def cursor(self):
        """Get a new cursor with dict-like rows"""
        return self._conn.cursor(cursor_factory=RealDictCursor)
    
    def commit(self):
        """Commit the transaction"""
        self._conn.commit()
    
    def rollback(self):
        """Rollback the transaction"""
        self._conn.rollback()

@contextmanager
def get_db():
    """Context manager for PostgreSQL database connections (Flask app)"""
    if app_db_pool is None:
        init_app_db_pool()
    
    conn = None
    max_retries = 2
    for attempt in range(max_retries):
        try:
            conn = app_db_pool.getconn()
            
            # Validate connection is alive by executing a simple query
            # This catches stale/closed SSL connections before they cause errors
            test_cursor = conn.cursor()
            test_cursor.execute("SELECT 1")
            test_cursor.close()
            
            # Connection is good, proceed
            break
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            # Connection is stale/dead, close it and get a new one
            if conn:
                try:
                    conn.close()
                except:
                    pass
                app_db_pool.putconn(conn, close=True)  # Mark as bad
            
            if attempt < max_retries - 1:
                # Try again with a fresh connection
                continue
            else:
                # Last attempt failed, re-raise
                raise
    
    wrapper = FlaskConnectionWrapper(conn)
    try:
        yield wrapper
        # Auto-commit on successful exit
        conn.commit()
    except Exception as e:
        # Auto-rollback on exception
        conn.rollback()
        raise
    finally:
        # Always return connection to pool
        try:
            app_db_pool.putconn(conn)
        except:
            pass
