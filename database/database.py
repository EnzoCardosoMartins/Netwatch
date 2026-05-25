import sqlite3
import os
from werkzeug.security import generate_password_hash 

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'netwatch.db')

def get_db_connection():
    """
    Retorna uma nova conexão com o banco de dados configurada para o modo WAL.
    Cada thread deve chamar esta função para obter seu próprio handle.
    """
    # Garante que a pasta database existe
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    # Habilita o modo WAL para concorrência multi-thread segura
    conn.execute('PRAGMA journal_mode=WAL;')
    # Retorna os resultados como dicionários (facilita a serialização JSON no Flask)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Inicializa o esquema do banco de dados criando as tabelas caso não existam.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Tabela: events (Logs gerais, alertas e telemetria bruta)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id   TEXT NOT NULL,
            type        TEXT NOT NULL,          -- TELEMETRY, ALERT, HEARTBEAT
            category    TEXT,                   -- BRUTE_FORCE, PORT_SCAN, etc.
            severity    TEXT,                   -- LOW, MEDIUM, HIGH, CRITICAL
            description TEXT,
            raw_payload TEXT NOT NULL,          -- JSON completo para auditoria
            timestamp   REAL NOT NULL,          -- Timestamp do sensor
            rtt_ms      REAL,                   -- Calculado no servidor
            received_at REAL NOT NULL           -- Timestamp local do recebimento
        );
    ''')
    
    # Tabela: sensors (Estado e inventário dos sensores)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensors (
            sensor_id   TEXT PRIMARY KEY,
            first_seen  REAL NOT NULL,
            last_seen   REAL NOT NULL,
            ip_address  TEXT,
            status      TEXT DEFAULT 'ACTIVE'   -- ACTIVE, OFFLINE
        );
    ''')
    
    # Tabela: metrics (Série temporal das métricas de performance para gráficos)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id           TEXT NOT NULL,
            timestamp           REAL NOT NULL,
            cpu_percent         REAL,
            ram_percent         REAL,
            active_connections  INTEGER,
            seq_number          INTEGER,
            udp_loss_percent    REAL
        );
    ''')

    # Tabela: users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
    ''')
    # cria o user padrao admin
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hash_senha = generate_password_hash("admin123")
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", hash_senha))

    conn.commit()
    conn.close()
    print("[*] Base de dados SQLite inicializada com sucesso em modo WAL.")

if __name__ == '__main__':
    # Teste rápido de execução direta
    init_db()