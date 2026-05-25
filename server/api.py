from flask import Flask, jsonify, send_file, request
from flask_cors import CORS
import os
import sys
pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if pasta_raiz not in sys.path:
    sys.path.append(pasta_raiz)
from database.database import get_db_connection


app = Flask(__name__)
CORS(app)


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), '..', 'web', 'templates')
STATIC_DIR   = os.path.join(os.path.dirname(__file__), '..', 'web', 'static')
 
app = Flask(__name__,
            template_folder=TEMPLATE_DIR,
            static_folder=STATIC_DIR)
CORS(app)
 


@app.route("/", methods=["GET"])
def index():
    """
    Serve o painel operacional (dashboard.html) localizado em web/templates/.
    Acesse em: http://127.0.0.1:5000
    """
    dashboard_path = os.path.join(TEMPLATE_DIR, 'dashboard.html')
    return send_file(dashboard_path, mimetype='text/html')



@app.route("/api/status", methods=["GET"])
def checar_status():
    """
    Rota simples que retorna um status 200 (OK) e um JSON estático.
    Serve para validar se a comunicação HTTP está funcionando.
    """
    resposta = {
        "status": "online",
        "projeto": "NetWatch SIEM",
        "mensagem": "API Flask operando com sucesso!",
        "protocolo": "NAP/1.0",
        "portas": {
            "udp_telemetry": 9999,
            "tcp_alerts":    9998,
            "http_api":      5000
        }

    }

    return jsonify(resposta), 200




# 2. Nova rota para expor o histórico de métricas do hardware
@app.route("/api/metrics", methods=["GET"])
def obter_metricas():
    """
    Conecta ao SQLite, busca as últimas 50 telemetrias registradas
    pelo sensor UDP e retorna no formato JSON.
    """

    try:
        # Abre a conexao com o banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()

        # Executa a query trazendo as métricas ordenadas pela data mais recente (LIMIT 50)
        cursor.execute("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 50")
        linhas = cursor.fetchall()

        conn.close()

        # Converte as linhas do banco (objetos sqlite3.Row) em dicionários Python normais
        lista_metricas = [dict(linha) for linha in linhas]

        return jsonify(lista_metricas), 200
    
    except Exception as e:
        return jsonify({"erro": f"Falha ao ler o banco de dados: {str(e)}"}), 500
    


@app.route("/api/events", methods=["GET"])
def obter_alertas():
    """
    Retorna os últimos 50 alertas de segurança recebidos via TCP.
    Filtra apenas registros do tipo ALERT.
    """

    try:
        # Abre a conexao com o banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()

        # Executa a query trazendo as métricas ordenadas pela data mais recente (LIMIT 50)
        cursor.execute("SELECT * FROM events WHERE type = 'ALERT' ORDER BY timestamp DESC LIMIT 50")
        linhas = cursor.fetchall()

        conn.close()

        # Converte as linhas do banco (objetos sqlite3.Row) em dicionários Python normais
        events_list = [dict(linha) for linha in linhas]

        return jsonify(events_list), 200
    
    except Exception as e:
        return jsonify({"erro": f"Falha ao ler o banco de dados: {str(e)}"}), 500



@app.route("/api/stats", methods=["GET"])
def obter_estatisticas():
    """
    Retorna contadores agregados de severidade e categoria,
    além do total geral de eventos e métricas registradas.
    """
    try:
        conn   = get_db_connection()
        cursor = conn.cursor()
 
        # Total de alertas por severidade
        cursor.execute("""
            SELECT severity, COUNT(*) as total
            FROM events
            WHERE type = 'ALERT'
            GROUP BY severity
        """)
        sev_rows = {row['severity']: row['total'] for row in cursor.fetchall()}
 
        # Total de alertas por categoria
        cursor.execute("""
            SELECT category, COUNT(*) as total
            FROM events
            WHERE type = 'ALERT'
            GROUP BY category
        """)
        cat_rows = {row['category']: row['total'] for row in cursor.fetchall()}
 
        # Total geral
        cursor.execute("SELECT COUNT(*) as total FROM events WHERE type = 'ALERT'")
        total_events = cursor.fetchone()['total']
 
        # Total de pacotes UDP recebidos
        cursor.execute("SELECT COUNT(*) as total FROM metrics")
        total_metrics = cursor.fetchone()['total']
 
        # Sensores únicos
        cursor.execute("SELECT COUNT(DISTINCT sensor_id) as total FROM metrics")
        total_sensors = cursor.fetchone()['total']
 
        conn.close()
 
        return jsonify({
            "total_alertas":  total_events,
            "total_metricas": total_metrics,
            "total_sensores": total_sensors,
            "por_severidade": {
                "CRITICAL": sev_rows.get("CRITICAL", 0),
                "HIGH":     sev_rows.get("HIGH",     0),
                "MEDIUM":   sev_rows.get("MEDIUM",   0),
                "LOW":      sev_rows.get("LOW",      0),
            },
            "por_categoria": cat_rows
        }), 200
 
    except Exception as e:
        return jsonify({"erro": f"Falha ao calcular estatísticas: {str(e)}"}), 500


@app.route("/api/auth/login", methods=["POST"])
def login():
    """
    Rota de autenticação básica para o operador do SOC.
    Recebe um JSON com usuário e senha e valida as credenciais.
    """
    try:
        dados = request.get_json()
        usuario = dados.get("username")
        senha = dados.get("password")

        if usuario == "admin" and senha == "admin123":
            return jsonify({"status": "success", "message": "Autenticado com sucesso!"}), 200
        else:
            return jsonify({"status": "error", "message": "Usuário ou senha incorretos."}), 401
    except Exception as e:
        return jsonify({"erro": f"Falha no servidor de autenticação: {str(e)}"}), 500

if __name__ == "__main__":
    print("[*] Iniciando o servidor da API HTTP...")
    app.run(host="127.0.0.1", port=5000, debug=True)
