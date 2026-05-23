from flask import Flask, jsonify
from flask_cors import CORS
import os
import sys
pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if pasta_raiz not in sys.path:
    sys.path.append(pasta_raiz)
from database.database import get_db_connection


app = Flask(__name__)

@app.route("/api/status", methods=["GET"])
def checar_status():
    """
    Rota simples que retorna um status 200 (OK) e um JSON estático.
    Serve para validar se a comunicação HTTP está funcionando.
    """
    resposta = {
        "status": "online",
        "projeto": "NetWatch SIEM",
        "mensagem": "API Flask operando com sucesso!"
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





if __name__ == "__main__":
    print("[*] Iniciando o servidor da API HTTP...")
    app.run(host="127.0.0.1", port=5000, debug=True)
