import socket
import threading
import json
import os
import sys
pasta_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if pasta_raiz not in sys.path:
    sys.path.append(pasta_raiz)
from database.database import get_db_connection
import time

IP_LISTEN = "127.0.0.1"
UDP_PORT = 9999
TCP_PORT = 9998


# Recebe os dados UDP (normais) do sensor
def listen_udp():
    print(f"[*] Thread UDP ativa na porta {UDP_PORT}")

    # Cria o socket Udp que vai receber os dados padroes do sensor
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((IP_LISTEN, UDP_PORT))

    while True:

        # Recebe os dados vindos do sensor e coloca em dados_bytes e endereco_cliente
        dados_bytes, endereco_cliente = udp_socket.recvfrom(4096)
        mensagem = dados_bytes.decode('utf-8')
        print(f"\n[UDP] Recebido de {endereco_cliente}: {mensagem}")

        try:
            pacote = json.loads(mensagem)
            sensor_id = pacote["sensor_id"]
            payload = pacote["payload"]

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO metrics (sensor_id, cpu_percent, ram_percent, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (sensor_id, 
                    payload["cpu_percent"], 
                    payload["ram_percent"], 
                    payload["active_connections"],
                    pacote["seq_number"],
                    pacote["timestamp"]
                )
            )

            conn.commit()
            conn.close()
            print(f"[UDP] Métricas do sensor {sensor_id} salvas no banco com sucesso!")
            
        except Exception as e:
            print(f"[ERRO UDP] Falha ao processar ou salvar o pacote: {e}")

    pass


# Recebe os dados TCP (Alertas) do sensor
def listen_tcp():
    print(f"[*] Thread TCP ativa na porta {TCP_PORT}")

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind((IP_LISTEN, TCP_PORT))
    tcp_socket.listen(5)

    while True:
        # Aceita a conexao
        conexao_cliente, endereco_cliente = tcp_socket.accept()
        # Pega os bytes
        dados_bytes = conexao_cliente.recv(4096)
        mensagem = dados_bytes.decode('utf-8')
        print(f"\n[TCP] Recebido de {endereco_cliente}: {mensagem}")

        try:
            pacote = json.loads(mensagem)
            sensor_id = pacote["sensor_id"]
            payload = pacote["payload"]

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO events (sensor_id, type, category, severity, description, raw_payload, timestamp, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sensor_id,
                    pacote["type"],            # "ALERT"
                    payload["category"],        # "FILE_INTEGRITY"
                    payload["severity"],        # "CRITICAL"
                    payload["description"],
                    mensagem,                   # JSON completo para auditoria histórica
                    pacote["timestamp"],
                    time.time()                 # Momento exato em que o servidor recebeu
                )
            )

            conn.commit()
            conn.close()
            print(f"[TCP] Alerta crítico do sensor {sensor_id} salvo no banco com sucesso!")

        except Exception as e:
            print(f"[ERRO TCP] Falha ao processar ou salvar o alerta: {e}")

        # Fecha o socket dedicado após terminar de tratar o cliente
        conexao_cliente.close()



def iniciar_servidor():

    thread_udp = threading.Thread(target=listen_udp, daemon=True)
    thread_tcp = threading.Thread(target=listen_tcp, daemon=True)

    thread_tcp.start()
    thread_udp.start()

    while True:
        try:
            input("[Servidor Rodando] Pressione Ctrl+C para encerrar.\n")
        except KeyboardInterrupt:
            break



if __name__ == "__main__":
    iniciar_servidor()