import psutil
import os
import socket
import time
import json
from collector import collect_system_metrics, calcular_hash_arquivo, SENSOR_ID

IP_SERVER = "127.0.0.1"
UDP_PORT = 9999
TCP_PORT = 9998
hash_antigo = calcular_hash_arquivo("collector.py")


def enviar_alerta_tcp(payload_alerta):
    try:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        endereco_destino = (IP_SERVER, TCP_PORT)
        tcp_socket.connect(endereco_destino)
        mensagem = json.dumps(payload_alerta).encode('utf-8')
        tcp_socket.sendall(mensagem)

        dados_resposta = tcp_socket.recv(1024)
        if dados_resposta:
            resposta_json = json.loads(dados_resposta.decode('utf-8'))
            if resposta_json["type"] == "ACK":
                rtt = resposta_json["rtt_ms"]
                print(f"[ACK RECEBIDO] Servidor confirmou o recebimento do alerta!")
                print(f"[RTT MEDIDO] Tempo de Ida e Volta (Fim-a-Fim): {rtt} ms")

        tcp_socket.close()
        
    except Exception as e:
        print(f"[ERRO TCP] Não foi possível enviar alerta ou receber ACK: {e}")


def iniciar_sensor():

    global hash_antigo

    print("[*] Configurando o Sensor NetWatch...")

    # Cria o socket (AF_INET diz que eh IPv4 e SOCK_DGRAM diz que eh UDP)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Numero de sequencia dos pacotes (usado para verificar perda de pacotes UDP)
    seq_number = 0

    while True:
        print("[+] Coletando e enviando dados...")
        
        # A collect_system_number retorna um dicionario, porem o encode so funciona com string continua
        mensagem = json.dumps(collect_system_metrics(seq_number))
        endereco_destino = (IP_SERVER, UDP_PORT)

        hash_novo = calcular_hash_arquivo("collector.py")

        if(hash_antigo != hash_novo):
            print("ALERTA: Modificação detectada no arquivo crítico!")

            pacote_alerta = {
                "protocol": "NAP",
                "version": "1.0",
                "type": "ALERT",
                "sensor_id": SENSOR_ID,
                "timestamp": time.time(),
                "seq_number": 0,
                "payload": {
                "severity": "CRITICAL",
                "category": "FILE_INTEGRITY",
                "description": f"O arquivo collector.py foi modificado de {hash_antigo} para {hash_novo}"
                }
            }
            enviar_alerta_tcp(pacote_alerta)
            hash_antigo = hash_novo

        # Enviando os dados para o Server
        udp_socket.sendto(mensagem.encode('utf-8'), endereco_destino)

        seq_number+=1

        time.sleep(5)



if __name__ == "__main__":
    iniciar_sensor()