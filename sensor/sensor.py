import psutil
import os
import socket
import time
import json
from collector import collect_system_metrics

SERVIDOR_IP = "127.0.0.1"
PORTA_UDP = 9999

def iniciar_sensor():
    print("[*] Configurando o Sensor NetWatch...")

    # Cria o socket (AF_INET diz que eh IPv4 e SOCK_DGRAM diz que eh UDP)
    meu_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Numero de sequencia dos pacotes (usado para verificar perda de pacotes UDP)
    seq_number = 0

    while True:
        print("[+] Coletando e enviando dados...")
        
        # A collect_system_number retorna um dicionario, porem o encode so funciona com string continua
        mensagem = json.dumps(collect_system_metrics(seq_number))
        endereco_destino = (SERVIDOR_IP, PORTA_UDP)

        meu_socket.sendto(mensagem.encode('utf-8'), endereco_destino)

        seq_number+=1

        time.sleep(5)



if __name__ == "__main__":
    iniciar_sensor()