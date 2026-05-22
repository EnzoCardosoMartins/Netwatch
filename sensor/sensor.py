import psutil
import os
import socket
import time

SERVIDOR_IP = "127.0.0.1"
PORTA_UDP = 9999

def iniciar_sensor():
    print("[*] Configurando o Sensor NetWatch...")

    # Cria o socket (AF_INET diz que eh IPv4 e SOCK_DGRAM diz que eh UDP)
    meu_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        print("[+] Coletando e enviando dados...")
        
        mensagem = "Teste"
        endereco_destino = (SERVIDOR_IP, PORTA_UDP)

        
        meu_socket.sendto(mensagem.encode('utf-8'), endereco_destino)

        time.sleep(5)



if __name__ == "__main__":
    iniciar_sensor()