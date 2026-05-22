import psutil
import time
import uuid
import hashlib
import os

# Gera um ID unico
SENSOR_ID = str(uuid.uuid4())[:8]



def calcular_hash_arquivo(arq_path):
    """
    Abre um arquivo do SO em modo binário, lê em blocos para gerenciar o buffer
    e retorna o hash SHA-256 correspondente.
    """
    if not os.path.exists(arq_path):
        return "FILE_DOES_NOT_EXIST"
    
    sha256 = hashlib.sha256()

    try:
        with open(arq_path, "rb") as f:
            while True:
                # Lê um bloco de 4096 bytes do arquivo
                bloco = f.read(4096)
                if not bloco:
                    break # Se o bloco vier vazio, chegamos ao fim do arquivo (EOF)
                
                # Alimenta o algoritmo SHA-256 com os bytes lidos
                sha256.update(bloco)

        return sha256.hexdigest()
    
    except Exception as e:
        return f"ERRO_LEITURA: {str(e)}"
    




def collect_system_metrics(seq_number):
    """
    Acessa o Subsistema do Kernel via psutil para ler o hardware
    e retorna os dados estruturados.
    """

    #Coleta o uso da CPU sem travar a execucao
    cpu = psutil.cpu_percent(interval=None)

    #Coleta o uso da RAM
    ram = psutil.virtual_memory().percent

    net_connections = psutil.net_connections(kind="inet")

    # Quantidade de conexoes ativas
    active_connections = len(net_connections)

    # Quantidade de portas abertas
    open_ports = []

    for conn in net_connections:

        # A porta tem que estra com o status LISTENING
        if(conn.status == psutil.CONN_LISTEN):
            port = conn.laddr.port

            # Verifica se a porta esta repetida
            if port not in open_ports:
                open_ports.append(port)


    package_nap ={
        "protocol": "NAP",
        "version": "1.0",
        "type": "TELEMETRY",
        "sensor_id": SENSOR_ID,
        "timestamp": time.time(),
        "seq_number": seq_number,
        "payload": {
            "cpu_percent": cpu,
            "ram_percent": ram,
            "open_ports": sorted(open_ports),
            "active_connections": active_connections,
            "file_hashes": {
                "meu_arquivo": calcular_hash_arquivo("collector.py")
            }
        }
    }
    

    return package_nap

