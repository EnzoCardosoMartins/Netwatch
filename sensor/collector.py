import psutil
import time
import uuid

# Gera um ID unico
SENSOR_ID = str(uuid.uuid4())[:8]

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
            "open_ports": open_ports,
            "active_connections": active_connections
        }
    }
    

    return package_nap