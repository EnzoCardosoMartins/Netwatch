import psutil
import time


def coletar_metricas_hardware():
    """
    Acessa o Subsistema do Kernel via psutil para ler o hardware
    e retorna os dados estruturados.
    """

    #Coleta o uso da CPU sem travar a execucao
    cpu = psutil.cpu_percent(interval=None)

    #Coleta o uso da RAM
    ram = psutil.virtual_memory().percent

    dados_hardware = {
        "cpu_percent": cpu,
        "ram_percent": ram
    }

    return dados_hardware