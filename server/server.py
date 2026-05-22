import socket
import threading

IP_LISTEN = "127.0.0.1"
UDP_PORT = 9999
TCP_PORT = 9998


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

    pass

def listen_tcp():
    print(f"[*] Thread TCP ativa na porta {TCP_PORT}")

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind((IP_LISTEN, TCP_PORT))
    tcp_socket.listen(5)
    while True:
        conexao_cliente, endereco_cliente = tcp_socket.accept()
        dados_bytes = conexao_cliente.recv(4096)
        mensagem = dados_bytes.decode('utf-8')
        print(f"\n[TCP] Recebido de {endereco_cliente}: {mensagem}")
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