import socket
import threading
import time

TCP_PORT = 9998
UDP_PORT = 9999
HOST = '127.0.0.1'

def run_test_server():
    # 1. Setup UDP Listener (Connectionless)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((HOST, UDP_PORT))
    
    # 2. Setup TCP Listener (Orientado à Conexão)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Evita Address already in use
    tcp_sock.bind((HOST, TCP_PORT))
    tcp_sock.listen(5)
    
    print("[SERVER] Listeners ativos. Aguardando dados...")

    def handle_udp():
        data, addr = udp_sock.recvfrom(1024)
        print(f"[SERVER][UDP] Recebido de {addr}: {data.decode('utf-8')}")
        udp_sock.close()

    def handle_tcp():
        client_conn, addr = tcp_sock.accept() # Bloqueia até o Handshake TCP (SYN, SYN-ACK, ACK) concluir
        print(f"[SERVER][TCP] Conexão aceita de {addr}")
        data = client_conn.recv(1024)
        print(f"[SERVER][TCP] Recebido: {data.decode('utf-8')}")
        client_conn.sendall(b"ACK_TEST")
        client_conn.close()
        tcp_sock.close()

    threading.Thread(target=handle_udp, daemon=True).start()
    threading.Thread(target=handle_tcp, daemon=True).start()

def run_test_client():
    time.sleep(1) # Garante que o servidor subiu
    print("[CLIENT] Iniciando disparos de teste...")
    
    # Disparo UDP
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.sendto(b"PING_UDP", (HOST, UDP_PORT))
    udp_sock.close()
    
    # Disparo TCP
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.connect((HOST, TCP_PORT)) # Dispara o Handshake de 3 vias
    tcp_sock.sendall(b"PING_TCP")
    response = tcp_sock.recv(1024)
    print(f"[CLIENT][TCP] Resposta do Servidor: {response.decode('utf-8')}")
    tcp_sock.close()

if __name__ == '__main__':
    server_thread = threading.Thread(target=run_test_server, daemon=True)
    server_thread.start()
    
    # Roda o cliente na thread principal
    run_test_client()
    time.sleep(1)
    print("[*] Sanity check de sockets concluído.")