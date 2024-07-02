import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(('0.0.0.0', 502))

s.listen(5)

while True:
    client, addr = s.accept()
    print('Connected by', addr)

    while True:
        data = client.recv(1024)
        if not data:
            break

        print('Received', repr(data))

    client.close()
