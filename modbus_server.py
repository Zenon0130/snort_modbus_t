import socket
from scapy.all import *
from scapy.contrib.modbus import *

def handle_modbus_request(data):
    modbus_request = ModbusADURequest(data)
    print("Received Modbus request:", modbus_request.show(dump=True))

    modbus_response = ModbusADUResponse(transId=modbus_request.transId) / ModbusPDU01ReadCoilsResponse()
    response_data = bytes(modbus_response)
    return response_data

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 502))
s.listen(5)
print("Server is listening on port 502...")

while True:
    client, addr = s.accept()
    print('Connected by', addr)

    while True:
        data = client.recv(1024)
        if not data:
            print('No data received. Closing connection.')
            break

        print('Received data:', repr(data))
        response = handle_modbus_request(data)
        print('Sending response:', repr(response))
        client.send(response)

    client.close()
    print('Connection closed.')
