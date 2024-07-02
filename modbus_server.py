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

while True:
    client, addr = s.accept()
    print('Connected by', addr)

    while True:
        data = client.recv(1024)
        if not data:
            break

        print('Received', repr(data))
        response = handle_modbus_request(data)
        client.send(response)

    client.close()
