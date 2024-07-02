import socket
from scapy.all import *
from scapy.contrib.modbus import *
import logging

logging.basicConfig(level=logging.DEBUG)

def send_modbus_request():
    try:
        # 創建Modbus請求
        modbus_request = ModbusADURequest(transId=1, protoId=0, len=6, unitId=1) / ModbusPDU01ReadCoilsRequest(startAddr=0, quantity=0xFFFF)
        request_data = bytes(modbus_request)
        
        # 使用socket發送請求
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.103.152.8', 502))
        logging.info("Connected to server.")
        
        s.send(request_data)
        logging.debug('Sent Modbus request: %s', repr(request_data))
        
        response = s.recv(1024)
        logging.debug('Received response: %s', repr(response))
        
        modbus_response = ModbusADUResponse(response)
        logging.info("Modbus response: %s", modbus_response.show(dump=True))
        
        s.close()
        logging.info("Connection closed.")
    except Exception as e:
        logging.error("Error in client communication: %s", e)

if __name__ == "__main__":
    send_modbus_request()
