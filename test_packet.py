from scapy.all import *
from scapy.contrib.modbus import *

packet = IP(dst="10.103.152.8") / TCP(dport=502) / ModbusADURequest(transId=1) / ModbusPDU01ReadCoilsRequest(startAddr=0x0000, quantity=0x0001)

send(packet)
print("Packet sent")
