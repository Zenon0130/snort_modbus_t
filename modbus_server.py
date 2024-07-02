import socket
from scapy.all import *
from scapy.contrib.modbus import *
import logging

logging.basicConfig(level=logging.DEBUG)

def handle_modbus_request(data):
    try:
        # 解析 Modbus 請求
        modbus_request = ModbusADURequest(data)
        logging.debug("Received Modbus request: %s", modbus_request.show(dump=True))
        
        # 構建 Modbus 回應
        if modbus_request.haslayer(ModbusPDU01ReadCoilsRequest):
            response_pdu = ModbusPDU01ReadCoilsResponse(bits=[1]*modbus_request[ModbusPDU01ReadCoilsRequest].count)
        elif modbus_request.haslayer(ModbusPDU15WriteFileRecordRequest):
            # 處理寫文件記錄請求，這裡我們假設處理成功
            response_pdu = ModbusPDUWriteFileRecordResponse(recordData=modbus_request[ModbusPDU15WriteFileRecordRequest].recordData)
        else:
            response_pdu = ModbusPDUException(ExceptionCode=0x01)  # 示範性的異常回應

        modbus_response = ModbusADUResponse(
            transId=modbus_request.transId,
            protoId=modbus_request.protoId,
            len=len(response_pdu)+1,
            unitId=modbus_request.unitId
        ) / response_pdu
        response_data = bytes(modbus_response)
        return response_data
    except Exception as e:
        logging.error("Error handling Modbus request: %s", e)
        return b''

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 502))
s.listen(5)
logging.info("Server is listening on port 502...")

try:
    while True:
        client, addr = s.accept()
        logging.info('Connected by %s', addr)

        try:
            while True:
                data = client.recv(1024)
                if not data:
                    logging.info('No data received. Closing connection.')
                    break

                logging.debug('Received data: %s', repr(data))
                
                # 確保收到的數據是有效的 Modbus 封包
                if len(data) < 7:  # 最小 Modbus TCP 封包長度
                    logging.warning("Received invalid Modbus packet, too short.")
                    break

                response = handle_modbus_request(data)
                logging.debug('Sending response: %s', repr(response))
                
                if not response:
                    logging.error("Failed to generate a valid Modbus response.")
                    break

                client.send(response)
        except Exception as e:
            logging.error("Error during communication with %s: %s", addr, e)
        finally:
            client.close()
            logging.info('Connection closed.')
except KeyboardInterrupt:
    logging.info("Server is shutting down.")
finally:
    s.close()
    logging.info("Socket closed.")
