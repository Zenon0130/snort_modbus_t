import socket
from scapy.all import *
from scapy.contrib.modbus import *
import logging

logging.basicConfig(level=logging.DEBUG)

def handle_modbus_request(data):
    try:
        modbus_request = ModbusADURequest(data)
        logging.debug("Received Modbus request: %s", modbus_request.show(dump=True))

        modbus_response = ModbusADUResponse(transId=modbus_request.transId) / ModbusPDU01ReadCoilsResponse()
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
                response = handle_modbus_request(data)
                logging.debug('Sending response: %s', repr(response))
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
    logging.info("Socket closed."
