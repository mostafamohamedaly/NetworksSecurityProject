import socket
from Crypto.PublicKey import RSA
import uuid
import struct
from Crypto.Cipher import PKCS1_OAEP
import os
import sys

import click


SERVER_IP = '0.0.0.0'
SERVER_PORT = 5678
MESSAGE_TYPES = [b'PUB', b'ENK', b'TRM', b'EML', b'ENC', b'DEC']
byte_size = 4
HEADER_LENGTH = 16 + 3 + byte_size


def decrypt_data(encrypted_data, private_key_bytes):
    # Load the private key
    private_key = RSA.import_key(private_key_bytes)

    # Create the cipher object
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data


def receive_data(conn):
    data = conn.recv(HEADER_LENGTH)
    if data == b'':
        return None, None, None
    unique_id = uuid.UUID(bytes=data[:16])
    data_type = data[16:19]
    if data_type in MESSAGE_TYPES:
        received_value = struct.unpack("!I", data[19:])[0]
        data = b''
        if received_value > 0:
            data = conn.recv(received_value)
    return unique_id, data_type, data


def generate_rsa_key():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    # write key pair to file
    # with open('KeyPair.key', 'w') as f:
    #     f.write((public_key).decode().replace('\n', ''))
    #     f.write(f'\n')
    #     f.write((private_key).decode().replace('\n', ''))
    return public_key, private_key


import datetime
from colorama import init, Fore, Style
init()


def print_time_color(message, color=Style.RESET_ALL, end=''):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] " + color + f"{message}" + Style.RESET_ALL + end)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_IP, SERVER_PORT))
        print_time_color('Server is listening', Fore.YELLOW)
        s.listen(1)
        conn, addr = s.accept()
        print_time_color(f'Connection accepted from :{addr}', Fore.GREEN)
        public_key, private_key = generate_rsa_key()
        with conn:
            while (True):
                # aes_key = b''
                # data = conn.recv(HEADER_LENGTH)
                # if len(data) != HEADER_LENGTH:
                #     continue
                # if not data:
                #     break
                _, data_type, data = receive_data(conn)
                if data_type is None and data is None:
                    break
                if data_type == b'PUB':
                    print_time_color("Generated key pair: ", Fore.BLUE)
                    print(public_key.decode())
                    print(private_key.decode())
                    conn.sendall(b'PUB' + struct.pack("!I",
                                 len(public_key)) + public_key)
                    print_time_color('Public key sent!', Fore.GREEN)
                elif data_type == b'ENK':
                    print_time_color('Encrypted key received: ', Fore.CYAN)
                    print(f'{data}')
                    aes_key = decrypt_data(data, private_key)
                    conn.sendall(
                        b'PUB' + struct.pack("!I", len(aes_key)) + aes_key)
                    print_time_color('Decrypted key sent: ',
                                     Fore.GREEN, f'{aes_key.decode()}')
                elif data_type == b'EML':
                    print_time_color(
                        'Sent emails to the following addresses: ', Fore.CYAN)
                    print(f'{data.decode()}')
                elif data_type == b'ENC':
                    num_of_files = struct.unpack("!I", data)[0]
                    print_time_color(
                        f'Encrypting {num_of_files} files', Fore.MAGENTA)
                    with click.progressbar(length=num_of_files) as bar:
                        for i in range(num_of_files):
                            _, data_type, data = receive_data(conn)
                            bar.update(1)
                elif data_type == b'DEC':
                    num_of_files = struct.unpack("!I", data)[0]
                    print_time_color(
                        f'Decrypting {num_of_files} files', Fore.GREEN)
                    with click.progressbar(length=num_of_files) as bar:
                        for i in range(num_of_files):
                            _, data_type, data = receive_data(conn)
                            bar.update(1)
                elif data_type == b'TRM':
                    break
                # with open('recived_key', 'ab') as f:
                #     f.write(data)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_time_color('Interrupted', Fore.RED)
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
