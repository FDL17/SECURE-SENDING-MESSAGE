import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class enkripsi:
    def generate_key_pair(cls):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    def encrypt_message(cls, public_key, message):
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        encrypted_message = cipher.encrypt(message.encode())
        return encrypted_message
    def decrypt_message(cls, private_key, encrypted_message):
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_message = cipher.decrypt(encrypted_message).decode()
        return decrypted_message

class server:
    def receiver(cls, server):
        s_receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_receiver.bind(server)
        s_receiver.listen()
        print("listening...")
        client, addr = s_receiver.accept()
        print(f"Connected {addr[0]} via port {addr[1]}")
        
        msg = client.recv(1024)
        if msg.decode() == "REQUEST KEY":
            print("accepted requesting key")
            e = enkripsi()
            print("generating key...")
            private, public = e.generate_key_pair()
            print("="*10, "publickey", "="*10)
            print(public)
            print("="*33)

            print("sending key..")
            client.send(public)
            msg = client.recv(1024)
            print("received message")
            print("=== message ===")
            print(e.decrypt_message(private, msg))
            
        client.close()
        s_receiver.close()

    def sender(cls, server):
        s_sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        e = enkripsi()
        msg = lambda x: f"halo {x}"
        try:
            print("connecting server")
            s_sender.connect(server)
            print("sending request public key... ")
            s_sender.send("REQUEST KEY".encode())
            print("receiving key...")
            publickey  = s_sender.recv(1024)
            print("="*10, "publickey", "="*10)
            print(publickey)
            print("="*33)
            print("sending message...")
            s_sender.send(e.encrypt_message(publickey, msg))
            print("done")

            
        except ConnectionRefusedError:
            print("Connection refused.")

        s_sender.close()

if __name__ == "__main__":

    s = server()
    i = int(input(">"))
    ip = ("127.0.0.1", 9999)
    print("1. RECEIVER \n 2. SENDER")
    if i == 1:
        s.receiver(ip)
    elif i == 2:
        s.sender(ip)
    else:
        print("Pilihan tidak valid.")
