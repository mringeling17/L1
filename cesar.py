import sys
from scapy.all import *

def cifrado_cesar(mensaje, corrimiento):
    cifrado = ""
    for caracter in mensaje:
        if caracter.isalpha():
            ascii_offset = ord('a') if caracter.islower() else ord('A')
            cifrado += chr((ord(caracter) - ascii_offset + corrimiento) % 26 + ascii_offset)
        else:
            cifrado += caracter
    return cifrado

def enviar_ping_con_payload(mensaje_cifrado):
    ip_destino = "192.168.1.1"
    paquete = IP(dst=ip_destino)/ICMP()/mensaje_cifrado
    send(paquete)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: sudo python3 cesar.py 'Mensaje a cifrar' corrimiento")
        sys.exit(1)
    
    mensaje = sys.argv[1]
    corrimiento = int(sys.argv[2])
    
    mensaje_cifrado = cifrado_cesar(mensaje, corrimiento)
    print("Mensaje cifrado:", mensaje_cifrado)
    enviar_ping_con_payload(mensaje_cifrado)
