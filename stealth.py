#!/usr/bin/env python3

import sys
from scapy.all import IP, ICMP, send

def cifrado_cesar(mensaje, corrimiento):
    cifrado = ''
    for caracter in mensaje:
        if caracter.isalpha():
            # Determinar si es mayúscula o minúscula
            ascii_offset = ord('A') if caracter.isupper() else ord('a')
            cifrado += chr((ord(caracter) - ascii_offset + corrimiento) % 26 + ascii_offset)
        else:
            cifrado += caracter
    return cifrado

def enviar_ping_stealth(ip_destino, char, ip_id, icmp_id, icmp_seq):
    payload_constante = b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' \
                        b'\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f' \
                        b'\x30\x31\x32\x33\x34\x35\x36\x37'
    
    # Mantener los primeros 8 bytes del payload ICMP
    payload_inicial = b'\x26\x4a\x00\x00\x00\x00\x00\x00'
    
    # Rellenar el resto del payload con la letra cifrada y el payload constante
    payload = payload_inicial + char.encode() + payload_constante[len(char):]

    paquete = IP(dst=ip_destino, ttl=64, id=ip_id, flags='DF')/ICMP(id=icmp_id, seq=icmp_seq)/payload
    send(paquete)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Uso: sudo python3 stealth.py 'Mensaje a cifrar' corrimiento")
        sys.exit(1)
    
    mensaje = sys.argv[1]
    corrimiento = int(sys.argv[2])
    
    mensaje_cifrado = cifrado_cesar(mensaje, corrimiento)
    
    ip_id = 0x2664
    icmp_id = 0x2283
    icmp_seq = 1
    
    for char in mensaje_cifrado:
        enviar_ping_stealth('192.168.1.1', char, ip_id, icmp_id, icmp_seq)
        print(f"Mensaje cifrado enviado: {char}")
        
        # Incrementar la identificación y número de secuencia para mantener coherencia
        ip_id += 1
        icmp_seq += 1