#!/usr/bin/env python3

import sys
from scapy.all import rdpcap, ICMP

# Frecuencias de letras en el idioma español
frecuencias = {
    'a': 0.1253, 'b': 0.0142, 'c': 0.0468, 'd': 0.0586,
    'e': 0.1368, 'f': 0.0069, 'g': 0.0177, 'h': 0.0070,
    'i': 0.0625, 'j': 0.0044, 'k': 0.0002, 'l': 0.0497,
    'm': 0.0315, 'n': 0.0671, 'o': 0.0868, 'p': 0.0251,
    'q': 0.0088, 'r': 0.0687, 's': 0.0798, 't': 0.0463,
    'u': 0.0293, 'v': 0.0114, 'w': 0.0001, 'x': 0.0021,
    'y': 0.0101, 'z': 0.0047
}

def descifrado_cesar(mensaje, corrimiento):
    descifrado = ''
    for caracter in mensaje:
        if caracter.isalpha():
            # Determinar si es mayúscula o minúscula
            ascii_offset = ord('A') if caracter.isupper() else ord('a')
            descifrado += chr((ord(caracter) - ascii_offset - corrimiento) % 26 + ascii_offset)
        else:
            descifrado += caracter
    return descifrado

def extraer_mensaje_cifrado(pcap_file):
    packets = rdpcap(pcap_file)
    mensaje_cifrado = ""
    for packet in packets:
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            mensaje_cifrado += chr(packet[ICMP].load[8])
    return mensaje_cifrado

def calcular_puntaje(mensaje):
    puntaje = 0
    for letra in mensaje:
        if letra.lower() in frecuencias:
            puntaje += frecuencias[letra.lower()]
    return puntaje

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Uso: sudo python3 mitm.py captura.pcapng")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    mensaje_cifrado = extraer_mensaje_cifrado(pcap_file)
    
    max_puntaje = -1
    mensaje_probablemente_original = ""

    for corrimiento in range(1, 26):
        mensaje_descifrado = descifrado_cesar(mensaje_cifrado, corrimiento)
        puntaje_actual = calcular_puntaje(mensaje_descifrado)
        
        if puntaje_actual > max_puntaje:
            max_puntaje = puntaje_actual
            mensaje_probablemente_original = mensaje_descifrado

    for corrimiento in range(26):    
        mensaje_descifrado = descifrado_cesar(mensaje_cifrado, corrimiento)
        if mensaje_descifrado == mensaje_probablemente_original:
            print(f"\033[92m{corrimiento}: {mensaje_descifrado}\033[0m")
        else:
            print(f"{corrimiento}: {mensaje_descifrado}")
