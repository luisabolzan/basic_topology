#!/usr/bin/env python3
import sys
from scapy.all import *
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
from myTunnel_header import MyTunnel  # Certifique-se de que MyTunnel está corretamente importado

TYPE_COUNTER_HEADER = 0x9999
TYPE_MYTUNNEL = 0x1212
TYPE_IPV4 = 0x0800

# Definindo o cabeçalho CounterHeader
class CounterHeader(Packet):
    name = "CounterHeader"
    fields_desc = [
        XIntField("cont_value", 0)  # Definindo o campo 'cont_value' com valor inicial 0
    ]

# Realizando os binds entre as camadas
bind_layers(Ether, CounterHeader, type=0x9999)  # Ethernet tipo 0x9999 associando a CounterHeader
bind_layers(CounterHeader, IP)  # CounterHeader agora associa com IPv4Header

def handle_pkt(pkt):
    # Verificando se o pacote contém o cabeçalho CounterHeader
    if CounterHeader in pkt:
        
        pkt.show2()
        sys.stdout.flush()

def main():
    # Encontrando a interface de rede para sniffing (eth0 ou s0)
    iface = next((i for i in get_if_list() if 'eth0' in i or 's0' in i), None)
    if not iface:
        print("Cannot find eth0 or s0 interface")
        return
    
    # Exibindo a interface em que vamos fazer o sniffing
    print(f"Sniffing on {iface}")
    
    # Iniciando o sniffing dos pacotes
    sniff(iface=iface,
          prn=lambda x: handle_pkt(x),
          filter="ether proto 0x9999 or ether proto 0x1212")  # Filtro para capturar pacotes do tipo desejado

if __name__ == '__main__':
    main()
