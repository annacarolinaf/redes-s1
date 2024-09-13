from iputils import *
from ipaddress import ip_address, ip_network
from socket import IPPROTO_ICMP, IPPROTO_TCP
from ipaddress import ip_address, ip_network
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama) #Leitura do cabeçalho IPv4
        
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            proto = IPPROTO_TCP
            ttl-=1 #O TTL é decrementado em 1 para evitar que o pacote fique indefinidamente circulando pela rede

            if ttl: #Caso o pacote ainda possa realizar um salto

                #O cabeçalho IPv4 é recriado com o novo valor do TTL e outras informações,
                #  como o protocolo e os endereços de origem e destino
                datagrama_corrigido = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(payload), identification, flags+frag_offset, ttl, proto, 0)
                datagrama_corrigido += str2addr(src_addr)
                datagrama_corrigido += str2addr(dst_addr)

                #Recalculo do checksum
                #O checksum é um mecanismo de verificação de integridade usado em vários protocolos de comunicação de rede
                # Seu propósito principal é detectar erros que possam ter ocorrido durante a transmissão ou armazenamento dos dados.
                checksum = calc_checksum(datagrama_corrigido)

#               
#               #O pacote é reconstituído com o checksum corrigido e o payload original.
                datagrama = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(payload), identification, flags+frag_offset, ttl, proto, checksum) 
                datagrama += str2addr(src_addr)
                datagrama += str2addr(dst_addr)
                datagrama += payload #Conteúdo do pacote

            #Se o TTL chegar a zero, o roteador não pode mais encaminhar o pacote. 
            # Ele deve retornar uma mensagem de erro ICMP do tipo "Time Exceeded".
            else:
                proto = IPPROTO_ICMP  

                checksum = calc_checksum(struct.pack('!BBHI', 0x0b, 0, 0, 0) + datagrama[:28])

                mensagem = struct.pack('!BBHI', 0x0b, 0, checksum, 0) + datagrama[:28] 

                datagrama_corrigido = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(mensagem), identification, flags+frag_offset, 64, proto, 0)   
                datagrama_corrigido += str2addr(self.meu_endereco) 
                datagrama_corrigido +=str2addr(src_addr)

                #Recalculo do checksum
                checksum = calc_checksum(datagrama_corrigido)

                datagrama = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(mensagem), identification, flags+frag_offset, 64, proto, checksum)
                datagrama += str2addr(self.meu_endereco)
                datagrama += str2addr(src_addr) 
                datagrama += mensagem
               
                next_hop = self._next_hop(self.meu_endereco)

            self.enlace.enviar(datagrama, next_hop)

    #TERCEIRA ETAPA
    #PRÓXIMO SALTO
    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        next_hop = None #Inicialmnete o IP do próximo salto é nulo
        maior_prefixo = 0 
        ip_destino = ip_address(dest_addr) #Descobre o próximo IP
        for valor in self.tabela_encaminhamento:
            ip_rede = ip_network(valor[0]) #Conversão pra um objeto de rede
            tam_prefixo = int(valor[0].split('/')[1]) #A variável armazena o tamanho do prefixo
            if (ip_destino in ip_rede and tam_prefixo >= maior_prefixo):
                next_hop = valor[1]
                maior_prefixo = tam_prefixo
        return next_hop
       
    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco


    #PRIMEIRA ETAPA
    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.

        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback


    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr = 0x45, 0, 20+len(segmento), 0, 0, 64, 6, 0, self.meu_endereco

        datagrama_corrigido = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum) 
        datagrama_corrigido +=  str2addr(src_addr) 
        datagrama_corrigido +=  str2addr(dest_addr)

        checksum = calc_checksum(datagrama_corrigido)

        datagrama = struct.pack('!BBHHHBBH', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum) 
        datagrama +=  str2addr(src_addr) 
        datagrama += str2addr(dest_addr) 
        datagrama += segmento

        self.enlace.enviar(datagrama, next_hop)