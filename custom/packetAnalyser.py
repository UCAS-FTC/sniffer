from ftplib import FTP
from smtplib import SMTP

import packet
from OpenSSL import SSL
from scapy.contrib.igmp import IGMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.tls.record import TLS
from scapy.packet import Raw


class Analyser:
    # 各层次
    DataLinkLayer = "" # 数据链路层
    NetworkLayer = "" # 网络层
    TransportLayer = "" # 传输层
    PresentationLayer = "" # 表示层
    ApplicationLayer = "" # 应用层

    def analysePacket(self, packet) -> str:
        # 数据链路层
        if packet.haslayer(Ether):
            self.DataLinkLayer = "Ether"

        # 网络层
        if packet.haslayer(IP):
            self.NetworkLayer = "IPv4"
        elif packet.haslayer(IPv6):
            self.NetworkLayer = "IPv6"
        elif packet.haslayer(ARP):
            self.NetworkLayer = "ARP"

        # 传输层
        if packet.haslayer(TCP):
            self.TransportLayer = "TCP"
        elif packet.haslayer(UDP):
            self.TransportLayer = "UDP"
        elif packet.haslayer(ICMP):
            self.TransportLayer = "ICMP"
        elif packet.haslayer(IGMP):
            self.TransportLayer = "IGMP"
        elif self.NetworkLayer == "IPv6":
            highest_layer = ""
            for layer in packet.getlayer(Ether).layers():
                layer = str(layer)
                if "scapy.layers" in layer:
                    highest_layer = layer
            highest_layer_protocol = highest_layer.split('.')[-1][:-2]
            # 由于ICMPv6相关协议众多，为了便于显示，统一修改为ICMPv6
            if "ICMPv6" in highest_layer_protocol:
                self.TransportLayer = "ICMPv6"

        # 应用层
        if packet.haslayer(TLS) and self.TransportLayer == "TCP":
            self.ApplicationLayer = "TLS/SSL"
        elif packet.haslayer(DNS) and self.TransportLayer == "UDP":
            self.ApplicationLayer = "DNS"
        elif packet.haslayer(FTP):
            self.ApplicationLayer = "FTP"
        elif packet.haslayer(SMTP):
            self.ApplicationLayer = "SMTP"
        elif packet.haslayer(TCP) and (packet[TCP].dport == 80) and packet.haslayer(HTTP):
            self.ApplicationLayer = "HTTP"

        if self.ApplicationLayer != "":
            return self.ApplicationLayer
        if self.TransportLayer != "":
            return self.TransportLayer
        if self.NetworkLayer != "":
            return self.NetworkLayer
        if self.DataLinkLayer != "":
            return self.DataLinkLayer

    def getAllLayersDetail(self, pkt: Ether) -> dict:
        """
        :type pkt: scapy.layers.l2.Ether
        :rtype: a dict --> contains all layers' detail info like this:{
                "Ether": {xxx}
                "IP": {xxx}
                "TCP": {xxx}
                ...}
        :param pkt: a packet that you want to know its all layer info
        """
        packet_detail = {}
        layers = pkt.layers()
        for layer in layers:
            layer = str(layer)
            protocol = layer.split('.')[-1][:-2]
            packet_detail[protocol] = pkt.getlayer(protocol).fields.items()
        return packet_detail
