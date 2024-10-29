import scapy
from PyQt6.QtCore import QObject, pyqtSignal
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP
from scapy import arch

from custom.packetAnalyser import getIPLayerAddr, getHighestProtocol, getARPLayerAddr


class CatchServer(QObject):
    def __init__(self):
        super(CatchServer, self).__init__()

    _interface = None
    _is_active = False
    isQuit = False
    _counter = 0
    sniff_filter = ""

    def start_sniffing(self, sniff_filter):
        print( self._interface)
        while True:
            print("等待捕获数据包...")
            # 捕获一个数据包
            packets = sniff(count=1, filter=sniff_filter, iface=self._interface)
            # 处理捕获的数据包
            for packet in packets:
                # 打印数据包摘要
                print(packet.summary())
                # 如果数据包是IP数据包，打印源IP和目标IP
                if packet.haslayer(IP):
                    ip_layer = packet.getlayer(IP)
                    print(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")

    @property
    def interFace(self) -> scapy.arch.windows.NetworkInterface_Win:
        return self._interface

    @interFace.setter
    def interFace(self, value: scapy.arch.windows.NetworkInterface_Win) -> None:
        self._interface = value

    @property
    def isActive(self) -> bool:
        return self._is_active

    @isActive.setter
    def isActive(self, value: bool) -> None:
        self._is_active = value