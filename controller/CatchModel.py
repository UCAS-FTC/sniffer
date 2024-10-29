import scapy
from OpenSSL import SSL
from PyQt6.QtCore import QObject, pyqtSignal
from scapy.all import *
from scapy.all import sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy import arch
from scapy.layers.tls.record import TLS

from custom.packetAnalyser import Analyser


class CatchServer(QObject, Analyser):
    def __init__(self):
        super(CatchServer, self).__init__()

    _interface = None
    _is_active = False
    _is_clear = False
    isQuit = False
    _counter = 0
    sniff_filter = ""

    # 捕获包信号
    current_packet = pyqtSignal(scapy.layers.l2.Ether) # 用于更新textEdit
    packet_captured = pyqtSignal(int, str, str, str, str, int, str)  # 新增信号，用于更新表格

    def start_sniffing(self):
        index = 0
        while True:
            if self.isQuit:
                break
            if self._is_clear:
                index = 0
                self._is_clear = False
            if self.isActive:
                try:
                    self._counter = 0
                    # sniff_filter = "ether proto 0x0800 or ether proto 0x86dd or ether proto 0x11 or ether proto 0x0806"
                    sniff_filter = "tcp"
                    # 捕获一个数据包
                    packets = sniff(count=1, filter=sniff_filter, iface=self._interface)

                    # 处理数据包
                    for pkt in packets:
                        # 初始化数据
                        index += 1
                        capture_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                        src_ip = dst_ip = ""
                        protocol = ""
                        length = len(pkt)
                        details = pkt.summary()

                        # 源地址与目的地址
                        if pkt.haslayer(IP):
                            src_ip = pkt[IP].src
                            dst_ip = pkt[IP].dst
                        elif pkt.haslayer(IPv6):
                            src_ip = pkt[IPv6].src
                            dst_ip = pkt[IPv6].dst

                        # 解析协议
                        self.DataLinkLayer = ""  # 数据链路层
                        self.NetworkLayer = ""  # 网络层
                        self.TransportLayer = ""  # 传输层
                        self.PresentationLayer = ""  # 表示层
                        self.ApplicationLayer = ""  # 应用层
                        protocol = self.analysePacket(pkt)
                        if "200 OK" in details:
                            protocol = "HTTP"

                        # 发射信号更新表格
                        self.packet_captured.emit(index, capture_time, src_ip, dst_ip, protocol, length, details)
                        self.current_packet.emit(packets[0])
                except Exception as e:
                    print(f"Error occurred: {e}")

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
