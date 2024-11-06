import scapy
from OpenSSL import SSL
from PyQt6.QtCore import QObject, pyqtSignal
from scapy.all import *
from scapy.all import sniff
from scapy.contrib.igmp import IGMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTP, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import ARP, Ether
from scapy import arch
from scapy.layers.tls.record import TLS
import dns.message
import dns.query

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
    _info = ""

    # 捕获包信号
    current_packet = pyqtSignal(scapy.layers.l2.Ether) # 用于更新textEdit
    packet_captured = pyqtSignal(int, str, str, str, str, int, str, str)  # 新增信号，用于更新表格
    packet_raw = pyqtSignal(PacketList) # 用于重新sniff

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
                    # 捕获一个数据包
                    if self.sniff_filter == "":
                        packets = sniff(count=1, iface=self._interface, timeout=1)
                    else:
                        packets = sniff(count=1, filter=self.sniff_filter, iface=self._interface, timeout=1)

                    # 处理数据包
                    for pkt in packets:
                        index += 1
                        length = len(pkt)
                        details = pkt.summary()
                        info = ""

                        src_ip = self.Addr(pkt)[0]
                        dst_ip = self.Addr(pkt)[1]

                        # 时间戳
                        timestamp = pkt.time
                        capture_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

                        # 解析协议
                        self.DataLinkLayer = ""  # 数据链路层
                        self.NetworkLayer = ""  # 网络层
                        self.TransportLayer = ""  # 传输层
                        self.PresentationLayer = ""  # 表示层
                        self.ApplicationLayer = ""  # 应用层
                        protocol = self.analysePacket(pkt)
                        if "200 OK" in details:
                            protocol = "HTTP"

                        self._info = self.Info(pkt, protocol)
                        if "mDNS" in details:
                            protocol = "MDNS"
                        if protocol == "Ether":
                            protocol = str(hex(pkt[Ether].type))

                        # 发射信号更新表格
                        self.packet_captured.emit(index, capture_time, src_ip, dst_ip, str(protocol), length, details, self._info)
                        self.current_packet.emit(packets[0])
                        self.packet_raw.emit(packets)
                except Exception as e:
                    print(f"Error occurred: {e}")
    def Addr(self, pkt):
        details = pkt.summary()
        info = ""
        src_ip = ""
        dst_ip = ""

        # 源地址与目的地址
        if pkt.haslayer(ARP):
            src_ip = pkt[Ether].src
            dst_ip = pkt[Ether].dst
        elif pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            src_ip = pkt[Ether].src
            dst_ip = pkt[Ether].dst

        # 广播地址
        if src_ip == "ff:ff:ff:ff:ff:ff":
            src_ip = "Broadcast"
        if dst_ip == "ff:ff:ff:ff:ff:ff":
            dst_ip = "Broadcast"

        return src_ip, dst_ip

    def Info(self, pkt, protocol) -> str:
        details = pkt.summary()
        info = ""

        # 处理详细数据
        if protocol == "TCP":
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            info += str(src_port) + " -> " + str(dst_port) + " "
            # 提取序列号和确认号
            seq_number = pkt[TCP].seq
            ack_number = pkt[TCP].ack
            flag = pkt[TCP].flags
            temp = ""
            if flag.P == 1:
                temp += "PSH"
            if flag.A == 1 and temp == "":
                temp += "ACK"
            elif flag.A == 1:
                temp += ", ACK"
            if flag.S == 1 and temp == "":
                temp += "SYN"
            elif flag.S == 1:
                temp += ", SYN"
            if flag.U == 1 and temp == "":
                temp += "URG"
            elif flag.U == 1:
                temp += ", URG"
            if flag.F == 1 and temp == "":
                temp += "FIN"
            elif flag.F == 1:
                temp += ", FIN"
            if flag.R == 1 and temp == "":
                temp += "RST"
            elif flag.R == 1:
                temp += ", RST"
            info += "[" + temp + "] Seq=" + str(seq_number) + " "
            if flag.A == 1:
                info += "Ack=" + str(ack_number) + " "
            info += "Win=" + str(pkt[TCP].window) + " Len=" + str(len(pkt[TCP].payload))
        elif protocol == "UDP":
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            info += str(src_port) + " -> " + str(dst_port) + " "
            info += " Len=" + str(len(pkt[UDP].payload))
        elif protocol == "ARP":
            arp_layer = pkt[ARP]
            # 检查操作类型
            if arp_layer.op == 1:  # ARP请求
                info = f"Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
            elif arp_layer.op == 2:  # ARP响应
                info = f"{arp_layer.pdst} is at {arp_layer.hwsrc}"
            else:
                info = "Unknown ARP operation"
        elif protocol == "ICMP":
            icmp_layer = pkt[ICMP]
            ip_layer = pkt[IP]
            # 检查 ICMP 类型
            if icmp_layer.type == 8:  # Echo Request
                info = f"Echo (ping) request id={icmp_layer.id} seq={icmp_layer.seq}"
            elif icmp_layer.type == 0:  # Echo Reply
                info = f"Echo (ping) reply id={icmp_layer.id} seq={icmp_layer.seq}"
            elif icmp_layer.type == 3:  # Destination Unreachable
                info = f"Destination Unreachable ({icmp_layer.code}) {ip_layer.dst}"
            else:
                info = f"ICMP Type {icmp_layer.type} Code {icmp_layer.code}"
        elif protocol == "ICMPv6" or "ICMPv6" in details:
            protocol = "ICMPv6"
            if pkt.haslayer(ICMPv6EchoRequest):
                icmp_layer = pkt[ICMPv6EchoRequest]
                ip_layer = pkt[IPv6]
                info = f"Echo Request id={icmp_layer.id} seq={icmp_layer.seq}"
                info = f"{ip_layer.src} → {ip_layer.dst}: {info}"
            elif pkt.haslayer(ICMPv6EchoReply):
                icmp_layer = pkt[ICMPv6EchoReply]
                ip_layer = pkt[IPv6]
                info = f"Echo Reply id={icmp_layer.id} seq={icmp_layer.seq}"
                info = f"{ip_layer.src} → {ip_layer.dst}: {info}"
            elif pkt.haslayer(ICMPv6ND_RA):
                ip_layer = pkt[IPv6]
                info = f"Router Advertisement from {ip_layer.src}:"
            elif pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
                ip_layer = pkt[IPv6]
                info = f"Neighbor Solicitation for {ip_layer.dst} from {ip_layer.src}:"
            else:
                ip_layer = pkt[IPv6]
                info = f"Unknown Data from {ip_layer.src}"
        elif protocol == "DNS":
            dns_layer = pkt[DNS]

            info += "Standard query "
            if dns_layer.qr == 0:  # 查询
                info += str(hex(dns_layer.id)) + " "

                if dns_layer.qdcount > 0:
                    for qd in dns_layer.qd:
                        if qd.qtype == 1:
                            info += "A "
                        elif qd.qtype == 28:
                            info += "AAAA "
                        elif qd.qtype == 6:
                            info += "SOA "
                        elif qd.qtype == 5:
                            info += "CNAME "
                        info += str(qd.qname.decode()) + " "

            else:  # 响应
                info += "response " + str(hex(dns_layer.id)) + " "

                if dns_layer.qdcount > 0:
                    for qd in dns_layer.qd:
                        if qd.qtype == 1:
                            info += "A "
                        elif qd.qtype == 28:
                            info += "AAAA "
                        elif qd.qtype == 6:
                            info += "SOA "
                        elif qd.qtype == 5:
                            info += "CNAME "
                        info += str(qd.qname.decode()) + " "

                if dns_layer.ancount > 0:
                    for answer in dns_layer.an:
                        if answer.type == 1:
                            info += "A "
                        elif answer.type == 28:
                            info += "AAAA "
                        elif answer.type == 6:
                            info += "SOA "
                        elif answer.type == 5:
                            info += "CNAME "

                        if isinstance(answer.rdata, list):
                            for data in answer.rdata:
                                if answer.type == 1 or answer.type == 28:
                                    info += str(data) + " "
                                else:
                                    info += str(data.decode()) + " "
                        else:
                            if answer.type == 1 or answer.type == 28:
                                info += str(answer.rdata) + " "
                            else:
                                info += str(answer.rdata.decode()) + " "

                if dns_layer.nscount > 0:
                    for ns in dns_layer.ns:
                        if ns.type == 1:
                            info += "A "
                        elif ns.type == 28:
                            info += "AAAA "
                        elif ns.type == 6:
                            info += "SOA "
                        elif ns.type == 5:
                            info += "CNAME "

                        if ns.type == 1 or ns.type == 28:
                            info += str(ns.mname) + " "
                        else:
                            info += str(ns.mname.decode()) + " "
        elif protocol == "HTTP":
            raw_data = pkt[HTTP]
            # 检查状态码
            if "200 OK" in details:
                info = "HTTP 200 OK"

            else:
                if "GET" in details:
                    info += str("GET " + str(raw_data.Path.decode(errors='ignore')) + " " + str(
                        raw_data.Http_Version.decode(errors='ignore')))
                else:
                    info += str("POST " + str(raw_data.Path.decode(errors='ignore')) + " " + str(
                        raw_data.Http_Version.decode(errors='ignore')))
        elif protocol == "TLS/SSL":
            tls_layer = pkt[TLS]
            t = tls_layer.type
            if tls_layer.version > 0x0304 or tls_layer.version < 0x0301:
                info = "Continuation Data"
            elif t == 20:
                info = "Change Cipher Spec"
            elif t == 21:
                info = "Alert"
            elif t == 22:
                info = "Handshake"
                if "Client Hello" in details:
                    info = "Client Hello"
                elif "Server hello" in details:
                    info = "Server hello"
            else:
                info = "Application Data"
        elif protocol == "IGMP":
            igmp_layer = pkt[IGMP]

            # 提取 IGMP 信息
            igmp_type = igmp_layer.type
            if igmp_type == 22:
                info = "Membership Report group "
                info += str(igmp_layer.gaddr)
        elif protocol == "ARP":
            info = details.replace("Ether/ARP/ ", "")
        elif protocol == "Ether":
            info = "Ether II"
        return info

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
