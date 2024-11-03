import os
import sys

import psutil
import scapy
from PyQt6.QtCore import QObject, QThread, pyqtSlot, pyqtSignal, Qt
from PyQt6.QtWidgets import QTableWidgetItem, QApplication, QTextEdit, QTreeWidget, QTreeWidgetItem, QFileDialog, \
    QMessageBox
from qt_material import apply_stylesheet
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.all import sniff
from scapy.all import conf

from ui.mainWindowInit import mainWindowInit
from controller.CatchModel import CatchServer
from custom.packetAnalyser import Analyser
from custom.filter import Filter
from controller.steamTraceController import steamTraceController


class MainWindowController(QObject, Analyser, Filter):
    def __init__(self):
        super(MainWindowController, self).__init__()
        self.trace_window_view = None
        self.main_window_view = mainWindowInit()
        self.main_window_view.show()

        # 暂存的包
        self.stored_packets = list()
        self.raw_packets = list()

        # 获取网卡设备并显示在下拉框中
        self.load_network_interfaces()

        # 创建新进程
        self.catch_thread = QThread()
        self.catch_server = CatchServer()

        # 连接信号和槽
        self.catch_server.packet_captured.connect(self.update_table)

        # 将服务绑定至线程
        self.catch_server.moveToThread(self.catch_thread)
        self.catch_thread.started.connect(self.catch_server.start_sniffing)
        self.catch_thread.start()

        # 对MainWindow中的功能进行绑定
        self.main_window_view.closeButton.clicked.connect(self.safeQuit)
        self.main_window_view.minButton.clicked.connect(self.main_window_view.showMinimized)
        self.main_window_view.startButton.clicked.connect(self.doCapture)
        self.main_window_view.stopButton.clicked.connect(self.doPause)
        self.main_window_view.restartButton.clicked.connect(self.doRestart)
        self.main_window_view.filterButton.clicked.connect(self.doFilter)
        self.main_window_view.openButton.clicked.connect(self.doOpen)
        self.main_window_view.downloadButton.clicked.connect(self.doSave)
        self.main_window_view.tableWidget.cellClicked.connect(self.show_detail)
        self.main_window_view.tableWidget.cellClicked.connect(self.show_tree)
        self.main_window_view.tableWidget.cellDoubleClicked.connect(self.steamTrace)
        # self.main_window_view.Interface.currentIndexChanged

        self.catch_server.current_packet.connect(self.storeTempCapturedPackets)
        self.catch_server.packet_raw.connect(self.storeRawPackets)

        self.index = 0

    def doCapture(self) -> None:
        """
        开始捕获
        :rtype: None
        """
        # 设置开始捕获按钮不可用，并且设置暂停和重新捕获按钮可用
        self.main_window_view.startButton.setDisabled(True)
        self.main_window_view.stopButton.setEnabled(True)
        self.main_window_view.restartButton.setEnabled(False)
        self.main_window_view.openButton.setDisabled(True)
        self.main_window_view.downloadButton.setDisabled(True)

        self.main_window_view.protocolPOB.setDisabled(True)
        self.main_window_view.protocol.setDisabled(True)
        self.main_window_view.portPOB.setDisabled(True)
        self.main_window_view.port.setDisabled(True)
        self.main_window_view.srcAddrPOB.setDisabled(True)
        self.main_window_view.srcAddr.setDisabled(True)
        self.main_window_view.dstAddrPOB.setDisabled(True)
        self.main_window_view.dstAddr.setDisabled(True)
        self.main_window_view.filterButton.setDisabled(True)

        # 获取当前网卡
        interface = self.main_window_view.Interface.currentText()

        # 开始捕获数据包
        self.catch_server._interface = interface
        self.catch_server.isActive = True

    def doPause(self) -> None:
        """
        终止捕获
        :rtype: None
        """
        # 设置暂停按钮和重新捕获按钮不可用，并且设置开始捕获按钮可用
        self.main_window_view.startButton.setEnabled(True)
        self.main_window_view.stopButton.setDisabled(True)
        self.main_window_view.restartButton.setDisabled(False)
        self.main_window_view.openButton.setDisabled(False)
        self.main_window_view.downloadButton.setDisabled(False)

        self.main_window_view.protocolPOB.setDisabled(False)
        self.main_window_view.protocol.setDisabled(False)
        self.main_window_view.portPOB.setDisabled(False)
        self.main_window_view.port.setDisabled(False)
        self.main_window_view.srcAddrPOB.setDisabled(False)
        self.main_window_view.srcAddr.setDisabled(False)
        self.main_window_view.dstAddrPOB.setDisabled(False)
        self.main_window_view.dstAddr.setDisabled(False)
        self.main_window_view.filterButton.setDisabled(False)

        if self.catch_server.isActive:
            self.catch_server.isActive = False

    def doRestart(self) -> None:
        self.main_window_view.tableWidget.clear()  # 清空内容
        self.main_window_view.tableWidget.setRowCount(0)
        self.stored_packets = list()
        self.catch_server._is_clear = True
        self.doCapture()

    def doFilter(self) -> None:
        self.catch_server.sniff_filter = self.filter(self.main_window_view.protocolPOB.currentText(),
                                                     self.main_window_view.protocol.toPlainText(),
                                                     self.main_window_view.portPOB.currentText(),
                                                     self.main_window_view.port.toPlainText(),
                                                     self.main_window_view.srcAddrPOB.currentText(),
                                                     self.main_window_view.srcAddr.toPlainText(),
                                                     self.main_window_view.dstAddrPOB.currentText(),
                                                     self.main_window_view.dstAddr.toPlainText())
        if self.main_window_view.tableWidget.rowCount() > 0:  # 把表格中的数据进行过滤
            self.main_window_view.tableWidget.clear()  # 清空内容
            self.main_window_view.tableWidget.setRowCount(0)

            bpf_filter = self.filter(self.main_window_view.protocolPOB.currentText(),
                                     self.main_window_view.protocol.toPlainText(),
                                     self.main_window_view.portPOB.currentText(),
                                     self.main_window_view.port.toPlainText(),
                                     self.main_window_view.srcAddrPOB.currentText(),
                                     self.main_window_view.srcAddr.toPlainText(),
                                     self.main_window_view.dstAddrPOB.currentText(),
                                     self.main_window_view.dstAddr.toPlainText())  # 获取用户输入的BPF过滤器
            self.filter_packets(bpf_filter)  # 筛选存储的数据包

    def doOpen(self) -> None:
        fileName, _ = QFileDialog.getOpenFileName(None, "Open File", "", "PCAP Files (*.pcap);;All Files (*.txt)",)
        if not fileName:  # 用户关闭对话框或未选择文件
            return

        if fileName:
            try:
                self.main_window_view.tableWidget.clear()  # 清空内容
                self.main_window_view.tableWidget.setRowCount(0)
                self.stored_packets = list()
                self.raw_packets.clear()

                packets = rdpcap(fileName)  # 读取pcap文件

                self.raw_packets = packets

                self.main_window_view.tableWidget.clear()  # 清空内容
                self.main_window_view.tableWidget.setRowCount(0)

                packets = sniff(offline=self.raw_packets)
                index = 0
                self.stored_packets = list()
                # 处理数据包
                for pkt in packets:
                    index += 1
                    src_ip = dst_ip = ""
                    length = len(pkt)
                    details = pkt.summary()

                    # 时间戳
                    timestamp = float(pkt.time)
                    capture_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

                    # 源地址与目的地址
                    src_ip = self.catch_server.Addr(pkt)[0]
                    dst_ip = self.catch_server.Addr(pkt)[1]

                    # 解析协议
                    self.DataLinkLayer = ""  # 数据链路层
                    self.NetworkLayer = ""  # 网络层
                    self.TransportLayer = ""  # 传输层
                    self.PresentationLayer = ""  # 表示层
                    self.ApplicationLayer = ""  # 应用层
                    protocol = self.analysePacket(pkt)
                    if "200 OK" in details:
                        protocol = "HTTP"

                    info = self.catch_server.Info(pkt, protocol)

                    if "mDNS" in details:
                        protocol = "MDNS"

                    # 更新表格
                    self.update_table(str(index), capture_time, src_ip, dst_ip, protocol, length, details,
                                      info)

                    self.stored_packets.append(pkt)

            except Exception as e:
                QMessageBox.critical(None, "Error", f"Could not open file: {e}")

    def doSave(self) -> None:
        if self.main_window_view.tableWidget.rowCount() == 0:
            msg_box = QMessageBox()
            msg_box.setWindowTitle("提示")
            msg_box.setText("没有可保存的数据！")
            msg_box.setStyleSheet("background-color: white; color: black;")  # 设置底色为白色，字体为黑色
            msg_box.exec()
            return
        # 弹出文件选择框
        file_name, _ = QFileDialog.getSaveFileName(None, "保存数据包为", "captured_packets.pcap", "PCAP Files (*.pcap);;All Files (*)")
        if not file_name:  # 用户关闭对话框或未选择文件
            return
        else:
            wrpcap(file_name, self.raw_packets)

    def safeQuit(self) -> None:
        """
        在退出程序时关闭线程
        :rtype: None
        """
        # 创建确认对话框
        msg_box = QMessageBox(self.main_window_view)
        msg_box.setWindowTitle("确认退出")
        msg_box.setText("是否保存文件？")
        msg_box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel)
        msg_box.setDefaultButton(QMessageBox.StandardButton.Cancel)

        # 显示对话框并获取用户的选择
        reply = msg_box.exec()

        if reply == QMessageBox.StandardButton.Yes:
            # 进行保存操作（需要实现保存文件的逻辑）
            self.doSave()  # 假设有一个 saveFile 方法负责保存文件
        elif reply == QMessageBox.StandardButton.Cancel:
            return  # 用户选择取消，停止退出

        self.catch_server.isQuit = True
        self.catch_thread.quit()
        self.main_window_view.close()

    def load_network_interfaces(self):
        # 可能有些网卡不工作
        interfaces = psutil.net_if_addrs()
        interface_names = list(interfaces.keys())
        self.main_window_view.Interface.addItems(interface_names)

        """
        # 仅显示在工作中的网卡
        # 获取网络接口的状态
        interfaces = psutil.net_if_stats()

        # 列出活动的网络接口
        active_interfaces = []
        for interface, stats in interfaces.items():
            if stats.isup:  # 检查接口是否启用
                active_interfaces.append(interface)
                print(f"Active Interface: {interface}, Speed: {stats.speed} Mbps")

        if not active_interfaces:
            print("No active network interfaces found.")
        self.main_window_view.Interface.addItems(active_interfaces)
        """

    def update_table(self, index, capture_time, src_ip, dst_ip, protocol, length, details, info):
        """更新表格"""
        row_position = self.main_window_view.tableWidget.rowCount()
        self.main_window_view.tableWidget.insertRow(row_position)

        self.main_window_view.tableWidget.setItem(row_position, 0, QTableWidgetItem(str(index)))
        self.main_window_view.tableWidget.setItem(row_position, 1, QTableWidgetItem(capture_time))
        self.main_window_view.tableWidget.setItem(row_position, 2, QTableWidgetItem(src_ip))
        self.main_window_view.tableWidget.setItem(row_position, 3, QTableWidgetItem(dst_ip))
        self.main_window_view.tableWidget.setItem(row_position, 4, QTableWidgetItem(protocol))
        self.main_window_view.tableWidget.setItem(row_position, 5, QTableWidgetItem(str(length)))
        self.main_window_view.tableWidget.setItem(row_position, 6, QTableWidgetItem(details))
        self.main_window_view.tableWidget.setItem(row_position, 7, QTableWidgetItem(info))

        self.main_window_view.tableWidget.setHorizontalHeaderLabels(
            ["序号", "捕获时间", "源IP地址", "目的IP地址", "协议", "长度(字节)", "内容", "详细"])

    def show_detail(self, row: int) -> None:
        """
        显示所选择的数据包的帧详情
        :rtype: None
        :param row: int, chosen row
        """
        textEdit = QTextEdit()
        textEdit.setReadOnly(True)

        packet_detail = hexdump(self.stored_packets[int(self.main_window_view.tableWidget.item(row, 0).text()) - 1], dump=True)
        self.main_window_view.textEdit.clear()  # 清除之前的内容
        self.main_window_view.textEdit.setPlainText(packet_detail)  # 设置详细信息

    def show_tree(self, row: int) -> None:
        """
        显示所选择的数据包的详情
        :rtype: None
        :param row: int, chosen row
        """
        treeWidget = QTreeWidget()
        treeWidget.header().setVisible(False)
        treeWidget.setAnimated(True)
        self.main_window_view.treeWidget.clear()  # 清空之前的树节点
        packet_detail = self.getAllLayersDetail(self.stored_packets[int(self.main_window_view.tableWidget.item(row, 0).text()) - 1])

        for layer in packet_detail:
            # 添加一级树节点
            root = QTreeWidgetItem(self.main_window_view.treeWidget)
            root.setText(0, layer)

            # 添加二级树节点
            for key, item in packet_detail[layer]:
                child = QTreeWidgetItem(root)
                child.setText(0, "{} : {}".format(key, item))

    def filter_packets(self, bpf_filter):
        try:
            if bpf_filter == "":
                filtered_packets = sniff(offline=self.raw_packets)
            else:
                filtered_packets = sniff(offline=self.raw_packets, filter=bpf_filter)
            # 处理数据包
            for pkt in filtered_packets:
                i = 0
                while self.stored_packets[i] != pkt:
                    i += 1
                index = i
                src_ip = dst_ip = ""
                length = len(pkt)
                details = pkt.summary()

                # 时间戳
                timestamp = float(pkt.time)
                capture_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

                # 源地址与目的地址
                src_ip = self.catch_server.Addr(pkt)[0]
                dst_ip = self.catch_server.Addr(pkt)[1]

                # 解析协议
                self.DataLinkLayer = ""  # 数据链路层
                self.NetworkLayer = ""  # 网络层
                self.TransportLayer = ""  # 传输层
                self.PresentationLayer = ""  # 表示层
                self.ApplicationLayer = ""  # 应用层
                protocol = self.analysePacket(pkt)
                if "200 OK" in details:
                    protocol = "HTTP"

                info = self.catch_server.Info(pkt, protocol)

                if "mDNS" in details:
                    protocol = "MDNS"

                # 更新表格
                self.update_table(str(index + 1), capture_time, src_ip, dst_ip, protocol, length, details, info)
        except Exception as e:
            print(f"Error occurred: {e}")

    def steamTrace(self, row, column):
        bpf_filter = ""
        port = ""
        src_addr = str(self.main_window_view.tableWidget.item(row, 2).text())
        des_addr = str(self.main_window_view.tableWidget.item(row, 3).text())
        # 协议名称
        protocol = str(self.main_window_view.tableWidget.item(row, 4).text()).lower()
        if protocol == "mdns":
            protocol = ""
            port = "udp port 5353"
        elif protocol == "dns":
            protocol = ""
            port = "udp port 53"
        elif protocol == "tls/ssl":
            protocol = ""
            port = "tcp port 443"
        elif protocol == "igmp":
            protocol = "ip proto 2"
        elif protocol == "icmpv6":
            protocol = "icmp6"
        elif protocol == "ipv6":
            protocol = "ip6"
        elif protocol == "http":
            protocol = ""
            port = "tcp port 80 or tcp port 443"

        if protocol != "":
            bpf_filter += protocol
        if port != "":
            bpf_filter = port
        bpf_filter += (" and ((src host " + src_addr + " and dst host " + des_addr + ") or (src host " + des_addr +
                       " and dst host " + src_addr + "))")

        try:
            filtered_packets = sniff(offline=self.raw_packets, filter=bpf_filter)
            self.trace_window_view = steamTraceController(filtered_packets)
            self.trace_window_view.main_window_view.show()
        except Exception as e:
            print(f"Error occurred: {e}")


    @pyqtSlot(scapy.layers.l2.Ether)
    def storeTempCapturedPackets(self, pkt: scapy.layers.l2.Ether) -> None:
        """
        暂存已捕获的包数据
        :param pkt: 由catch_server捕获并返回的数据包
        :rtype: None
        """
        self.index += 1
        self.stored_packets.append(pkt)

    @pyqtSlot(PacketList)
    def storeRawPackets(self, raw_packet: PacketList) -> None:
        self.raw_packets.append(raw_packet)


if __name__ == '__main__':
    os.chdir("../")  # 改变工作目录
    app = QApplication(sys.argv)
    # 应用主题样式
    apply_stylesheet(app, theme='dark_lightgreen.xml')
    w = MainWindowController()  # 创建控制器实例
    sys.exit(app.exec())  # 进入应用程序主循环
