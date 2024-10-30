import os
import sys

import psutil
import scapy
from PyQt6.QtCore import QObject, QThread, pyqtSlot, pyqtSignal, Qt
from PyQt6.QtWidgets import QTableWidgetItem, QApplication, QTextEdit, QTreeWidget, QTreeWidgetItem
from qt_material import apply_stylesheet
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy import interfaces

from ui.mainWindowInit import mainWindowInit
from controller.CatchModel import CatchServer
from custom.packetAnalyser import Analyser
from custom.filter import Filter


class MainWindowController(QObject, Analyser, Filter):
    def __init__(self):
        super(MainWindowController, self).__init__()
        self.main_window_view = mainWindowInit()
        self.main_window_view.show()

        # 暂存的包
        self.stored_packets = list()

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
        self.main_window_view.tableWidget.cellClicked.connect(self.show_detail)
        self.main_window_view.tableWidget.cellClicked.connect(self.show_tree)

        self.catch_server.current_packet.connect(self.storeTempCapturedPackets)

    def doCapture(self) -> None:
        """
        开始捕获
        :rtype: None
        """
        # 设置开始捕获按钮不可用，并且设置暂停和重新捕获按钮可用
        self.main_window_view.startButton.setDisabled(True)
        self.main_window_view.stopButton.setEnabled(True)
        self.main_window_view.restartButton.setEnabled(False)

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
        if self.catch_server.isActive:
            self.catch_server.isActive = False

    def doRestart(self) -> None:
        self.main_window_view.tableWidget.clear()  # 清空内容
        self.main_window_view.tableWidget.setRowCount(0)
        self.stored_packets = list()
        self.catch_server._is_clear = True
        self.doCapture()

    def doFilter(self) -> None:
        if self.main_window_view.tableWidget.rowCount() > 0: # 把表格中的数据进行过滤
            self.main_window_view.tableWidget.clear()  # 清空内容
            self.main_window_view.tableWidget.setRowCount(0)
        else:
            self.catch_server.sniff_filter = self.filter(self.main_window_view.protocolPOB.currentText(),
                                                         self.main_window_view.protocol.toPlainText(),
                                                         self.main_window_view.portPOB.currentText(),
                                                         self.main_window_view.port.toPlainText(),
                                                         self.main_window_view.srcAddrPOB.currentText(),
                                                         self.main_window_view.srcAddr.toPlainText(),
                                                         self.main_window_view.dstAddrPOB.currentText(),
                                                         self.main_window_view.dstAddr.toPlainText())



    def safeQuit(self) -> None:
        """
        在退出程序时关闭线程
        :rtype: None
        """
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

    def update_table(self, index, capture_time, src_ip, dst_ip, protocol, length, details):
        """更新表格"""
        row_position = self.main_window_view.tableWidget.rowCount()
        self.main_window_view.tableWidget.insertRow(row_position)

        self.main_window_view.tableWidget.setItem(row_position, 0, QTableWidgetItem(str(row_position + 1)))
        self.main_window_view.tableWidget.setItem(row_position, 1, QTableWidgetItem(capture_time))
        self.main_window_view.tableWidget.setItem(row_position, 2, QTableWidgetItem(src_ip))
        self.main_window_view.tableWidget.setItem(row_position, 3, QTableWidgetItem(dst_ip))
        self.main_window_view.tableWidget.setItem(row_position, 4, QTableWidgetItem(protocol))
        self.main_window_view.tableWidget.setItem(row_position, 5, QTableWidgetItem(str(length)))
        self.main_window_view.tableWidget.setItem(row_position, 6, QTableWidgetItem(details))

    def show_detail(self, row: int) -> None:
        """
        显示所选择的数据包的帧详情
        :rtype: None
        :param row: int, chosen row
        """
        textEdit = QTextEdit()
        textEdit.setReadOnly(True)
        packet_detail = hexdump(self.stored_packets[row], dump=True)
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
        packet_detail = self.getAllLayersDetail(self.stored_packets[row])

        for layer in packet_detail:
            # 添加一级树节点
            root = QTreeWidgetItem(self.main_window_view.treeWidget)
            root.setText(0, layer)

            # 添加二级树节点
            for key, item in packet_detail[layer]:
                child = QTreeWidgetItem(root)
                child.setText(0, "{} : {}".format(key, item))

    @pyqtSlot(scapy.layers.l2.Ether)
    def storeTempCapturedPackets(self, pkt: scapy.layers.l2.Ether) -> None:
        """
        暂存已捕获的包数据
        :param pkt: 由catch_server捕获并返回的数据包
        :rtype: None
        """
        self.stored_packets.append(pkt)




if __name__ == '__main__':
    os.chdir("../")  # 改变工作目录
    app = QApplication(sys.argv)
    # 应用主题样式
    apply_stylesheet(app, theme='dark_lightgreen.xml')
    w = MainWindowController() # 创建控制器实例
    sys.exit(app.exec())  # 进入应用程序主循环