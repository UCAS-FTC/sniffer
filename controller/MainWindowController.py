import os
import sys

import psutil
import scapy
from PyQt6.QtCore import QObject, QThread, pyqtSlot, pyqtSignal
from PyQt6.QtWidgets import QTableWidgetItem, QApplication
from qt_material import apply_stylesheet
from scapy.all import *
from scapy import interfaces

from ui.mainWindowInit import mainWindowInit
from controller.CatchModel import CatchServer

class MainWindowController(QObject):
    def __init__(self):
        super(MainWindowController, self).__init__()
        self.main_window_view = mainWindowInit()
        self.main_window_view.show()

        # 获取网卡设备并显示在下拉框中
        self.load_network_interfaces()

        # 创建新进程
        self.catch_thread = QThread()
        self.catch_server = CatchServer()

        # 将服务绑定至线程
        self.catch_server.moveToThread(self.catch_thread)
        self.catch_thread.started.connect(self.catch_server.start_sniffing)
        self.catch_thread.start()

        # 对MainWindow中的功能进行绑定
        self.main_window_view.closeButton.clicked.connect(self.safeQuit)
        self.main_window_view.minButton.clicked.connect(self.main_window_view.showMinimized)
        self.main_window_view.startButton.clicked.connect(self.doCapture)
        self.main_window_view.stopButton.clicked.connect(self.doPause)

    def doCapture(self) -> None:
        """
        开始捕获
        :rtype: None
        """
        # 设置开始捕获按钮不可用，并且设置暂停和重新捕获按钮可用
        self.main_window_view.startButton.setDisabled(True)
        self.main_window_view.stopButton.setEnabled(True)
        self.main_window_view.restartButton.setEnabled(True)

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
        self.main_window_view.restartButton.setDisabled(True)
        if self.catch_server.isActive:
            self.catch_server.isActive = False

    def doRestart(self) -> None:
        pass

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


    def update_table(self, src, dst, summary):
        """更新表格"""
        row_position = self.main_window_view.tableWidget.rowCount()
        self.main_window_view.tableWidget.insertRow(row_position)
        self.main_window_view.tableWidget.setItem(row_position, 0, QTableWidgetItem(src))
        self.main_window_view.tableWidget.setItem(row_position, 1, QTableWidgetItem(dst))
        self.main_window_view.tableWidget.setItem(row_position, 2, QTableWidgetItem(summary))

if __name__ == '__main__':
    os.chdir("../")  # 改变工作目录
    app = QApplication(sys.argv)
    # 应用主题样式
    apply_stylesheet(app, theme='dark_lightgreen.xml')
    w = MainWindowController() # 创建控制器实例
    sys.exit(app.exec())  # 进入应用程序主循环