import os
import sys

import cursor
from PyQt6 import QtWidgets
from PyQt6.QtGui import QPalette
from PyQt6.QtCore import QObject
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QBrush
from PyQt6.QtWidgets import QApplication, QTextEdit, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QScrollArea
from qt_material import apply_stylesheet
from scapy.utils import hexdump

from ui.steamTraceInit import steamTraceInit


class steamTraceController(QObject):
    def __init__(self, packets):
        super(steamTraceController, self).__init__()
        self.main_window_view = steamTraceInit()
        
        self.update_textEdit(packets)

        self.main_window_view.minimize.clicked.connect(self.main_window_view.showMinimized)
        self.main_window_view.closeButton.clicked.connect(self.safeQuit)

    def safeQuit(self) -> None:
        """
        在退出程序时关闭线程
        :rtype: None
        """
        self.main_window_view.close()

    def update_textEdit(self, packets):
        red = True
        blue = False

        mainLayout = QVBoxLayout()
        scrollArea = QScrollArea()

        # 滚动区域
        scrollAreaWidgetContents = QWidget()
        vLayout = QVBoxLayout(scrollAreaWidgetContents)

        for pkt in packets:
            packet_detail = hexdump(pkt, dump=True)

            # 创建 QLabel
            label = QLabel()
            label.setText(packet_detail)
            label.setFixedWidth(self.main_window_view.widget.width() - 100)


            # 使用样式表设置背景色
            if red:
                label.setStyleSheet("background-color: #FBE5D6; color: #780024;")
                red = False
                blue = True
            elif blue:
                label.setStyleSheet("background-color: #DAE3F3; color: #211C75;")
                red = True
                blue = False

            # 将 QLabel 添加到布局中
            vLayout.addWidget(label)

        # 将 QLabel 添加到内容布局中
        scrollAreaWidgetContents.setLayout(vLayout)
        scrollArea.setWidget(scrollAreaWidgetContents)
        scrollArea.setFixedWidth(self.main_window_view.widget.width() - 50)
        scrollArea.setFixedHeight(self.main_window_view.widget.height() - 50)
        mainLayout.addWidget(scrollArea)
        self.main_window_view.widget.setLayout(mainLayout)

if __name__ == '__main__':
    os.chdir("../")  # 改变工作目录
    app = QApplication(sys.argv)
    w = steamTraceController()  # 创建控制器实例
    sys.exit(app.exec())  # 进入应用程序主循环
