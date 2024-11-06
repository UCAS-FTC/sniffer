from PyQt6.QtCore import QObject
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QBrush
from PyQt6.QtWidgets import QApplication, QTextEdit, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QScrollArea
from qt_material import apply_stylesheet
from scapy.layers.l2 import Ether
from scapy.utils import hexdump
from scapy.all import *

from ui.steamTraceInit import steamTraceInit
from controller.CatchModel import CatchServer


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

        catch_server = CatchServer()

        for pkt in packets:
            packet_detail = hexdump(pkt, dump=True)
            length = len(pkt)
            details = pkt.summary()
            src_ip = catch_server.Addr(pkt)[0]
            dst_ip = catch_server.Addr(pkt)[1]
            pkt_detail = ""

            # 时间戳
            timestamp = float(pkt.time)
            capture_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

            # 解析协议
            self.DataLinkLayer = ""  # 数据链路层
            self.NetworkLayer = ""  # 网络层
            self.TransportLayer = ""  # 传输层
            self.PresentationLayer = ""  # 表示层
            self.ApplicationLayer = ""  # 应用层
            protocol = catch_server.analysePacket(pkt)
            if "200 OK" in details:
                protocol = "HTTP"

            self._info = catch_server.Info(pkt, protocol)
            if "mDNS" in details:
                protocol = "MDNS"
            if protocol == "Ether":
                protocol = str(hex(pkt[Ether].type))

            pkt_detail = "\n" + "捕获时间：" + str(capture_time) + "\n"
            pkt_detail += "源地址：" + str(src_ip) + "\n"
            pkt_detail += "目的地址：" + str(dst_ip) + "\n"
            pkt_detail += "协议层次：" + str(details) + "\n"
            pkt_detail += "详细内容：" + str(self._info) + "\n\n"
            pkt_detail += packet_detail + "\n"

            # 创建 QLabel
            label = QLabel()
            label.setText(pkt_detail)
            label.setWordWrap(True)  # 启用自动换行
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
