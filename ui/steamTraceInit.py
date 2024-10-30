import sys

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtWidgets import QMainWindow, QApplication
from qt_material import apply_stylesheet

from ui.steamTrace import Ui_steamTrace
class steamTraceInit(Ui_steamTrace, QtWidgets.QMainWindow):
    def __init__(self):
        super(steamTraceInit, self).__init__()

        # 初始化ui
        self.hboxLayout = None
        self.setupUi(self)

        # 设置鼠标位置记录量,用于窗口拖动实现
        self.mouse_pos = None
        # 设置窗口无边框
        self.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint)
        # 设置窗口透明度
        self.setWindowOpacity(0.95)
        self.setMinimumSize(800, 600)  # 设置窗口最小大小

        # 设置窗口大小固定
        self.setFixedSize(self.width(), self.height())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_lightgreen.xml')
    w = steamTraceInit()
    w.show()
    sys.exit(app.exec())