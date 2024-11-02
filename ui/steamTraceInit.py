import sys

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtGui import QMouseEvent, QIcon
from PyQt6.QtWidgets import QMainWindow, QApplication, QScrollArea, QWidget, QVBoxLayout
from qt_material import apply_stylesheet

from custom.style import min_style, close_style
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
        # self.setMinimumSize(800, 600)  # 设置窗口最小大小

        # 设置窗口大小固定
        self.setFixedSize(self.width(), self.height())

        self.minimize.setStyleSheet(min_style)
        self.closeButton.setStyleSheet(close_style)
        self.minimize.setIcon(QIcon("resources/minimize.png"))
        self.closeButton.setIcon(QIcon("resources/close.png"))

    # 添加鼠标事件
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            self.mouse_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self.mouse_pos is not None:
            self.move(event.globalPosition().toPoint() - self.mouse_pos)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            self.mouse_pos = None

if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = steamTraceInit()
    sys.exit(app.exec())