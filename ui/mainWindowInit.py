import sys

from PyQt6 import QtWidgets, QtCore
from PyQt6.QtCore import QSize
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import QPushButton, QApplication
from qt_material import apply_stylesheet

from ui.mainWindow import Ui_Form
from custom.style import min_style, close_style, normalButton_style


class mainWindowInit(Ui_Form, QtWidgets.QMainWindow):
    def __init__(self):
        super(mainWindowInit, self).__init__()

        # 初始化ui
        self.hboxLayout = None
        self.setupUi(self)

        # 设置鼠标位置记录量,用于窗口拖动实现
        self.mouse_pos = None
        # 设置窗口无边框
        self.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint)
        # 设置窗口透明度
        self.setWindowOpacity(0.97)
        self.setMinimumSize(800, 600)  # 设置窗口最小大小

        # 设置窗口大小固定
        self.setFixedSize(self.width(), self.height())
        # 初始化按钮控件
        self.initButtons()
        # 初始化表格控件

        self.initComboBox()

    def initButtons(self):
        """
        初始化按钮控件
        """
        # 单独设置最小化、关闭窗口按钮以及filter按钮的样式
        self.minButton.setStyleSheet(min_style)
        self.closeButton.setStyleSheet(close_style)
        self.minButton.setIcon(QIcon("resources/minimize.png"))
        self.closeButton.setIcon(QIcon("resources/close.png"))

        # 设置按钮图标的QPixmap
        catchpix = QPixmap("resources/start.png")
        catchpix = catchpix.scaled(QSize(80, 80))
        pausepix = QPixmap("resources/pause.png")
        pausepix = pausepix.scaled(QSize(80, 80))
        restartpix = QPixmap("resources/restart.png")
        restartpix = restartpix.scaled(QSize(80, 80))
        downloadpix = QPixmap("resources/download.png")
        downloadpix = downloadpix.scaled(QSize(80, 80))

        # 将QPixmap应用到按钮
        self.startButton.setIcon(QIcon(catchpix))
        self.stopButton.setIcon(QIcon(pausepix))
        self.restartButton.setIcon(QIcon(restartpix))
        self.downloadButton.setIcon(QIcon(downloadpix))

        # 功能按钮应用自定义style（增加hover样式）
        for button in self.findChildren(QPushButton):
            if button.objectName() not in ["closeButton", "minButton", "ucasLogoButton"]:
                button.setStyleSheet(normalButton_style)
        self.startButton.setStyleSheet(normalButton_style)

    def initComboBox(self):
        self.Interface.setStyleSheet("color: white;")  # 设置文字颜色和背景颜色


if __name__ == '__main__':
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_lightgreen.xml')
    w = mainWindowInit()
    w.show()
    sys.exit(app.exec())
