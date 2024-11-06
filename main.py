import os
import sys

from PyQt6.QtWidgets import QApplication
from qt_material import apply_stylesheet
from scapy.config import conf

from controller.MainWindowController import MainWindowController

if __name__ == '__main__':
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_lightgreen.xml')
    w = MainWindowController()
    sys.exit(app.exec())
