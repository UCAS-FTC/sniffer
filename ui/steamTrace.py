# Form implementation generated from reading ui file 'steamTrace.ui'
#
# Created by: PyQt6 UI code generator 6.7.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_steamTrace(object):
    def setupUi(self, steamTrace):
        steamTrace.setObjectName("steamTrace")
        steamTrace.resize(1126, 698)
        self.widget = QtWidgets.QWidget(parent=steamTrace)
        self.widget.setGeometry(QtCore.QRect(10, 50, 1111, 641))
        self.widget.setObjectName("widget")
        self.widget_2 = QtWidgets.QWidget(parent=steamTrace)
        self.widget_2.setGeometry(QtCore.QRect(1040, 10, 84, 48))
        self.widget_2.setObjectName("widget_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget_2)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.minimize = QtWidgets.QPushButton(parent=self.widget_2)
        self.minimize.setMinimumSize(QtCore.QSize(30, 30))
        self.minimize.setMaximumSize(QtCore.QSize(30, 30))
        self.minimize.setText("")
        self.minimize.setObjectName("minimize")
        self.horizontalLayout.addWidget(self.minimize)
        self.closeButton = QtWidgets.QPushButton(parent=self.widget_2)
        self.closeButton.setMinimumSize(QtCore.QSize(30, 30))
        self.closeButton.setMaximumSize(QtCore.QSize(30, 30))
        self.closeButton.setText("")
        self.closeButton.setObjectName("closeButton")
        self.horizontalLayout.addWidget(self.closeButton)
        self.widget_3 = QtWidgets.QWidget(parent=steamTrace)
        self.widget_3.setGeometry(QtCore.QRect(20, 10, 154, 58))
        self.widget_3.setObjectName("widget_3")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.widget_3)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.logo = QtWidgets.QPushButton(parent=self.widget_3)
        self.logo.setMinimumSize(QtCore.QSize(40, 40))
        self.logo.setMaximumSize(QtCore.QSize(40, 40))
        self.logo.setText("")
        self.logo.setIconSize(QtCore.QSize(32, 32))
        self.logo.setObjectName("logo")
        self.horizontalLayout_2.addWidget(self.logo)
        self.steamtrace = QtWidgets.QPushButton(parent=self.widget_3)
        self.steamtrace.setMinimumSize(QtCore.QSize(90, 30))
        self.steamtrace.setMaximumSize(QtCore.QSize(90, 30))
        self.steamtrace.setText("")
        self.steamtrace.setIconSize(QtCore.QSize(110, 50))
        self.steamtrace.setObjectName("steamtrace")
        self.horizontalLayout_2.addWidget(self.steamtrace)

        self.retranslateUi(steamTrace)
        QtCore.QMetaObject.connectSlotsByName(steamTrace)

    def retranslateUi(self, steamTrace):
        _translate = QtCore.QCoreApplication.translate
        steamTrace.setWindowTitle(_translate("steamTrace", "Form"))
