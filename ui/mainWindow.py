# Form implementation generated from reading ui file 'mainWindow.ui'
#
# Created by: PyQt6 UI code generator 6.7.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1132, 669)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Form.sizePolicy().hasHeightForWidth())
        Form.setSizePolicy(sizePolicy)
        self.widget = QtWidgets.QWidget(parent=Form)
        self.widget.setGeometry(QtCore.QRect(10, 10, 1111, 48))
        self.widget.setObjectName("widget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.startButton = QtWidgets.QPushButton(parent=self.widget)
        self.startButton.setMinimumSize(QtCore.QSize(30, 30))
        self.startButton.setMaximumSize(QtCore.QSize(30, 30))
        self.startButton.setStyleSheet("image: url(:/start.png);")
        self.startButton.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/start.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        self.startButton.setIcon(icon)
        self.startButton.setObjectName("startButton")
        self.horizontalLayout.addWidget(self.startButton)
        self.stopButton = QtWidgets.QPushButton(parent=self.widget)
        self.stopButton.setMinimumSize(QtCore.QSize(30, 30))
        self.stopButton.setMaximumSize(QtCore.QSize(30, 30))
        self.stopButton.setStyleSheet("image: url(:/pause.png);")
        self.stopButton.setText("")
        self.stopButton.setObjectName("stopButton")
        self.horizontalLayout.addWidget(self.stopButton)
        self.restartButton = QtWidgets.QPushButton(parent=self.widget)
        self.restartButton.setMinimumSize(QtCore.QSize(30, 30))
        self.restartButton.setMaximumSize(QtCore.QSize(30, 30))
        self.restartButton.setStyleSheet("image: url(:/restart.png);")
        self.restartButton.setText("")
        self.restartButton.setObjectName("restartButton")
        self.horizontalLayout.addWidget(self.restartButton)
        self.downloadButton = QtWidgets.QPushButton(parent=self.widget)
        self.downloadButton.setMinimumSize(QtCore.QSize(30, 30))
        self.downloadButton.setMaximumSize(QtCore.QSize(30, 30))
        self.downloadButton.setStyleSheet("image: url(:/download.png);")
        self.downloadButton.setText("")
        self.downloadButton.setObjectName("downloadButton")
        self.horizontalLayout.addWidget(self.downloadButton)
        self.Interface = QtWidgets.QComboBox(parent=self.widget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.Interface.sizePolicy().hasHeightForWidth())
        self.Interface.setSizePolicy(sizePolicy)
        self.Interface.setMinimumSize(QtCore.QSize(300, 30))
        self.Interface.setMaximumSize(QtCore.QSize(300, 30))
        self.Interface.setObjectName("Interface")
        self.horizontalLayout.addWidget(self.Interface)
        spacerItem = QtWidgets.QSpacerItem(800, 20, QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.minButton = QtWidgets.QPushButton(parent=self.widget)
        self.minButton.setMinimumSize(QtCore.QSize(30, 30))
        self.minButton.setMaximumSize(QtCore.QSize(30, 30))
        self.minButton.setStyleSheet("image: url(:/minimize.png);")
        self.minButton.setText("")
        self.minButton.setObjectName("minButton")
        self.horizontalLayout.addWidget(self.minButton)
        self.closeButton = QtWidgets.QPushButton(parent=self.widget)
        self.closeButton.setMinimumSize(QtCore.QSize(30, 30))
        self.closeButton.setMaximumSize(QtCore.QSize(30, 30))
        self.closeButton.setStyleSheet("image: url(:/close.png);")
        self.closeButton.setText("")
        self.closeButton.setObjectName("closeButton")
        self.horizontalLayout.addWidget(self.closeButton)
        self.filter = QtWidgets.QComboBox(parent=Form)
        self.filter.setGeometry(QtCore.QRect(10, 60, 1111, 30))
        self.filter.setMinimumSize(QtCore.QSize(0, 30))
        self.filter.setMaximumSize(QtCore.QSize(16777215, 30))
        self.filter.setObjectName("filter")
        self.splitter_2 = QtWidgets.QSplitter(parent=Form)
        self.splitter_2.setGeometry(QtCore.QRect(10, 100, 1111, 551))
        self.splitter_2.setOrientation(QtCore.Qt.Orientation.Vertical)
        self.splitter_2.setObjectName("splitter_2")
        self.tableWidget = QtWidgets.QTableWidget(parent=self.splitter_2)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(0)
        self.tableWidget.setRowCount(0)
        self.splitter = QtWidgets.QSplitter(parent=self.splitter_2)
        self.splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
        self.splitter.setObjectName("splitter")
        self.treeWidget = QtWidgets.QTreeWidget(parent=self.splitter)
        self.treeWidget.setObjectName("treeWidget")
        self.treeWidget.headerItem().setText(0, "1")
        self.textEdit = QtWidgets.QTextEdit(parent=self.splitter)
        self.textEdit.setObjectName("textEdit")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
