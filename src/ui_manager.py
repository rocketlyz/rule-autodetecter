from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                           QHBoxLayout, QPushButton, QListWidget, QLabel,
                           QListWidgetItem, QCheckBox)
from PyQt5.QtCore import Qt, QTimer
import queue
import logging
from modify_config import add_domain_to_clash_config

logger = logging.getLogger(__name__)

class DomainManagerUI(QMainWindow):
    def __init__(self, pending_domains: queue.Queue):
        super().__init__()
        self.pending_domains = pending_domains
        self.domain_items = {}  # 存储域名和对应的列表项

        self.init_ui()

        # 设置定时器更新域名列表
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_domain_list)
        self.timer.start(1000)  # 每秒检查一次

    def init_ui(self):
        self.setWindowTitle('域名管理器')
        self.setGeometry(300, 300, 600, 400)

        # 创建中心部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # 添加标题标签
        title_label = QLabel('待处理域名列表')
        layout.addWidget(title_label)

        # 创建列表部件
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        # 创建按钮布局
        button_layout = QHBoxLayout()

        # 添加按钮
        select_all_btn = QPushButton('全选')
        deselect_all_btn = QPushButton('取消全选')
        add_selected_btn = QPushButton('添加选中域名')
        remove_selected_btn = QPushButton('清除选中域名')

        # 连接按钮信号
        select_all_btn.clicked.connect(self.select_all)
        deselect_all_btn.clicked.connect(self.deselect_all)
        add_selected_btn.clicked.connect(self.add_selected_domains)
        remove_selected_btn.clicked.connect(self.remove_selected_domains)

        # 添加按钮到布局
        button_layout.addWidget(select_all_btn)
        button_layout.addWidget(deselect_all_btn)
        button_layout.addWidget(add_selected_btn)
        button_layout.addWidget(remove_selected_btn)

        # 将按钮布局添加到主布局
        layout.addLayout(button_layout)

    def update_domain_list(self):
        """更新域名列表"""
        try:
            while True:
                domain = self.pending_domains.get_nowait()
                if domain and domain not in self.domain_items:
                    self.add_domain_to_list(domain)
        except queue.Empty:
            pass

    def add_domain_to_list(self, domain):
        """添加新域名到列表"""
        if domain not in self.domain_items:
            item = QListWidgetItem()
            self.list_widget.addItem(item)

            # 创建复选框
            checkbox = QCheckBox(domain)
            item.setSizeHint(checkbox.sizeHint())

            self.list_widget.setItemWidget(item, checkbox)
            self.domain_items[domain] = (item, checkbox)

    def select_all(self):
        """全选"""
        for domain, (_, checkbox) in self.domain_items.items():
            checkbox.setChecked(True)

    def deselect_all(self):
        """取消全选"""
        for domain, (_, checkbox) in self.domain_items.items():
            checkbox.setChecked(False)

    def add_selected_domains(self):
        """添加选中的域名到配置文件"""
        selected_domains = []
        for domain, (_, checkbox) in self.domain_items.items():
            if checkbox.isChecked():
                selected_domains.append(domain)

        for domain in selected_domains:
            try:
                add_domain_to_clash_config(domain)
                logger.info(f"成功添加域名: {domain}")
            except Exception as e:
                logger.error(f"添加域名 {domain} 失败: {str(e)}")

        self.remove_selected_domains()

    def remove_selected_domains(self):
        """从列表中移除选中的域名"""
        domains_to_remove = []
        for domain, (item, checkbox) in self.domain_items.items():
            if checkbox.isChecked():
                domains_to_remove.append((domain, item))

        for domain, item in domains_to_remove:
            self.list_widget.takeItem(self.list_widget.row(item))
            del self.domain_items[domain]

def start_ui(pending_domains: queue.Queue):
    """启动UI"""
    app = QApplication([])
    ui = DomainManagerUI(pending_domains)
    ui.show()
    app.exec_()
