
import os
import sys
import subprocess
import threading
import json
import re
from collections import defaultdict
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QComboBox, QProgressBar, QMessageBox, QListWidget, QListWidgetItem, QAbstractItemView,
    QGroupBox, QFormLayout, QSizePolicy, QSpacerItem, QDialog, QTabWidget
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from nuclei_result_sort import parse_line, LEVEL_ORDER
from category_manager import load_category_groups, save_category_groups

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "user_config.json")

def load_user_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_user_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


# ===================== NucleiGUI类定义 =====================

from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QGroupBox, QFormLayout, QSizePolicy, QSpacerItem

class NucleiGUI(QWidget):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    show_result_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nuclei 一站式安全扫描工具")
        self.resize(850, 750)
        self.setFont(QFont("微软雅黑", 10))
        self.category_groups = load_category_groups()
        self.user_config = load_user_config()
        self.init_ui()
        # 信号连接
        self.log_signal.connect(self.log.append)
        self.progress_signal.connect(self.progress.setValue)
        self.show_result_signal.connect(self.show_vuln_result)

    def init_ui(self):
        main_layout = QVBoxLayout()

        # 路径设置分组
        path_group = QGroupBox("环境与模板路径设置")
        path_layout = QFormLayout()
        self.exe_edit = QLineEdit()
        exe_btn = QPushButton("选择nuclei.exe")
        exe_btn.clicked.connect(self.choose_exe)
        exe_hbox = QHBoxLayout()
        exe_hbox.addWidget(self.exe_edit)
        exe_hbox.addWidget(exe_btn)
        path_layout.addRow(QLabel("nuclei.exe 路径："), exe_hbox)

        self.tpl_edit = QLineEdit()
        tpl_btn = QPushButton("选择nuclei-templates")
        tpl_btn.clicked.connect(self.choose_tpl)
        tpl_hbox = QHBoxLayout()
        tpl_hbox.addWidget(self.tpl_edit)
        tpl_hbox.addWidget(tpl_btn)
        path_layout.addRow(QLabel("nuclei-templates 路径："), tpl_hbox)
        path_group.setLayout(path_layout)
        main_layout.addWidget(path_group)

        # 自动填充上次路径
        if self.user_config.get("exe_path"):
            self.exe_edit.setText(self.user_config["exe_path"])
        if self.user_config.get("tpl_path"):
            self.tpl_edit.setText(self.user_config["tpl_path"])

        # 扫描参数分组
        scan_group = QGroupBox("扫描参数设置")
        scan_layout = QFormLayout()
        self.target_edit = QLineEdit()
        scan_layout.addRow(QLabel("目标URL（如https://example.com）："), self.target_edit)

        self.group_combo = QComboBox()
        self.group_combo.addItems(self.category_groups.keys())
        self.group_combo.currentIndexChanged.connect(self.update_subcats)
        scan_layout.addRow(QLabel("选择大类："), self.group_combo)

        self.subcat_list = QListWidget()
        self.subcat_list.setSelectionMode(QAbstractItemView.MultiSelection)
        self.subcat_list.setMinimumHeight(100)
        scan_layout.addRow(QLabel("选择子类（可多选，Ctrl/Shift辅助）："), self.subcat_list)
        self.update_subcats()

        add_subcat_hbox = QHBoxLayout()
        self.new_subcat_edit = QLineEdit()
        add_subcat_btn = QPushButton("添加新子类")
        add_subcat_btn.clicked.connect(self.add_new_subcat)
        add_subcat_hbox.addWidget(self.new_subcat_edit)
        add_subcat_hbox.addWidget(add_subcat_btn)
        scan_layout.addRow(QLabel("新子类名："), add_subcat_hbox)

        self.concurrent_edit = QLineEdit("10")
        scan_layout.addRow(QLabel("并发数："), self.concurrent_edit)
        scan_group.setLayout(scan_layout)
        main_layout.addWidget(scan_group)

        # 扫描按钮
        scan_btn = QPushButton("开始扫描")
        scan_btn.setStyleSheet("font-weight:bold;font-size:15px;height:32px;")
        scan_btn.clicked.connect(self.start_scan)
        main_layout.addWidget(scan_btn)

        # 进度条
        self.progress = QProgressBar()
        self.progress.setMinimumHeight(18)
        main_layout.addWidget(self.progress)

        # 日志分组
        log_group = QGroupBox("运行日志/结果")
        log_layout = QVBoxLayout()
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.log)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

        # 整理按钮
        sort_btn = QPushButton("整理扫描结果（手动选择文件）")
        sort_btn.clicked.connect(self.sort_result)
        main_layout.addWidget(sort_btn)

        # 增加弹性空间
        main_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        self.setLayout(main_layout)

    def choose_exe(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择nuclei.exe", "", "可执行文件 (*.exe)")
        if path:
            self.exe_edit.setText(path)
            self.user_config["exe_path"] = path
            save_user_config(self.user_config)

    def choose_tpl(self):
        path = QFileDialog.getExistingDirectory(self, "选择nuclei-templates目录")
        if path:
            self.tpl_edit.setText(path)
            self.user_config["tpl_path"] = path
            save_user_config(self.user_config)

    def update_subcats(self):
        group = self.group_combo.currentText()
        self.subcat_list.clear()
        for cat in self.category_groups[group]:
            item = QListWidgetItem(cat)
            self.subcat_list.addItem(item)

    def add_new_subcat(self):
        group = self.group_combo.currentText()
        new_cat = self.new_subcat_edit.text().strip()
        if not new_cat:
            QMessageBox.warning(self, "提示", "新子类名不能为空！")
            return
        if new_cat in self.category_groups[group]:
            QMessageBox.warning(self, "提示", "该子类已存在！")
            return
        self.category_groups[group].append(new_cat)
        save_category_groups(self.category_groups)
        self.update_subcats()
        self.new_subcat_edit.clear()
        QMessageBox.information(self, "提示", f"已添加新子类：{new_cat}")

    def start_scan(self):
        exe = self.exe_edit.text().strip()
        tpl = self.tpl_edit.text().strip()
        target = self.target_edit.text().strip()
        group = self.group_combo.currentText()
        concurrency = self.concurrent_edit.text().strip() or "10"

        # 多选小类
        selected_items = self.subcat_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "提示", "请至少选择一个子类！")
            return
        subcats = [item.text() for item in selected_items]

        if not all([exe, tpl, target]):
            QMessageBox.warning(self, "提示", "请填写nuclei.exe、模板路径和目标！")
            return

        self.user_config["exe_path"] = exe
        self.user_config["tpl_path"] = tpl
        save_user_config(self.user_config)

        os.environ["PATH"] = os.path.dirname(exe) + ";" + os.environ.get("PATH", "")
        poc_paths = [os.path.join(tpl, c) for c in subcats]
        output_file = f"nuclei_results_{group}_{'_'.join(subcats)}_{os.getpid()}.txt"

        threading.Thread(target=self.run_nuclei, args=(exe, target, poc_paths, concurrency, output_file), daemon=True).start()

    def run_nuclei(self, exe, target, poc_paths, concurrency, output_file):
        self.progress_signal.emit(0)
        command = [
            exe, "-u", target,
            "-t", ",".join(poc_paths),
            "-c", str(concurrency),
            "-o", output_file,
            "-v"
        ]
        self.log_signal.emit(f"执行命令: {' '.join(command)}")
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,creationflags=0x08000000)
            total = 0
            for line in proc.stdout:
                self.log_signal.emit(line.strip())
                total += 1
                self.progress_signal.emit(min(100, total % 100))
            proc.wait()
            self.progress_signal.emit(100)
            self.log_signal.emit(f"扫描完成，结果文件: {output_file}")
            # 扫描完成后自动整理并展示
            self.show_vuln_result(output_file)
        except Exception as e:
            self.log_signal.emit(f"运行出错: {e}")


    def show_vuln_result(self, result_file):
        # 读取并整理结果
        result = defaultdict(lambda: defaultdict(list))
        total_count = 0
        try:
            with open(result_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    level, info_type, content = parse_line(line)
                    result[level][info_type].append(content)
                    total_count += 1
        except Exception as e:
            QMessageBox.warning(self, "整理失败", f"读取结果文件失败: {e}")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("漏洞扫描结果展示")
        dlg.resize(1100, 750)
        main_layout = QVBoxLayout()
        label = QLabel(f"漏洞总量：{total_count}")
        label.setFont(QFont("微软雅黑", 13, QFont.Bold))
        main_layout.addWidget(label)

        # 一级Tab：评级
        level_tabs = QTabWidget()
        # 色调与图标映射
        # nuclei 官方配色
        level_colors = {
            'critical': '#e53935',   # 红
            'high':     '#fb8c00',   # 橙
            'medium':   '#fbc02d',   # 黄
            'low':      '#1976d2',   # 蓝
            'info':     '#90a4ae',   # 灰
            'unknown':  '#bdbdbd',   # 浅灰
        }
        level_icons = {
            'critical': '❗',
            'high': '⚠️',
            'medium': '🔶',
            'low': '🔷',
            'info': 'ℹ️',
            'unknown': '❔',
        }
        def highlight_text(text):
            # 高亮URL、CVE、payload等常见字段
            text = re.sub(r'(https?://\S+)', r'<span style="color:#0070c0;font-weight:bold;">\1</span>', text)
            text = re.sub(r'(CVE-\d{4}-\d+)', r'<span style="color:#d14;font-weight:bold;">\1</span>', text)
            text = re.sub(r'(\[.*?\])', r'<span style="color:#333;font-weight:bold;">\1</span>', text)
            return text.replace('\n', '<br>')

        for level in LEVEL_ORDER:
            if level not in result:
                continue
            # 二级Tab：该评级下每个漏洞单独一个Tab
            vuln_widget = QWidget()
            vuln_layout = QVBoxLayout()
            # 搜索框
            search_layout = QHBoxLayout()
            search_edit = QLineEdit()
            search_edit.setPlaceholderText("输入关键字可搜索当前评级下所有内容，回车高亮...")
            search_layout.addWidget(QLabel("搜索："))
            search_layout.addWidget(search_edit)
            # 导出全部按钮
            export_all_btn = QPushButton("导出全部TXT")
            def make_export_all_func(level=level):
                return lambda: self.export_all_vuln_content(result, level)
            export_all_btn.clicked.connect(make_export_all_func(level))
            search_layout.addWidget(export_all_btn)
            vuln_layout.addLayout(search_layout)

            vuln_tabs = QTabWidget()
            vuln_tabs.setTabsClosable(True)
            vuln_tabs.setMovable(True)
            idx = 1
            tab_widgets = []  # 保存tab内容和控件
            for info_type in sorted(result[level].keys()):
                for item in result[level][info_type]:
                    tab = QWidget()
                    tab_layout = QVBoxLayout()
                    text_edit = QTextEdit()
                    text_edit.setReadOnly(True)
                    text_edit.setFont(QFont("Consolas", 13, QFont.Bold))
                    color = level_colors.get(level, '#cccccc')
                    text_edit.setHtml(f'<div style="background-color:{color};font-size:15px;">{highlight_text(item)}</div>')
                    tab_layout.addWidget(text_edit)
                    # 复制按钮
                    btn_layout = QHBoxLayout()
                    copy_btn = QPushButton("复制内容")
                    def make_copy_func(te=text_edit):
                        return lambda: te.selectAll() or te.copy()
                    copy_btn.clicked.connect(make_copy_func(text_edit))
                    btn_layout.addWidget(copy_btn)
                    # 导出按钮
                    export_btn = QPushButton("导出为TXT")
                    def make_export_func(content=item):
                        return lambda: self.export_vuln_content(content)
                    export_btn.clicked.connect(make_export_func(item))
                    btn_layout.addWidget(export_btn)
                    btn_layout.addStretch()
                    tab_layout.addLayout(btn_layout)
                    tab.setLayout(tab_layout)
                    tab_title = f"{info_type}-{idx}"
                    vuln_tabs.addTab(tab, tab_title)
                    tab_widgets.append((tab, text_edit, item))
                    idx += 1
            # 关闭tab功能
            def close_tab(index, tabs=vuln_tabs):
                tabs.removeTab(index)
            vuln_tabs.tabCloseRequested.connect(close_tab)
            # 搜索功能
            def do_search():
                keyword = search_edit.text().strip()
                for i, (tab, text_edit, item) in enumerate(tab_widgets):
                    if keyword and keyword.lower() in item.lower():
                        # 高亮关键字
                        highlighted = highlight_text(item).replace(keyword, f'<span style="background:yellow;">{keyword}</span>')
                        text_edit.setHtml(f'<div style="background-color:{color};font-size:15px;">{highlighted}</div>')
                        vuln_tabs.setCurrentIndex(i)
                    else:
                        text_edit.setHtml(f'<div style="background-color:{color};font-size:15px;">{highlight_text(item)}</div>')
            search_edit.returnPressed.connect(do_search)
            vuln_layout.addWidget(vuln_tabs)
            vuln_widget.setLayout(vuln_layout)
            # 一级Tab色调和图标
            color = level_colors.get(level, '#cccccc')
            icon = level_icons.get(level, '')
            level_tabs.addTab(vuln_widget, f"{icon} {level.upper()}")
            level_tabs.setTabBarAutoHide(False)
            level_tabs.setStyleSheet(f"QTabBar::tab:selected {{ background: {color}; }}")

        main_layout.addWidget(level_tabs)
        dlg.setLayout(main_layout)
        dlg.exec_()

    def export_all_vuln_content(self, result, level):
        path, _ = QFileDialog.getSaveFileName(self, "导出全部漏洞内容", f"{level}_all_vuln.txt", "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for info_type in sorted(result[level].keys()):
                    for item in result[level][info_type]:
                        f.write(item + "\n\n")

    def export_vuln_content(self, content):
        path, _ = QFileDialog.getSaveFileName(self, "导出漏洞内容", "vuln.txt", "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

    def sort_result(self):
        file, _ = QFileDialog.getOpenFileName(self, "选择nuclei结果文件", "", "文本文件 (*.txt)")
        if not file:
            return
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QTextEdit, QTabWidget
        from collections import defaultdict
        result = defaultdict(lambda: defaultdict(list))
        total_count = 0
        try:
            with open(file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    level, info_type, content = parse_line(line)
                    result[level][info_type].append(content)
                    total_count += 1
        except Exception as e:
            QMessageBox.warning(self, "整理失败", f"读取结果文件失败: {e}")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("漏洞整理结果展示")
        dlg.resize(900, 600)
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"漏洞总量：{total_count}"))
        tabs = QTabWidget()
        for level in LEVEL_ORDER:
            if level not in result:
                continue
            tab = QTextEdit()
            tab.setReadOnly(True)
            text = []
            for info_type in sorted(result[level].keys()):
                text.append(f"--- [{info_type}] ---\n")
                for item in result[level][info_type]:
                    text.append(item + "\n")
            tab.setPlainText(''.join(text))
            tabs.addTab(tab, level.upper())
        layout.addWidget(tabs)
        dlg.setLayout(layout)
        dlg.exec_()


    def choose_exe(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择nuclei.exe", "", "可执行文件 (*.exe)")
        if path:
            self.exe_edit.setText(path)
            self.user_config["exe_path"] = path
            save_user_config(self.user_config)

    def choose_tpl(self):
        path = QFileDialog.getExistingDirectory(self, "选择nuclei-templates目录")
        if path:
            self.tpl_edit.setText(path)
            self.user_config["tpl_path"] = path
            save_user_config(self.user_config)

    def update_subcats(self):
        group = self.group_combo.currentText()
        self.subcat_list.clear()
        for cat in self.category_groups[group]:
            item = QListWidgetItem(cat)
            self.subcat_list.addItem(item)

    def add_new_subcat(self):
        group = self.group_combo.currentText()
        new_cat = self.new_subcat_edit.text().strip()
        if not new_cat:
            QMessageBox.warning(self, "提示", "新子类名不能为空！")
            return
        if new_cat in self.category_groups[group]:
            QMessageBox.warning(self, "提示", "该子类已存在！")
            return
        self.category_groups[group].append(new_cat)
        save_category_groups(self.category_groups)
        self.update_subcats()
        self.new_subcat_edit.clear()
        QMessageBox.information(self, "提示", f"已添加新子类：{new_cat}")

    def start_scan(self):
        exe = self.exe_edit.text().strip()
        tpl = self.tpl_edit.text().strip()
        target = self.target_edit.text().strip()
        group = self.group_combo.currentText()
        concurrency = self.concurrent_edit.text().strip() or "10"

        # 多选小类
        selected_items = self.subcat_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "提示", "请至少选择一个子类！")
            return
        subcats = [item.text() for item in selected_items]

        if not all([exe, tpl, target]):
            QMessageBox.warning(self, "提示", "请填写nuclei.exe、模板路径和目标！")
            return

        self.user_config["exe_path"] = exe
        self.user_config["tpl_path"] = tpl
        save_user_config(self.user_config)

        os.environ["PATH"] = os.path.dirname(exe) + ";" + os.environ.get("PATH", "")
        poc_paths = [os.path.join(tpl, c) for c in subcats]
        output_file = f"nuclei_results_{group}_{'_'.join(subcats)}_{os.getpid()}.txt"

        threading.Thread(target=self.run_nuclei, args=(exe, target, poc_paths, concurrency, output_file), daemon=True).start()

    def run_nuclei(self, exe, target, poc_paths, concurrency, output_file):
        self.progress_signal.emit(0)
        command = [
            exe, "-u", target,
            "-t", ",".join(poc_paths),
            "-c", str(concurrency),
            "-o", output_file,
            "-v"
        ]
        self.log_signal.emit(f"执行命令: {' '.join(command)}")
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,creationflags=0x08000000)
            total = 0
            for line in proc.stdout:
                self.log_signal.emit(line.strip())
                total += 1
                self.progress_signal.emit(min(100, total % 100))
            proc.wait()
            self.progress_signal.emit(100)
            self.log_signal.emit(f"扫描完成，结果文件: {output_file}")
            # 用信号通知主线程弹窗
            self.show_result_signal.emit(output_file)
        except Exception as e:
            self.log_signal.emit(f"运行出错: {e}")

    def sort_result(self):
        file, _ = QFileDialog.getOpenFileName(self, "选择nuclei结果文件", "", "文本文件 (*.txt)")
        if not file:
            return
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QTextEdit, QTabWidget
        from collections import defaultdict
        result = defaultdict(lambda: defaultdict(list))
        total_count = 0
        try:
            with open(file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    level, info_type, content = parse_line(line)
                    result[level][info_type].append(content)
                    total_count += 1
        except Exception as e:
            QMessageBox.warning(self, "整理失败", f"读取结果文件失败: {e}")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("漏洞整理结果展示")
        dlg.resize(900, 600)
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"漏洞总量：{total_count}"))
        tabs = QTabWidget()
        for level in LEVEL_ORDER:
            if level not in result:
                continue
            tab = QTextEdit()
            tab.setReadOnly(True)
            text = []
            for info_type in sorted(result[level].keys()):
                text.append(f"--- [{info_type}] ---\n")
                for item in result[level][info_type]:
                    text.append(item + "\n")
            tab.setPlainText(''.join(text))
            tabs.addTab(tab, level.upper())
        layout.addWidget(tabs)
        dlg.setLayout(layout)
        dlg.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # 确保NucleiGUI类已定义
    win = NucleiGUI()
    win.show()
    sys.exit(app.exec_())
