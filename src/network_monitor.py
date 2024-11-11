import threading
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP
import time
import logging
from modify_config import add_domain_to_clash_config, is_valid_domain
import queue
from ui_manager import DomainManagerUI, start_ui
from PyQt5.QtWidgets import QApplication

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 超时阈值（秒）
TIMEOUT_THRESHOLD = 10  # 调整为10秒
request_times = {}
lock = threading.Lock()  # 为了线程安全

# 候补域名队列
pending_domains = queue.Queue()

def packet_callback(packet):
    try:
        # DNS 请求监控
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            with lock:
                request_times[domain] = time.time()
            # logger.info(f"DNS 请求: {domain}")

        # TCP 连接监控
        elif packet.haslayer(IP) and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            sport = tcp_layer.sport
            dport = tcp_layer.dport
            connection_key = f"{src_ip}:{sport}->{dst_ip}:{dport}"

            if tcp_layer.flags == "S":  # SYN 包
                with lock:
                    request_times[connection_key] = time.time()
                # logger.info(f"SYN 包: {connection_key}")

            elif tcp_layer.flags.F or tcp_layer.flags.R:  # FIN 或 RST 包
                connection_key_reverse = f"{dst_ip}:{dport}->{src_ip}:{sport}"
                with lock:
                    start_time = request_times.get(connection_key_reverse)
                    if start_time:
                        elapsed_time = time.time() - start_time
                        if elapsed_time > TIMEOUT_THRESHOLD:
                            logger.warning(f"连接超时: {connection_key_reverse}, 耗时: {elapsed_time:.2f}秒")
                            # 检查域名有效性并添加到候补队列
                            if is_valid_domain(connection_key_reverse):
                                pending_domains.put(connection_key_reverse)
                                logger.info(f"域名 {connection_key_reverse} 添加到候补队列")
                        del request_times[connection_key_reverse]

    except Exception as e:
        logger.error(f"处理数据包时发生错误: {str(e)}")

def check_timeouts():
    """
    定期检查是否有超时的连接
    """
    while True:
        current_time = time.time()
        with lock:
            keys_to_delete = []
            for key, start_time in request_times.items():
                if current_time - start_time > TIMEOUT_THRESHOLD:
                    logger.warning(f"连接超时: {key}, 耗时: {current_time - start_time:.2f}秒")
                    keys_to_delete.append(key)
                    if is_valid_domain(key):
                      pending_domains.put(key)
                      logger.info(f"域名 {key} 添加到候补队列")
            for key in keys_to_delete:
                del request_times[key]
        time.sleep(TIMEOUT_THRESHOLD)  # 根据需要调整检查频率

def write_pending_domains():
    """
    处理候补域名队列并写入 YAML 配置文件
    """
    while True:
        domain = pending_domains.get()
        if domain:
            try:
                add_domain_to_clash_config(domain)
                logger.info(f"成功将域名 {domain} 添加到 Clash 配置文件")
            except Exception as e:
                logger.error(f"将域名 {domain} 添加到配置文件时发生错误: {str(e)}")
        pending_domains.task_done()

def start_monitoring(interface="any"):
    """
    开始网络监听
    :param interface: 网络接口名称
    """
    logger.info(f"开始在接口 {interface} 上监听网络流量...")

    try:
        # 初始化 QApplication
        app = QApplication([])

        # 启动定时检查线程
        timeout_thread = threading.Thread(target=check_timeouts, daemon=True)
        timeout_thread.start()

        # 创建UI
        ui = DomainManagerUI(pending_domains)
        ui.show()  # 显示UI窗口

        # 创建抓包线程
        sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=interface,
                filter="tcp or udp port 53",
                prn=packet_callback,
                store=0
            ),
            daemon=True
        )
        sniff_thread.start()

        # 在主线程中运行Qt事件循环
        app.exec_()

    except KeyboardInterrupt:
        logger.info("监听已停止")
    except Exception as e:
        logger.error(f"监听时发生错误: {str(e)}")

if __name__ == "__main__":
    start_monitoring("en0")
