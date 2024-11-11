import re
import logging
import os

logger = logging.getLogger(__name__)

# 白名单域名后缀
WHITELIST_SUFFIXES = {
    'pdd.net',
    'pinduoduo.com',
    # 可以添加更多白名单后缀
}

def is_whitelisted(domain):
    """
    检查域名是否在白名单中
    :param domain: 要检查的域名
    :return: 布尔值，表示域名是否在白名单中
    """
    return any(domain.endswith(suffix) for suffix in WHITELIST_SUFFIXES)

def is_valid_domain(domain):
    """
    验证域名是否有效且不在白名单中
    :param domain: 要验证的域名
    :return: 布尔值，表示域名是否有效且不在白名单中
    """
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,6}$'
    )
    match = pattern.match(domain)
    if not match:
        logger.debug(f"域名格式无效: {domain}")
        return False

    if is_whitelisted(domain):
        logger.info(f"域名在白名单中: {domain}")
        return False

    logger.debug(f"域名有效且不在白名单中: {domain}")
    return True

def extract_domain(connection_key):
    """
    从连接字符串中提取域名
    格式: src_ip:sport->dst_ip:dport
    """
    try:
        # 尝试提取域名样式的字符串
        domain_match = re.search(r'([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', connection_key)
        if domain_match:
            domain = domain_match.group(0)
            # 验证提取的字符串是否为有效域名且不在白名单中
            if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', domain):
                if is_whitelisted(domain):
                    logger.info(f"提取的域名在白名单中: {domain}")
                    return None
                return domain
    except Exception as e:
        logger.error(f"提取域名时发生错误: {str(e)}")

    return None

def add_domain_to_clash_config(domain):
    """
    将域名添加到clash配置文件的Custom部分
    """
    if not domain or not is_valid_domain(domain):
        logger.info(f"无效的域名或域名在白名单中: {domain}")
        return

    config_path = os.path.expanduser('~/.config/clash/clash_jms.yaml')

    try:
        with open(config_path, 'r') as f:
            lines = f.readlines()

        # 找到Custom部分
        custom_start = -1
        custom_end = -1
        for i, line in enumerate(lines):
            if '# Custom' in line:
                custom_start = i
            elif '# END Custom' in line:
                custom_end = i

        if custom_start == -1 or custom_end == -1:
            logger.error("未找到Custom配置区域")
            return

        # 检查域名是否已存在
        domain_entry = f"- DOMAIN-SUFFIX,{domain},PROXY\n"
        for line in lines[custom_start:custom_end]:
            if domain in line:
                logger.info(f"域名 {domain} 已存在于配置中")
                return

        # 在End Custom之前插入新域名
        lines.insert(custom_end, domain_entry)

        # 写回文件
        with open(config_path, 'w') as f:
            f.writelines(lines)

        logger.info(f"已将域名 {domain} 添加到clash配置文件")

    except Exception as e:
        logger.error(f"添加域名到配置文件时发生错误: {str(e)}")

__all__ = ['add_domain_to_clash_config', 'extract_domain']
