import json
import os.path
import subprocess
import time

from app.config import Config
from app import utils

logger = utils.get_logger()

class NucleiScan:
    # 原有的NucleiScan类保持不变
    # ...
    # 这里保留原有的NucleiScan实现
    # ...

class RadScan:
    def __init__(self, targets: list):
        self.targets = targets
        self.results = []
        self.rad_bin_path = "rad"

    def check_have_rad(self) -> bool:
        """检查系统中是否安装了rad"""
        command = [self.rad_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            logger.debug(f"Rad not found: {str(e)}")
        return False

    def run_rad(self, domain):
        """针对单个域名执行rad扫描"""
        # 创建临时结果文件
        rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(4)}.txt")
        
        # 构建rad命令
        rad_cmd = [
            self.rad_bin_path,
            "-t", domain,
            "-http-proxy", "172.18.0.1:7777",  # 代理参数
            "-text-output", rad_result_path
        ]
        
        logger.info(f"Starting Rad scan for: {domain}")
        logger.debug(" ".join(rad_cmd))
        
        try:
            # 执行扫描
            start_time = time.time()
            subprocess.run(rad_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60*60)
            elapsed = time.time() - start_time
            logger.info(f"Rad scan for {domain} completed in {elapsed:.2f} seconds")
            
            # 读取结果
            if os.path.exists(rad_result_path):
                with open(rad_result_path, "r") as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            self.results.append({
                                "target": domain,
                                "url": url,
                                "type": "rad"
                            })
                
                # 删除临时文件
                os.unlink(rad_result_path)
        except Exception as e:
            logger.error(f"Rad scan failed for {domain}: {str(e)}")

    def run(self):
        """执行rad扫描所有目标"""
        if not self.check_have_rad():
            logger.warning("Rad not found, skipping scan")
            return []
        
        for domain in self.targets:
            domain = domain.strip()
            if not domain:
                continue
            self.run_rad(domain)
        
        return self.results

def nuclei_scan(targets: list):
    # 原有的nuclei_scan函数保持不变
    # ...
    # 这里保留原有的nuclei_scan实现
    # ...

def rad_scan(targets: list):
    """执行rad扫描"""
    if not targets:
        return []
    
    r = RadScan(targets=targets)
    return r.run()

# 在您的扫描流程中，可以这样调用：
# 先执行nuclei扫描
# nuclei_results = nuclei_scan(targets)

# 然后执行rad扫描（使用相同的目标列表）
# rad_results = rad_scan(targets)
