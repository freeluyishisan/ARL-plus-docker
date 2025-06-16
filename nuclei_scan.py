import json
import os.path
import subprocess
from urllib.parse import urlparse

from app.config import Config
from app import utils

logger = utils.get_logger()

class NucleiScan(object):
    def __init__(self, targets: list):
        self.targets = targets
        self.nuclei_json_flag = None  # 初始化标志

        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        self.nuclei_target_path = os.path.join(tmp_path,
                                               "nuclei_target_{}.txt".format(rand_str))

        self.nuclei_result_path = os.path.join(tmp_path,
                                               "nuclei_result_{}.json".format(rand_str))

        self.nuclei_bin_path = "nuclei"

    def _check_json_flag(self):
        """修复：添加 JSON 参数检测方法"""
        json_flag = ["-json", "-jsonl"]
        for x in json_flag:
            command = [self.nuclei_bin_path, "-duc", x, "-version"]
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                self.nuclei_json_flag = x
                return
        assert self.nuclei_json_flag

    def check_have_nuclei(self) -> bool:
        """修复：添加 Nuclei 安装检查"""
        command = [self.nuclei_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return pro.returncode == 0
        except Exception as e:
            logger.debug(str(e))
            return False

    def _delete_file(self):
        try:
            if os.path.exists(self.nuclei_target_path):
                os.unlink(self.nuclei_target_path)
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
        except Exception as e:
            logger.warning(e)

    def _gen_target_file(self):
        with open(self.nuclei_target_path, "w") as f:
            for domain in self.targets:
                domain = domain.strip()
                if domain:
                    f.write(domain + "\n")

    def dump_result(self) -> list:
        results = []
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"Result file not found: {self.nuclei_result_path}")
            return results
            
        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    # 修复：字段映射与 1.py 保持一致
                    item = {
                        "template_url": data.get("template-url", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", ""),
                        "vuln_url": data.get("matched-at", ""),  # 修正为 matched-at
                        "curl_command": data.get("curl-command", ""),
                        "target": data.get("host", "")
                    }
                    results.append(item)
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"Parse error: {e}")

        return results

    def run_rad_scan(self):
        """优化：添加超时和错误处理"""
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
                
            try:
                parsed = urlparse(target)
                if not parsed.scheme or not parsed.netloc:
                    logger.warning(f"Invalid target: {target}")
                    continue
                
                domain = f"{parsed.scheme}://{parsed.netloc}"
                rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(6)}.txt")
                
                rad_cmd = [
                    "rad",
                    "-t", domain,
                    "-http-proxy", "172.18.0.1:7777",
                    "-text-output", rad_result_path
                ]
                
                # 添加超时和错误处理
                utils.exec_system(rad_cmd, timeout=4*60*60)
            except Exception as e:
                logger.error(f"RAD failed for {target}: {str(e)}")

    def exec_nuclei(self):
        self._gen_target_file()
        
        # 确保参数正确传递
        command = [
            self.nuclei_bin_path,
            "-duc",
            "-tags", "cve",  # 拆分为独立参数
            "-severity", "low,medium,high,critical",
            "-type", "http",
            "-l", self.nuclei_target_path,
            self.nuclei_json_flag,
            "-stats",
            "-stats-interval", "60",
            "-o", self.nuclei_result_path
        ]

        logger.info(" ".join(command))
        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        # 1. 按需运行 RAD（可选步骤）
        # self.run_rad_scan()  # 根据实际需求决定是否启用
        
        # 2. 检查 Nuclei 安装
        if not self.check_have_nuclei():
            logger.warning("Nuclei not installed")
            return []
        
        # 3. 检测 JSON 参数
        self._check_json_flag()
        
        # 4. 执行 Nuclei 扫描
        self.exec_nuclei()
        
        # 5. 处理结果
        results = self.dump_result()
        self._delete_file()
        return results

def nuclei_scan(targets: list):
    if not targets:
        return []
    return NucleiScan(targets).run()
