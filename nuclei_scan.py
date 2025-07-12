import json
import os.path
import subprocess
from urllib.parse import urlparse
from typing import List, Dict

from app.config import Config
from app import utils

logger = utils.get_logger()


class NucleiScan(object):
    # 常量定义
    RAD_TIMEOUT = 2 * 60 * 60  # 2小时
    AFROG_TIMEOUT = 2 * 60 * 60  # 2小时
    NUCLEI_TIMEOUT = 96 * 60 * 60  # 96小时

    def __init__(self, targets: List[str]):
        self.targets = targets
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        # 使用f-string格式化字符串
        self.nuclei_target_path = os.path.join(tmp_path, f"nuclei_target_{rand_str}.txt")
        self.nuclei_result_path = os.path.join(tmp_path, f"nuclei_result_{rand_str}.json")
        self.nuclei_bin_path = "nuclei"

    def _delete_file(self):
        """删除临时文件"""
        try:
            os.unlink(self.nuclei_target_path)
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
        except Exception as e:
            logger.warning(e)

    def _gen_target_file(self):
        """生成目标文件"""
        with open(self.nuclei_target_path, "w") as f:
            for domain in self.targets:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

    def dump_result(self) -> List[Dict[str, str]]:
        """解析nuclei的jsonl结果"""
        results = []
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"Nuclei result file not found: {self.nuclei_result_path}")
            return results
            
        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    item = {
                        "template_url": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", ""),
                        "vuln_url": data.get("host", ""),
                        "curl_command": data.get("curl-command", ""),
                        "target": data.get("host", "")
                    }
                    results.append(item)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON line: {line}")
                except Exception as e:
                    logger.error(f"Error parsing Nuclei result: {str(e)}")
        return results

    def run_rad_scan(self):
        """对每个目标运行RAD扫描"""
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
                
            try:
                parsed = urlparse(target)
                if not parsed.scheme or not parsed.netloc:
                    logger.warning(f"Invalid target format: {target}")
                    continue
                    
                domain = f"{parsed.scheme}://{parsed.netloc}"
                logger.info(f"Starting RAD scan for: {domain}")
                
                rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(4)}.txt")
                rad_cmd = [
                    "rad",
                    "-t", domain,
                    "-http-proxy", "172.18.0.1:7777",
                    "-text-output", rad_result_path
                ]
                
                logger.info(f"Executing rad command: {' '.join(rad_cmd)}")
                utils.exec_system(rad_cmd, timeout=self.RAD_TIMEOUT)
                logger.info(f"RAD scan completed for {domain}. Results saved to {rad_result_path}")
                
            except Exception as e:
                logger.error(f"RAD scan failed for {target}: {str(e)}")

    def exec_nuclei(self):
        """执行Nuclei扫描"""
        self._gen_target_file()

        command = [
            self.nuclei_bin_path, "-duc",
            "-severity", "low,medium,high,critical",
            "-type", "http",
            "-list", self.nuclei_target_path,
            "-jsonl",
            "-o", self.nuclei_result_path
        ]

        logger.info(" ".join(command))
        utils.exec_system(command, timeout=self.NUCLEI_TIMEOUT)

    def afrog_cmd(self):
        """执行afrog扫描命令"""
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
                
            try:
                parsed = urlparse(target)
                if not parsed.scheme or not parsed.netloc:
                    logger.warning(f"Invalid target format for afrog: {target}")
                    continue
                    
                domain = f"{parsed.scheme}://{parsed.netloc}"
                logger.info(f"Starting afrog scan for: {domain}")
                
                output_dir = "/tmp/test22"
                os.makedirs(output_dir, exist_ok=True)
                output_file = os.path.join(output_dir, f"afrog_{utils.random_choices(4)}.html")
                
                afrog_cmd = [
                    "./afrog",
                    "-t", domain,
                    "-S", "low,medium,high,critical",
                    "-oob", "alphalog",
                    "-o", output_file
                ]
                
                logger.info(f"Executing afrog command: {' '.join(afrog_cmd)}")
                utils.exec_system(afrog_cmd, timeout=self.AFROG_TIMEOUT)
                logger.info(f"afrog scan completed for {domain}. Results saved to {output_file}")
                
            except Exception as e:
                logger.error(f"afrog scan failed for {target}: {str(e)}")

    def run(self):
        """执行扫描流程"""
        # 1. 首先运行RAD扫描
        self.run_rad_scan()
        
        # 2. 运行afrog扫描
        self.afrog_cmd()
        
        # 3. 运行Nuclei扫描
        self.exec_nuclei()
        
        # 4. 解析Nuclei结果
        results = self.dump_result()

        # 5. 删除临时文件
        self._delete_file()

        return results


def nuclei_scan(targets: List[str]) -> List[Dict[str, str]]:
    """执行nuclei扫描的入口函数"""
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()
