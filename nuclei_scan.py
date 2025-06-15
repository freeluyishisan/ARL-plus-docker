import json
import os.path
import subprocess
import time

from app.config import Config
from app import utils

logger = utils.get_logger()

class NucleiScan(object):
    def __init__(self, targets: list):
        self.targets = targets
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        # 添加Rad相关文件路径
        self.rad_output_path = os.path.join(tmp_path, f"rad_output_{rand_str}.txt")
        self.rad_target_path = os.path.join(tmp_path, f"rad_target_{rand_str}.txt")
        
        self.nuclei_target_path = os.path.join(tmp_path, f"nuclei_target_{rand_str}.txt")
        self.nuclei_result_path = os.path.join(tmp_path, f"nuclei_result_{rand_str}.json")
        self.nuclei_bin_path = "nuclei"
        self.rad_bin_path = "rad"
        self.nuclei_json_flag = None

    def _check_json_flag(self):
        json_flag = ["-json", "-jsonl"]
        for x in json_flag:
            command = [self.nuclei_bin_path, "-duc", x, "-version"]
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                self.nuclei_json_flag = x
                return
        assert self.nuclei_json_flag

    def _delete_file(self):
        files_to_delete = [
            self.rad_target_path,
            self.rad_output_path,
            self.nuclei_target_path,
            self.nuclei_result_path
        ]
        for file_path in files_to_delete:
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    logger.warning(f"Failed to delete {file_path}: {e}")

    def check_have_rad(self) -> bool:
        command = [self.rad_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return pro.returncode == 0
        except Exception as e:
            logger.debug(f"Rad check error: {str(e)}")
            return False

    def check_have_nuclei(self) -> bool:
        command = [self.nuclei_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return pro.returncode == 0
        except Exception as e:
            logger.debug(f"Nuclei check error: {str(e)}")
            return False

    def _run_rad(self):
        """执行Rad爬虫收集URL"""
        # 创建Rad输入文件（域名列表）
        with open(self.rad_target_path, "w") as f:
            for domain in self.targets:
                domain = domain.strip()
                if domain:
                    f.write(domain + "\n")
        
        # 构建Rad命令
        rad_cmd = [
            self.rad_bin_path,
            "-t", self.rad_target_path,
            "-http-proxy", "172.18.0.1:7777",
            "-text-output", self.rad_output_path
        ]
        
        logger.info(f"Running Rad: {' '.join(rad_cmd)}")
        try:
            # 执行Rad并等待完成
            utils.exec_system(rad_cmd, timeout=24*60*60)
            time.sleep(5)  # 确保文件写入完成
        except Exception as e:
            logger.error(f"Rad execution failed: {str(e)}")
            raise

    def _process_rad_output(self):
        """处理Rad输出，准备Nuclei输入"""
        if not os.path.exists(self.rad_output_path):
            logger.warning("No Rad output found")
            return False

        # 读取Rad输出并去重
        unique_urls = set()
        with open(self.rad_output_path, "r") as f:
            for line in f:
                url = line.strip()
                if url:
                    unique_urls.add(url)
        
        # 写入Nuclei输入文件
        with open(self.nuclei_target_path, "w") as f:
            for url in unique_urls:
                f.write(url + "\n")
        
        return True

    def exec_nuclei(self):
        """执行Nuclei扫描"""
        command = [
            self.nuclei_bin_path,
            "-duc",
            "-tags", "cve",
            "-severity", "low,medium,high,critical",
            "-type", "http",
            "-l", self.nuclei_target_path,
            self.nuclei_json_flag,
            "-stats",
            "-stats-interval", "60",
            "-o", self.nuclei_result_path,
        ]
        
        logger.info("Starting Nuclei: " + " ".join(command))
        utils.exec_system(command, timeout=96*60*60)

    def dump_result(self) -> list:
        results = []
        if not os.path.exists(self.nuclei_result_path):
            return results
            
        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    results.append({
                        "template_url": data.get("template-url", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", ""),
                        "vuln_url": data.get("matched-at", ""),
                        "curl_command": data.get("curl-command", ""),
                        "target": data.get("host", "")
                    })
                except json.JSONDecodeError:
                    continue
        return results

    def run(self):
        if not self.check_have_rad():
            logger.warning("Rad not found, skipping scan")
            return []
        
        if not self.check_have_nuclei():
            logger.warning("Nuclei not found, skipping scan")
            return []
        
        self._check_json_flag()
        
        try:
            # 步骤1: 运行Rad爬虫
            self._run_rad()
            
            # 步骤2: 处理Rad输出
            if not self._process_rad_output():
                logger.warning("No valid URLs from Rad, skipping Nuclei")
                return []
                
            # 步骤3: 执行Nuclei扫描
            self.exec_nuclei()
            
            # 步骤4: 解析结果
            return self.dump_result()
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return []
        finally:
            self._delete_file()

def nuclei_scan(targets: list):
    return [] if not targets else NucleiScan(targets=targets).run()
