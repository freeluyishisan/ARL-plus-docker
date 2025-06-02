import json
import os.path
import subprocess
import logging

from app.config import Config
from app import utils

# 配置日志输出到 /tmp/
rand_str = utils.random_choices()
log_file = f"/tmp/nuclei_scan_{rand_str}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()  # 保留终端输出
    ]
)
logger = logging.getLogger(__name__)

class NucleiScan(object):
    def __init__(self, targets: list):
        self.targets = targets

        tmp_path = "/tmp"  # 明确使用 /tmp/
        rand_str = utils.random_choices()

        self.nuclei_target_path = os.path.join(tmp_path,
                                               f"nuclei_target_{rand_str}.txt")
        self.nuclei_result_path = os.path.join(tmp_path,
                                               f"nuclei_result_{rand_str}.json")
        self.vscan_result_path = os.path.join(tmp_path,
                                              f"vscan_result_{rand_str}.json")
        self.rad_output_path = os.path.join(tmp_path,
                                            f"rad_output_{rand_str}.txt")  # rad 输出到 /tmp/

        self.nuclei_bin_path = "nuclei"
        self.vscan_bin_path = "vscan"
        self.rad_bin_path = "rad"

        self.nuclei_json_flag = None

    def _delete_file(self):
        try:
            os.unlink(self.nuclei_target_path)
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
            if os.path.exists(self.vscan_result_path):
                os.unlink(self.vscan_result_path)
            # 不删除 rad_output_path 以便测试
        except Exception as e:
            logger.warning(f"删除文件失败: {e}")

    def _gen_target_file(self):
        try:
            with open(self.nuclei_target_path, "w") as f:
                for domain in self.targets:
                    domain = domain.strip()
                    if not domain:
                        continue
                    f.write(domain + "\n")
            logger.info(f"生成目标文件: {self.nuclei_target_path}")
        except Exception as e:
            logger.error(f"生成目标文件失败: {e}")
            raise

    def dump_result(self) -> list:
        results = []
        try:
            with open(self.vscan_result_path, "r") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    data = json.loads(line)
                    technologies_list = data.get("technologies", [])
                    poc_list = data.get("POC", [])
                    vuln_url_list = data.get("file-fuzz", [])
                    technologies = ", ".join(technologies_list)
                    curl_command = ", ".join(poc_list)
                    vuln_url = ", ".join(vuln_url_list)
                    item = {
                        "template_url": data.get("url", ""),
                        "template_id": "vscan",
                        "vuln_name": technologies,
                        "vuln_severity": "vscan",
                        "vuln_url": vuln_url,
                        "curl_command": curl_command,
                        "target": data.get("url", "")
                    }
                    results.append(item)
            logger.info(f"成功解析 vscan 结果: {self.vscan_result_path}")
        except Exception as e:
            logger.error(f"解析 vscan 结果失败: {e}")
        return results

    def exec_nuclei(self):
        self._gen_target_file()

        # 执行 rad 命令
        rad_command = [
            self.rad_bin_path,
            f"-t {self.nuclei_target_path}",
            #"-http-proxy", "127.0.0.1:7777",
            "-text-output", self.rad_output_path
        ]
        logger.info(f"运行 rad 命令: {' '.join(rad_command)}")
        print(rad_command)
        try:
            result = subprocess.run(
                rad_command,
                capture_output=True,
                text=True,
                timeout=3600  # 缩短为 1 小时，便于调试
            )
            logger.info(f"rad stdout: {result.stdout}")
            if result.stderr:
                logger.warning(f"rad stderr: {result.stderr}")
            if result.returncode != 0:
                logger.error(f"rad 执行失败，退出码: {result.returncode}")
            else:
                logger.info(f"rad 执行成功，输出文件: {self.rad_output_path}")
        except subprocess.TimeoutExpired:
            logger.error("rad 执行超时（1小时）")
        except Exception as e:
            logger.error(f"rad 执行失败: {e}")

        # 执行 vscan 命令
        vscan_command = [
            self.vscan_bin_path,
            f"-l {self.nuclei_target_path}",
            "-json",
            f"-o {self.vscan_result_path}",
        ]
        logger.info(f"运行 vscan 命令: {' '.join(vscan_command)}")
        print(vscan_command)
        try:
            utils.exec_system(vscan_command, timeout=96*60*60)
            logger.info("vscan 执行成功")
        except Exception as e:
            logger.error(f"vscan 执行失败: {e}")

    def run(self):
        self.exec_nuclei()
        results = self.dump_result()
        self._delete_file()
        return results

def nuclei_scan(targets: list):
    if not targets:
        logger.warning("目标列表为空")
        return []
    n = NucleiScan(targets=targets)
    return n.run()
