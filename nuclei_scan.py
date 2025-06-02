import json
import os.path
import subprocess
import logging

from app import utils

# 配置日志到 /tmp/
rand_str = utils.random_choices()
log_file = f"/tmp/nuclei_scan_{rand_str}.log"
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NucleiScan(object):
    def __init__(self, targets: list):
        self.targets = targets
        logger.debug(f"初始化 NucleiScan，目标数量: {len(targets)}, 目标: {targets}")

        tmp_path = "/tmp"
        rand_str = utils.random_choices()

        self.nuclei_target_path = os.path.join(tmp_path, f"nuclei_target_{rand_str}.txt")
        self.nuclei_result_path = os.path.join(tmp_path, f"nuclei_result_{rand_str}.json")
        self.vscan_result_path = os.path.join(tmp_path, f"vscan_result_{rand_str}.json")
        self.rad_output_path = os.path.join(tmp_path, f"rad_output_{rand_str}.txt")

        self.nuclei_bin_path = "nuclei"
        self.vscan_bin_path = "vscan"
        self.rad_bin_path = "rad"

        self.nuclei_json_flag = None
        logger.debug(f"临时文件路径: target={self.nuclei_target_path}, rad_output={self.rad_output_path}")

    def _delete_file(self):
        logger.debug("跳过文件删除，保留所有临时文件")

    def _gen_target_file(self):
        try:
            logger.debug(f"开始生成目标文件: {self.nuclei_target_path}")
            if not self.targets:
                logger.error("目标列表为空，无法生成目标文件")
                raise ValueError("目标列表为空")
            with open(self.nuclei_target_path, "w") as f:
                for domain in self.targets:
                    domain = domain.strip()
                    if not domain:
                        continue
                    f.write(domain + "\n")
            logger.info(f"成功生成目标文件: {self.nuclei_target_path}")
        except Exception as e:
            logger.error(f"生成目标文件失败: {e}")
            raise

    def dump_result(self) -> list:
        results = []
        try:
            logger.debug(f"开始解析 vscan 结果: {self.vscan_result_path}")
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
            logger.info(f"成功解析 vscan 结果，条目数: {len(results)}")
        except Exception as e:
            logger.error(f"解析 vscan 结果失败: {e}")
        return results

    def exec_nuclei(self):
        self._gen_target_file()

        # 执行 rad 命令（移除 -http-proxy）
        rad_command = [
            self.rad_bin_path,
            f"-t {self.nuclei_target_path}",
            "-text-output", self.rad_output_path
        ]
        logger.info(f"运行 rad 命令: {' '.join(rad_command)}")
        print(rad_command)
        try:
            result = subprocess.run(
                rad_command,
                capture_output=True,
                text=True,
                timeout=3600
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
        logger.debug("开始运行 NucleiScan")
        self.exec_nuclei()
        results = self.dump_result()
        self._delete_file()
        logger.debug(f"扫描完成，结果条目数: {len(results)}")
        return results

def nuclei_scan(targets: list):
    if not targets:
        logger.warning("目标列表为空")
        return []
    logger.debug(f"启动 nuclei_scan，目标: {targets}")
    n = NucleiScan(targets=targets)
    return n.run()
