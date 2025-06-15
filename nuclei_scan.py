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

        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        self.nuclei_target_path = os.path.join(tmp_path,
                                               "nuclei_target_{}.txt".format(rand_str))

        self.nuclei_result_path = os.path.join(tmp_path,
                                               "nuclei_result_{}.json".format(rand_str))

        self.nuclei_bin_path = "nuclei"

        # 使用-jsonl参数（新版本nuclei）
        self.nuclei_json_flag = "-jsonl"

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
                if not domain:
                    continue
                f.write(domain + "\n")

    def dump_result(self) -> list:
        results = []
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"Nuclei result file not found: {self.nuclei_result_path}")
            return results
            
        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    item = {
                        "template_url": data.get("template-url", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", ""),
                        "vuln_url": data.get("matched-at", ""),
                        "curl_command": "",
                        "target": data.get("host", "")
                    }
                    results.append(item)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse nuclei result line: {line}, error: {e}")
        return results

    def exec_nuclei(self):
        self._gen_target_file()

        command = [
            self.nuclei_bin_path,
            "-list", self.nuclei_target_path,  # 使用-list参数加载目标列表
            self.nuclei_json_flag,
            "-o", self.nuclei_result_path,
            "-severity", "low,medium,high,critical",
            "-silent"  # 减少控制台输出
        ]

        logger.info("Running nuclei command: " + " ".join(command))

        try:
            # 使用subprocess.run以便更好地捕获输出和错误
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=24*60*60  # 24小时超时
            )
            
            if result.returncode != 0:
                logger.error(f"Nuclei failed with error:\n{result.stderr}")
            else:
                logger.info(f"Nuclei completed successfully. Output size: {len(result.stdout)} bytes")
                
        except subprocess.TimeoutExpired:
            logger.warning("Nuclei scan timed out")
        except Exception as e:
            logger.error(f"Error executing nuclei: {str(e)}")

    def run(self):
        logger.info("Starting nuclei scan...")
        self.exec_nuclei()
        results = self.dump_result()
        logger.info(f"Nuclei scan completed. Found {len(results)} results.")

        # 提取唯一的基域名（协议+域名+端口）
        base_domains = set()
        for item in results:
            url = item.get("target", "")
            if url:
                try:
                    parsed = urlparse(url)
                    if parsed.scheme and parsed.netloc:
                        base_url = f"{parsed.scheme}://{parsed.netloc}"
                        base_domains.add(base_url)
                except Exception as e:
                    logger.warning(f"URL parse error for {url}: {str(e)}")

        # 执行rad扫描
        if base_domains:
            logger.info(f"Starting rad scan for {len(base_domains)} base domains...")
            for domain in base_domains:
                rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(4)}.txt")
                
                rad_cmd = [
                    "rad",
                    "-t", domain,
                    "-http-proxy", "172.18.0.1:7777",
                    "-text-output", rad_result_path
                ]
                logger.info(f"Executing rad command: {' '.join(rad_cmd)}")
                try:
                    utils.exec_system(rad_cmd, timeout=240*60*60)
                    logger.info(f"rad scan completed for {domain}")
                except Exception as e:
                    logger.error(f"rad scan failed for {domain}: {str(e)}")

        # 删除临时文件
        self._delete_file()

        return results


def nuclei_scan(targets: list):
    if not targets:
        logger.warning("No targets provided for nuclei scan")
        return []

    logger.info(f"Initializing nuclei scan for {len(targets)} targets")
    n = NucleiScan(targets=targets)
    return n.run()
