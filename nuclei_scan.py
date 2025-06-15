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

    def _delete_file(self):
        try:
            os.unlink(self.nuclei_target_path)
            # 删除结果临时文件
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
        # 解析nuclei的jsonl结果
        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    # 映射nuclei字段到原有结构
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
        return results

    def exec_nuclei(self):
        self._gen_target_file()

        command = [
            self.nuclei_bin_path,
            "-list", self.nuclei_target_path,
            "-jsonl",
            "-o", self.nuclei_result_path
        ]

        logger.info(" ".join(command))

        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        self.exec_nuclei()
        results = self.dump_result()

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

        for domain in base_domains:
            # 在/tmp目录下创建结果文件
            rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(4)}.txt")
            
            rad_cmd = [
                "rad",
                "-t", domain,
                "-http-proxy", "172.18.0.1:7777",  # 添加代理参数
                "-text-output", rad_result_path
            ]
            logger.info(f"Executing rad command: {' '.join(rad_cmd)}")
            try:
                # 执行rad命令（超时设置为240小时）
                utils.exec_system(rad_cmd, timeout=240*60*60)
                logger.info(f"rad scan completed for {domain} with proxy. Results saved to {rad_result_path}")
            except Exception as e:
                logger.error(f"rad scan failed for {domain}: {str(e)}")

        # 删除临时文件
        self._delete_file()

        return results


def nuclei_scan(targets: list):
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()
