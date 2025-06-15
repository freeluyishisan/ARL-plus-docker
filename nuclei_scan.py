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

        # 在nuclei 2.9.1 中 将-json 参数改成了 -jsonl 参数。
        self.nuclei_json_flag = "-jsonl"

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
        if not os.path.exists(self.nuclei_result_path):
            return results

        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                # 解析nuclei结果
                item = {
                    "template_url": data.get("matched", ""),
                    "template_id": data.get("template", ""),
                    "vuln_name": data.get("info", {}).get("name", ""),
                    "vuln_severity": data.get("info", {}).get("severity", ""),
                    "vuln_url": data.get("matched", ""),
                    "curl_command": data.get("curl-command", ""),
                    "target": data.get("host", "")
                }
                results.append(item)

        return results

    def exec_nuclei(self):
        self._gen_target_file()

        command = [
            self.nuclei_bin_path,
            "-list", self.nuclei_target_path,
            self.nuclei_json_flag,
            "-o", self.nuclei_result_path
        ]

        logger.info(" ".join(command))
        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        self.exec_nuclei()
        results = self.dump_result()

        # 修复：直接从输入目标提取基域名，而不是依赖nuclei结果
        base_domains = set()
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
            try:
                # 确保目标有协议
                if not target.startswith("http"):
                    target = "http://" + target
                    
                parsed = urlparse(target)
                if parsed.scheme and parsed.netloc:
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    base_domains.add(base_url)
            except Exception as e:
                logger.warning(f"URL parse error for {target}: {str(e)}")

        # 确保至少有一个目标时执行rad扫描
        if base_domains:
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
        else:
            logger.warning("No valid base domains found for rad scan")

        # 删除临时文件
        self._delete_file()

        return results


def nuclei_scan(targets: list):
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()
