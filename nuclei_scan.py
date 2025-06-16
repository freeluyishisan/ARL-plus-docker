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
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"Nuclei result file not found: {self.nuclei_result_path}")
            return results
            
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
                # 解析URL获取基域名
                parsed = urlparse(target)
                if not parsed.scheme or not parsed.netloc:
                    logger.warning(f"Invalid target format: {target}")
                    continue
                    
                domain = f"{parsed.scheme}://{parsed.netloc}"
                
                logger.info(f"Starting RAD scan for: {domain}")
                
                # 在/tmp目录下创建结果文件
                rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(6)}.txt")
                
                rad_cmd = [
                    "rad",
                    "-t", domain,
                    "-http-proxy", "172.18.0.1:7777",  # 添加代理参数
                    "-text-output", rad_result_path
                ]
                logger.info(f"Executing rad command: {' '.join(rad_cmd)}")
                
                # 执行rad命令（超时设置为4小时）
                utils.exec_system(rad_cmd, timeout=6*60*60)
                logger.info(f"RAD scan completed for {domain}. Results saved to {rad_result_path}")
                
            except Exception as e:
                logger.error(f"RAD scan failed for {target}: {str(e)}")

    def exec_nuclei(self):
        self._gen_target_file()

        command = [self.nuclei_bin_path, "-duc",
                   "-tags cve",
                   "-severity low,medium,high,critical",
                   "-type http",
                   "-l {}".format(self.nuclei_target_path),
                   self.nuclei_json_flag,  # 在nuclei 2.9.1 中 将 -json 参数改成了 -jsonl 参数
                   "-stats",
                   "-stats-interval 60",
                   "-o {}".format(self.nuclei_result_path),
                   ]

        logger.info(" ".join(command))

        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        # 1. 首先运行RAD扫描
        self.run_rad_scan()
        
        # 2. 运行Nuclei扫描
        self.exec_nuclei()
        
        # 3. 解析Nuclei结果
        results = self.dump_result()

        # 4. 删除临时文件
        self._delete_file()

        return results


def nuclei_scan(targets: list):
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()
