import json
import os.path
import subprocess

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

        self.vscan_result_path = os.path.join(tmp_path,
                                              "vscan_result_{}.json".format(rand_str))

        self.nuclei_bin_path = "nuclei"
        self.vscan_bin_path = "vscan"
        self.rad_bin_path = "rad"  # Added path for rad binary

        # 在nuclei 2.9.1 中 将-json 参数改成了 -jsonl 参数。
        self.nuclei_json_flag = None

    def _delete_file(self):
        try:
            os.unlink(self.nuclei_target_path)
            # 删除结果临时文件
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
            if os.path.exists(self.vscan_result_path):
                os.unlink(self.vscan_result_path)
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
        # vscan结果
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

        return results

    def exec_nuclei(self):
        self._gen_target_file()

        # Execute rad command with proxy
        rad_command = [
            self.rad_bin_path,
            "-t {}".format(self.nuclei_target_path),
            "-http-proxy", "127.0.0.1:7777"
        ]
        logger.info(" ".join(rad_command))
        print(rad_command)
        utils.exec_system(rad_command, timeout=96*60*60)

        # Execute vscan command
        vscan_command = [
            self.vscan_bin_path,
            "-l {}".format(self.nuclei_target_path),
            "-json",
            "-o {}".format(self.vscan_result_path),
        ]
        logger.info(" ".join(vscan_command))
        print(vscan_command)
        utils.exec_system(vscan_command, timeout=96*60*60)

    def run(self):
        self.exec_nuclei()
        results = self.dump_result()
        # 删除临时文件
        self._delete_file()
        return results

def nuclei_scan(targets: list):
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()
