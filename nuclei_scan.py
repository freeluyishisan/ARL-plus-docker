import json
import os.path
import subprocess
from urllib.parse import urlparse

from app.config import Config
from app import utils

logger = utils.get_logger()

class NucleiScan(object):
    def __init__(self, targets: list):
        self.targets = []
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        self.nuclei_target_path = os.path.join(tmp_path,
                                               "nuclei_target_{}.txt".format(rand_str))

        self.nuclei_result_path = os.path.join(tmp_path,
                                               "nuclei_result_{}.json".format(rand_str))

        self.nuclei_bin_path = "nuclei"
        # Added: Initialize nuclei_json_flag
        self.nuclei_json_flag = None

    def _check_json_flag(self):
        """Check if Nuclei supports -json or -jsonl flag."""
        json_flag = ["-json", "-jsonl"]
        for x in json_flag:
            command = [self.nuclei_bin_path, "-duc", x, "-version"]
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                self.nuclei_json_flag = x
                return

        assert self.nuclei_json_flag, "Nuclei does not support -json or -jsonl"

    def _delete_file(self):
        try:
            os.unlink(self.nuclei_target_path)
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
        except Exception as e:
            logger.warning(e)

    def check_have_nuclei(self) -> bool:
        """Check if Nuclei binary is available."""
        command = [self.nuclei_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            logger.error(f"Nuclei check failed: {str(e)}")
        return False

    def _gen_target_file(self):
        with open(self.nuclei_target_path, "w") as f:
            for target in self.targets:
                target = target.strip()
                if not target:
                    continue
                f.write(target + "\n")

    def dump_result(self) -> list:
        results = []
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"Nuclei result file not found: {self.nuclei_result_path}")
            return results

        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    # Aligned with 1.py's mapping
                    item = {
                        "template_url": data.get("template-url", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", ""),
                        "vuln_url": data.get("matched-at", ""),
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
        """Run RAD scan for each target."""
        # Check if rad binary exists
        try:
            subprocess.run(["rad", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"RAD binary not found or failed: {str(e)}")
            return False

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

                rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(6)}.txt")

                rad_cmd = [
                    "rad",
                    "-t", domain,
                    "--http-proxy", "172.17.0.1:7777",
                    "-text-output", rad_result_path
                ]
                logger.info(f"Executing RAD command: {' '.join(rad_cmd)}")

                utils.exec_system(rad_cmd, timeout=6*60*60)
                logger.info(f"RAD scan completed for {domain}. Results saved to {rad_result_path}")
            except Exception as e:
                logger.error(f"RAD scan failed: for {str(e)}")

        return True

    def exec_nuclei(self):
        self._gen_target_file()

        command = [self.nuclei_bin_path, "-duc",
                   "-tags", "cve",
                   "-severity", "low,medium,high,critical",
                   "-type", "http",
                   "-l", self.nuclei_target_path,
                   self.nuclei_json_flag,
                   "-stats",
                   "-stats-interval", "60",
                   "-o", self.nuclei_result_path,
                   ]

        logger.info(" ".join(command))
        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        if not self.check_have_nuclei():
            logger.warning("Nuclei not found")
            return []

        self._check_json_flag()

        # Run RAD scan scan
        if not self.run_rad_scan():
            logger.warning("RAD scan failed, continuing with Nuclei scan")

        self.exec_nuclei()

        results = self.dump_result()

        self._delete_file()

        return results


def nuclei_scan(targets: list):
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()
