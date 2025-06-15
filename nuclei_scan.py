import json
import os.path
import subprocess
import time

from app.config import Config
from app import utils

logger = utils.get_logger()

class NucleiScan:
    # 原有的NucleiScan类保持不变
    def __init__(self, targets: list):
        self.targets = targets
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.nuclei_target_path = os.path.join(tmp_path, "nuclei_target_{}.txt".format(rand_str))
        self.nuclei_result_path = os.path.join(tmp_path, "nuclei_result_{}.json".format(rand_str))
        self.nuclei_bin_path = "nuclei"
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
        try:
            os.unlink(self.nuclei_target_path)
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
        except Exception as e:
            logger.warning(e)

    def check_have_nuclei(self) -> bool:
        command = [self.nuclei_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if pro.returncode == 0:
                return True
        except Exception as e:
            logger.debug("{}".format(str(e)))
        return False

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
            while True:
                line = f.readline()
                if not line:
                    break
                try:
                    data = json.loads(line)
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
                    continue
        return results

    def exec_nuclei(self):
        self._gen_target_file()
        command = [
            self.nuclei_bin_path, "-duc",
            "-tags", "cve",
            "-severity", "low,medium,high,critical",
            "-type", "http",
            "-l", self.nuclei_target_path,
            self.nuclei_json_flag,
            "-stats",
            "-stats-interval", "60",
            "-o", self.nuclei_result_path
        ]
        logger.info(" ".join(command))
        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        if not self.check_have_nuclei():
            logger.warning("not found nuclei")
            return []
        self._check_json_flag()
        self.exec_nuclei()
        results = self.dump_result()
        self._delete_file()
        return results


class RadScan:
    def __init__(self, targets: list):
        self.targets = targets
        self.results = []
        self.rad_bin_path = "rad"
        self.tmp_path = Config.TMP_PATH

    def check_have_rad(self) -> bool:
        """检查系统中是否安装了rad"""
        command = [self.rad_bin_path, "-version"]
        try:
            pro = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return pro.returncode == 0
        except Exception:
            return False

    def run_rad(self, domain):
        """针对单个域名执行rad扫描"""
        rad_result_path = os.path.join(self.tmp_path, f"rad_result_{utils.random_choices(4)}.txt")
        
        rad_cmd = [
            self.rad_bin_path,
            "-t", domain,
            "-http-proxy", "172.18.0.1:7777",  # 代理参数
            "-text-output", rad_result_path
        ]
        
        logger.info(f"Starting Rad scan for: {domain}")
        logger.debug(" ".join(rad_cmd))
        
        try:
            # 执行扫描
            start_time = time.time()
            process = subprocess.run(
                rad_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=60*60  # 1小时超时
            )
            
            # 记录执行状态
            elapsed = time.time() - start_time
            if process.returncode == 0:
                logger.info(f"Rad scan for {domain} completed in {elapsed:.2f}s")
            else:
                logger.warning(f"Rad scan for {domain} failed with code {process.returncode} in {elapsed:.2f}s")
                logger.debug(f"Rad stderr: {process.stderr.decode()[:500]}")
            
            # 读取结果
            if os.path.exists(rad_result_path):
                with open(rad_result_path, "r") as f:
                    urls = [line.strip() for line in f if line.strip()]
                
                # 保存结果
                if urls:
                    self.results.append({
                        "target": domain,
                        "urls": urls,
                        "result_path": rad_result_path
                    })
                else:
                    # 没有结果时删除空文件
                    os.unlink(rad_result_path)
        except subprocess.TimeoutExpired:
            logger.error(f"Rad scan for {domain} timed out after 1 hour")
        except Exception as e:
            logger.error(f"Rad scan failed for {domain}: {str(e)}")
        finally:
            # 确保临时文件被清理（除非有结果需要保留）
            if "result_path" not in locals() or not os.path.exists(rad_result_path):
                return
            
            # 如果结果已经处理，删除临时文件
            for result in self.results:
                if result["result_path"] == rad_result_path:
                    try:
                        os.unlink(rad_result_path)
                        result.pop("result_path", None)  # 从结果中移除路径
                    except Exception:
                        pass
                    break

    def run(self):
        """执行rad扫描所有目标"""
        if not self.check_have_rad():
            logger.warning("Rad not found, skipping scan")
            return []
        
        logger.info(f"Starting Rad scan for {len(self.targets)} targets")
        
        for domain in self.targets:
            domain = domain.strip()
            if not domain:
                continue
            self.run_rad(domain)
        
        logger.info(f"Rad scan completed, found {sum(len(r['urls']) for r in self.results)} URLs")
        return self.results


def nuclei_scan(targets: list):
    """执行nuclei扫描"""
    if not targets:
        return []
    n = NucleiScan(targets=targets)
    return n.run()


def rad_scan(targets: list):
    """执行rad扫描"""
    if not targets:
        return []
    r = RadScan(targets=targets)
    return r.run()


# 示例使用方式
def run_full_scan(targets: list):
    """执行完整的扫描流程"""
    # 1. 先执行nuclei扫描
    logger.info("Starting Nuclei scan...")
    nuclei_results = nuclei_scan(targets)
    logger.info(f"Nuclei scan completed, found {len(nuclei_results)} vulnerabilities")
    
    # 2. 再执行rad扫描
    logger.info("Starting Rad scan...")
    rad_results = rad_scan(targets)
    logger.info(f"Rad scan completed, found {len(rad_results)} targets with URLs")
    
    # 3. 返回所有结果
    return {
        "nuclei": nuclei_results,
        "rad": rad_results
    }
