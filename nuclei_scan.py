import json
import os
import subprocess
import time
from typing import List, Dict

from app.config import Config
from app import utils

logger = utils.get_logger()


class NucleiScan:
    # 常量定义
    NUCLEI_TIMEOUT = 96 * 60 * 60  # 96小时

    def __init__(self, targets: List[str]):
        self.targets = targets
        self.tmp_path = Config.TMP_PATH
        self.rand_str = utils.random_choices()

        # 临时文件路径（适配ARL文件管理）
        self.nuclei_target_path = os.path.join(self.tmp_path, f"nuclei_target_{self.rand_str}.txt")
        self.nuclei_result_path = os.path.join(self.tmp_path, f"nuclei_result_{self.rand_str}.jsonl")
        self.nuclei_bin_path = "nuclei"  # ARL默认路径

    def _cleanup(self):
        """安全删除临时文件（适配ARL资源回收机制）"""
        for path in [self.nuclei_target_path, self.nuclei_result_path]:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except Exception as e:
                logger.warning(f"清理临时文件失败: {path} - {str(e)}")

    def _gen_target_file(self):
        """生成目标文件（兼容ARL输入格式）"""
        try:
            with open(self.nuclei_target_path, "w") as f:
                for target in self.targets:
                    if target := target.strip():
                        f.write(target + "\n")
            logger.debug(f"生成目标文件: {self.nuclei_target_path}")
        except Exception as e:
            logger.error(f"创建目标文件失败: {str(e)}")
            raise

    def _parse_results(self) -> List[Dict]:
        """解析nuclei结果（严格匹配ARL数据结构）[3](@ref)"""
        results = []
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"结果文件不存在: {self.nuclei_result_path}")
            return results

        try:
            with open(self.nuclei_result_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        # 关键字段映射（适配ARL前端展示）
                        item = {
                            "template_id": data.get("template-id", ""),
                            "vuln_name": data.get("info", {}).get("name", ""),
                            "vuln_severity": data.get("info", {}).get("severity", "").lower(),
                            "vuln_url": data.get("matched-at", ""),
                            "curl_command": data.get("curl-command", ""),
                            "target": data.get("host", ""),
                            "description": data.get("info", {}).get("description", "")[:500]  # 防止过长
                        }
                        results.append(item)
                    except json.JSONDecodeError:
                        logger.warning(f"JSON解析失败: {line[:100]}...")
        except Exception as e:
            logger.error(f"结果解析异常: {str(e)}")
        return results

    def run(self) -> List[Dict]:
        """核心扫描逻辑（适配ARL任务调度）"""
        try:
            # 1. 生成目标列表
            self._gen_target_file()
            
            # 2. 执行Nuclei命令（参数优化）
            command = [
                self.nuclei_bin_path,
                "-jsonl",  # 强制JSONL格式[3](@ref)
                "-severity", "low,medium,high,critical",  # 默认扫描级别
                "-timeout", "10",  # 单请求超时
                "-rate-limit", "100",  # 限速防止封IP
                "-l", self.nuclei_target_path,
                "-o", self.nuclei_result_path
            ]
            logger.info(f"执行命令: {' '.join(command)}")
            
            # 使用subprocess替代os.system（避免僵尸进程）
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 实时日志输出（适配ARL任务监控）
            while True:
                stdout_line = process.stdout.readline()
                if stdout_line:
                    logger.debug(f"Nuclei: {stdout_line.strip()}")
                if process.poll() is not None and not stdout_line:
                    break
            
            # 3. 解析结果
            return self._parse_results()
            
        except subprocess.TimeoutExpired:
            logger.error("扫描超时")
            return []
        except Exception as e:
            logger.error(f"扫描异常: {str(e)}")
            return []
        finally:
            # 4. 资源清理（防止磁盘溢出）
            self._cleanup()


def nuclei_scan(targets: List[str]) -> List[Dict]:
    """ARL标准入口函数[3](@ref)"""
    if not targets:
        return []
    return NucleiScan(targets).run()
