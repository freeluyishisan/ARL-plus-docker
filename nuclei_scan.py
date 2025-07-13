import json
import os.path
import subprocess
from urllib.parse import urlparse
from typing import List, Dict

from app.config import Config
from app import utils, db
from app.models import NucleiVulnerability  # 导入数据库模型

logger = utils.get_logger()


class NucleiScan(object):
    # 常量定义保持不变
    RAD_TIMEOUT = 2 * 60 * 60
    AFROG_TIMEOUT = 2 * 60 * 60
    NUCLEI_TIMEOUT = 96 * 60 * 60

    def __init__(self, targets: List[str]):
        self.targets = targets
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        self.nuclei_target_path = os.path.join(tmp_path, f"nuclei_target_{rand_str}.txt")
        self.nuclei_result_path = os.path.join(tmp_path, f"nuclei_result_{rand_str}.json")
        self.nuclei_bin_path = "nuclei"

    def _delete_file(self):
        """删除临时文件（保持不变）"""
        try:
            os.unlink(self.nuclei_target_path)
            if os.path.exists(self.nuclei_result_path):
                os.unlink(self.nuclei_result_path)
        except Exception as e:
            logger.warning(f"删除临时文件失败: {e}")

    def _gen_target_file(self):
        """生成目标文件（保持不变）"""
        with open(self.nuclei_target_path, "w") as f:
            for domain in self.targets:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

    def dump_result(self) -> List[Dict[str, str]]:
        """解析Nuclei的jsonl结果（保持解析逻辑，为数据库保存做准备）"""
        results = []
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"Nuclei结果文件未找到: {self.nuclei_result_path}")
            return results
            
        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    # 提取需要的字段（与数据库模型对应）
                    item = {
                        "template_url": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", "").lower(),  # 统一小写
                        "vuln_url": data.get("host", ""),
                        "curl_command": data.get("curl-command", ""),
                        "target": data.get("host", "")
                    }
                    results.append(item)
                except json.JSONDecodeError:
                    logger.warning(f"无效JSON行: {line}")
                except Exception as e:
                    logger.error(f"解析Nuclei结果失败: {str(e)}")
        return results

    def save_to_database(self, results: List[Dict[str, str]]):
        """将Nuclei结果保存到数据库"""
        if not results:
            logger.info("无Nuclei扫描结果需要保存到数据库")
            return

        for idx, item in enumerate(results, 1):
            try:
                # 检查是否已存在相同模板ID的记录（避免重复）
                existing = NucleiVulnerability.query.filter_by(template_id=item["template_id"]).first()
                if existing:
                    logger.debug(f"模板ID {item['template_id']} 已存在，跳过")
                    continue

                # 创建新记录
                new_record = NucleiVulnerability(
                    template_url=item["template_url"],
                    template_id=item["template_id"],
                    vuln_name=item["vuln_name"],
                    vuln_severity=item["vuln_severity"],
                    vuln_url=item["vuln_url"],
                    curl_command=item["curl_command"],
                    target=item["target"]
                )
                db.session.add(new_record)

                # 每100条提交一次（减少数据库压力）
                if idx % 100 == 0:
                    db.session.commit()
                    logger.info(f"已保存 {idx} 条Nuclei结果到数据库")

            except Exception as e:
                db.session.rollback()
                logger.error(f"保存第 {idx} 条结果到数据库失败: {str(e)}")

        # 提交剩余记录
        if idx % 100 != 0:
            try:
                db.session.commit()
                logger.info(f"全部Nuclei结果保存完成，共 {len(results)} 条")
            except Exception as e:
                db.session.rollback()
                logger.error(f"最终提交数据库失败: {str(e)}")

    def run_rad_scan(self):
        """RAD扫描（保持不变）"""
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
                
            try:
                parsed = urlparse(target)
                if not parsed.scheme or not parsed.netloc:
                    logger.warning(f"无效目标格式: {target}")
                    continue
                    
                domain = f"{parsed.scheme}://{parsed.netloc}"
                logger.info(f"开始RAD扫描: {domain}")
                
                rad_result_path = os.path.join("/tmp", f"rad_result_{utils.random_choices(4)}.txt")
                rad_cmd = [
                    "rad",
                    "-t", domain,
                    "-http-proxy", "172.18.0.1:7777",
                    "-text-output", rad_result_path
                ]
                
                logger.info(f"执行RAD命令: {' '.join(rad_cmd)}")
                utils.exec_system(rad_cmd, timeout=self.RAD_TIMEOUT)
                logger.info(f"RAD扫描完成，结果保存至: {rad_result_path}")
                
            except Exception as e:
                logger.error(f"RAD扫描失败: {str(e)}")

    def exec_nuclei(self):
        """执行Nuclei扫描（保持不变）"""
        self._gen_target_file()

        command = [
            self.nuclei_bin_path, "-duc",  # -duc: 禁用颜色输出
            "-severity", "info,low,medium,high,critical",
            "-type", "http",
            "-list", self.nuclei_target_path,
            "-jsonl",  # 输出为JSON行格式
            "-o", self.nuclei_result_path
        ]

        logger.info(f"执行Nuclei命令: {' '.join(command)}")
        utils.exec_system(command, timeout=self.NUCLEI_TIMEOUT)

    def afrog_cmd(self):
        """afrog扫描（保持不变）"""
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
                
            try:
                parsed = urlparse(target)
                if not parsed.scheme or not parsed.netloc:
                    logger.warning(f"afrog无效目标格式: {target}")
                    continue
                    
                domain = f"{parsed.scheme}://{parsed.netloc}"
                logger.info(f"开始afrog扫描: {domain}")
                
                output_dir = "/tmp/test22"
                os.makedirs(output_dir, exist_ok=True)
                output_file = os.path.join(output_dir, f"afrog_{utils.random_choices(4)}.html")
                
                afrog_cmd = [
                    "./afrog",
                    "-t", domain,
                    "-S", "low,medium,high,critical",  # 扫描级别
                    "-oob", "alphalog",  # 启用OOB日志
                    "-o", output_file  # 输出文件
                ]
                
                logger.info(f"执行afrog命令: {' '.join(afrog_cmd)}")
                utils.exec_system(afrog_cmd, timeout=self.AFROG_TIMEOUT)
                logger.info(f"afrog扫描完成，结果保存至: {output_file}")
                
            except Exception as e:
                logger.error(f"afrog扫描失败: {str(e)}")

    def run(self):
        """执行扫描流程（关键修改：添加数据库保存）"""
        # 1. 运行RAD扫描（结果存/tmp）
        self.run_rad_scan()
        
        # 2. 运行afrog扫描（结果存/tmp）
        self.afrog_cmd()
        
        # 3. 运行Nuclei扫描（结果后续存数据库）
        self.exec_nuclei()
        
        # 4. 解析Nuclei结果
        results = self.dump_result()
        logger.info(f"Nuclei解析结果数量: {len(results)}")
        
        # 5. 保存Nuclei结果到数据库
        self.save_to_database(results)
        
        # 6. 删除临时文件
        self._delete_file()

        return results


def nuclei_scan(targets: List[str]) -> List[Dict[str, str]]:
    """执行Nuclei扫描的入口函数（保持返回值，结果已存数据库）"""
    if not targets:
        return []
    
    n = NucleiScan(targets=targets)
    return n.run()
