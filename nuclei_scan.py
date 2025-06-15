import json
import os
import subprocess
from urllib.parse import urlparse
from typing import List, Dict, Any

from app.config import Config
from app import utils

logger = utils.get_logger()

class NucleiScan:
    def __init__(self, targets: List[str]):
        self.targets = targets
        self.tmp_path = Config.TMP_PATH
        self.rand_str = utils.random_choices()
        
        self.nuclei_target_path = os.path.join(
            self.tmp_path, f"nuclei_target_{self.rand_str}.txt"
        )
        self.nuclei_result_path = os.path.join(
            self.tmp_path, f"nuclei_result_{self.rand_str}.json"
        )
        self.nuclei_bin_path = "nuclei"

    def _cleanup_files(self, file_paths: List[str]):
        """Clean up temporary files"""
        for path in file_paths:
            try:
                if path and os.path.exists(path):
                    os.unlink(path)
            except Exception as e:
                logger.warning(f"Error deleting file {path}: {str(e)}")

    def _gen_target_file(self):
        """Generate targets file for Nuclei"""
        with open(self.nuclei_target_path, "w") as f:
            for target in self.targets:
                target = target.strip()
                if target:
                    f.write(target + "\n")

    def dump_result(self) -> List[Dict[str, Any]]:
        """Parse Nuclei JSONL results"""
        if not os.path.exists(self.nuclei_result_path):
            logger.warning(f"Nuclei result file not found: {self.nuclei_result_path}")
            return []

        results = []
        with open(self.nuclei_result_path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    results.append({
                        "template_url": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "vuln_name": data.get("info", {}).get("name", ""),
                        "vuln_severity": data.get("info", {}).get("severity", ""),
                        "vuln_url": data.get("host", ""),
                        "curl_command": data.get("curl-command", ""),
                        "target": data.get("host", "")
                    })
                except Exception as e:
                    logger.error(f"Error parsing Nuclei result: {str(e)}")
        return results

    def run_rad_scan(self) -> List[str]:
        """Run RAD scans and return discovered URLs"""
        rad_results = []
        rad_files_to_clean = []
        
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
                logger.debug(f"Starting RAD scan for: {domain}")
                
                # Create temp result file
                rad_result_path = os.path.join(
                    self.tmp_path, f"rad_result_{utils.random_choices(4)}.txt"
                )
                rad_files_to_clean.append(rad_result_path)
                
                # Build RAD command
                rad_cmd = [
                    "rad",
                    "-t", domain,
                    "-http-proxy", Config.RAD_PROXY,  # Configurable proxy
                    "-text-output", rad_result_path
                ]
                
                # Execute RAD
                utils.exec_system(rad_cmd, timeout=4*60*60)
                
                # Collect results
                if os.path.exists(rad_result_path):
                    with open(rad_result_path, "r") as f:
                        rad_results.extend(
                            [line.strip() for line in f if line.strip()]
                        )
                logger.debug(f"RAD scan completed for {domain}")
                
            except Exception as e:
                logger.error(f"RAD scan failed for {target}: {str(e)}")
        
        # Cleanup RAD temp files
        self._cleanup_files(rad_files_to_clean)
        return list(set(rad_results))  # Return unique URLs

    def exec_nuclei(self, targets: List[str]):
        """Execute Nuclei scan with specified targets"""
        # Generate target file
        with open(self.nuclei_target_path, "w") as f:
            for target in targets:
                f.write(target + "\n")
        
        # Build Nuclei command
        command = [
            self.nuclei_bin_path,
            "-list", self.nuclei_target_path,
            "-jsonl",
            "-o", self.nuclei_result_path,
            "-severity", "low,medium,high,critical"
        ]
        logger.debug(f"Executing: {' '.join(command)}")
        
        # Execute Nuclei
        utils.exec_system(command, timeout=96*60*60)

    def run(self):
        """Main scan workflow"""
        # 1. Run RAD to discover additional URLs
        rad_urls = self.run_rad_scan()
        
        # 2. Combine initial targets and discovered URLs
        all_targets = list(set(self.targets + rad_urls))
        logger.info(f"Total targets for Nuclei scan: {len(all_targets)}")
        
        # 3. Run Nuclei scan
        self.exec_nuclei(all_targets)
        
        # 4. Parse and return results
        results = self.dump_result()
        
        # 5. Cleanup temporary files
        self._cleanup_files([self.nuclei_target_path, self.nuclei_result_path])
        
        return results


def nuclei_scan(targets: List[str]) -> List[Dict[str, Any]]:
    """Entry point for Nuclei scanning"""
    if not targets:
        return []
    return NucleiScan(targets=targets).run()
