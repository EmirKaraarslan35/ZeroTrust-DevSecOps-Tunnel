import os
import subprocess
import json

import sys

class ScanEngineManager:
    def __init__(self, project_root):
        if getattr(sys, 'frozen', False):
            # If running as PyInstaller .exe, the physical root is where the .exe is.
            self.project_root = os.path.dirname(sys.executable)
        else:
            self.project_root = project_root
            
        self.venv_scripts = os.path.join(self.project_root, "venv", "Scripts")

    def get_tool_path(self, tool_name):
        # Look in the virtual environment first to avoid missing path errors
        venv_path = os.path.join(self.venv_scripts, f"{tool_name}.exe")
        if os.path.exists(venv_path):
            return venv_path
        
        venv_path_noext = os.path.join(self.venv_scripts, tool_name)
        if os.path.exists(venv_path_noext):
            return venv_path_noext
            
        return tool_name

    def run_semgrep(self, target_path):
        """Runs Semgrep on the target path."""
        cmd = [
            self.get_tool_path("semgrep"), 
            "scan", 
            "--config", "p/default", 
            "--config", "p/security-audit", 
            "--json", 
            "--quiet",
            target_path
        ]
        return self._run_command(cmd, target_path if os.path.isdir(target_path) else os.path.dirname(target_path))

    def run_detect_secrets(self, target_path):
        """Runs Detect-Secrets on the target path."""
        is_file = os.path.isfile(target_path)
        
        cmd = [self.get_tool_path("detect-secrets"), "scan"]
        if is_file:
            cmd.append(os.path.basename(target_path))
            cwd = os.path.dirname(target_path)
        else:
            # Bypass Windows absolute path bug
            cmd.extend(["--all-files", "."])
            cwd = target_path
            
        return self._run_command(cmd, cwd)

    def run_osv_scanner(self, target_path):
        """Runs OSV-Scanner on the target path."""
        cmd = [self.get_tool_path("osv-scanner"), "--json", "-r", target_path]
        return self._run_command(cmd, target_path if os.path.isdir(target_path) else os.path.dirname(target_path))

    def _run_command(self, cmd, cwd):
        """Helper to run commands robustly with UTF-8 replacement."""
        try:
            # CREATE_NO_WINDOW in Windows
            creationflags = 0x08000000 if os.name == 'nt' else 0
            
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                encoding="utf-8", 
                errors="replace", 
                creationflags=creationflags,
                cwd=cwd
            )
            stdout, stderr = process.communicate()
            return {
                "success": True,
                "stdout": stdout,
                "stderr": stderr,
                "returncode": process.returncode
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Araç bulunamadı: {cmd[0]}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
