# Deliberately insecure — triggers CODE-01 CRITICAL patterns
import os
import subprocess


def run_task(task_code: str):
    """Execute arbitrary task code — eval() triggers CODE-01."""
    return eval(task_code)


def exec_script(script: str):
    """Execute script as statements — exec() triggers CODE-01."""
    exec(script)


def system_call(cmd: str):
    """Run OS command — os.system() triggers CODE-01."""
    return os.system(cmd)


def run_shell(cmd: str):
    """Run shell command — shell=True triggers CODE-01."""
    return subprocess.run(cmd, shell=True, capture_output=True)


def load_dynamic(module_name: str):
    """Import by name — __import__() triggers CODE-01."""
    mod = __import__(module_name)
    return mod
