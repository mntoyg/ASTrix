import subprocess


def list_dir(path):
    return subprocess.run("ls -la", shell=True, check=True, cwd=path)
