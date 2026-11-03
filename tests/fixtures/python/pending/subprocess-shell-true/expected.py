import subprocess


def list_dir(path):
    return subprocess.run(["ls", "-la"], shell=False, check=True, cwd=path)
