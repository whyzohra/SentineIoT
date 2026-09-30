"""Install the model dependency into the CDK Lambda layer before deployment."""

import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    target = root / "layer" / "python"
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(root / "layer-requirements.txt"),
                    "-t", str(target), "--platform", "manylinux2014_x86_64", "--only-binary=:all:",
                    "--implementation", "cp", "--python-version", "3.12", "--abi", "cp312"], check=True)
    print(f"Packaged Lambda dependencies in {target}")


if __name__ == "__main__":
    main()
