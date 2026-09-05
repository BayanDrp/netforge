import subprocess
from pathlib import Path

from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup


def pkg_config(*args):
    try:
        out = subprocess.check_output(
            ["pkg-config", *args, "libpcap"], text=True
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return out.split() if out else []


sources = sorted(str(p.relative_to(".")) for p in Path("src").glob("**/*.cpp") if p.name != "pcap.cpp")
sources.append("bindings/module.cpp")

include_dirs = ["include"]
extra_compile_args = []
for flag in pkg_config("--cflags"):
    (include_dirs if flag.startswith("-I") else extra_compile_args).append(
        flag[2:] if flag.startswith("-I") else flag
    )

ext = Pybind11Extension(
    "netforge._netforge",
    sources,
    include_dirs=include_dirs,
    cxx_std=17,
    extra_compile_args=["-O2"] + extra_compile_args,
    extra_link_args=pkg_config("--libs-only-l") + pkg_config("--libs-only-L"),
)

setup(ext_modules=[ext], cmdclass={"build_ext": build_ext})