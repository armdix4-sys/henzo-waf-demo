from pathlib import Path

from setuptools import setup
from Cython.Build import cythonize

source = Path(__file__).resolve().parent.parent / "src_backup" / "shieldcore_waf.py"

setup(
    name="henzo_waf_native",
    ext_modules=cythonize([str(source)], language_level=3),
    script_args=["build_ext", "--inplace"],
)
