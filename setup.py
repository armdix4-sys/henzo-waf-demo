from setuptools import setup
from Cython.Build import cythonize
import os

# البحث الديناميكي عن كافة ملفات python لتحويلها دون الاعتماد على مسارات مطلقة
setup(
    ext_modules=cythonize(
        ["protected_runtime/*.py"],
        compiler_directives={'language_level': "3"}
    )
)
