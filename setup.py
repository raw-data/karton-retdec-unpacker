#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

version_path = Path(__file__).parent / "karton/retdec_unpacker/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setup(
    name="karton-retdec-unpacker",
    version=version_info["__version__"],
    description="RetDec unpacker module for the Karton framework",
    namespace_packages=["karton"],
    packages=["karton.retdec_unpacker"],
    url="https://github.com/raw-data/karton-retdec-unpacker",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "karton-retdec-unpacker=karton.retdec_unpacker:RetDecUnpacker.main"
        ],
    },
    classifiers=["Programming Language :: Python"],
)
