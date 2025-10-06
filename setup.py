#!/usr/bin/python
#
# Copyright (C) 2015 Umea Universitet, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import glob
import re
import io
from os.path import exists

from setuptools import setup

__author__ = 'rohe0002'

with open('src/jwkest/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name="pyjwkest",
    version=version,
    description="Python implementation of JWT, JWE, JWS and JWK",
    long_description=io.open('README.rst', encoding='utf-8').read() if exists("README.rst") else "",
    author="Roland Hedberg",
    author_email="roland@catalogix.se",
    license="Apache 2.0",
    url='https://github.com/IdentityPython/pyjwkest',
    packages=["jwkest"],
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5"],
    install_requires=["pycryptodomex", "requests", "six"],
    tests_require=['pytest'],
    zip_safe=False,
    scripts=glob.glob('script/*.py'),
)
