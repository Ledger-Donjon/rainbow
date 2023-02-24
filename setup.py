# This file is part of rainbow 
#
# rainbow is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#
# Copyright 2019 Victor Servant, Ledger SAS
# Copyright 2023 Jan Jancar

from setuptools import setup, find_packages

setup(
    name="rainbow",
    version="2.0",
    author="Victor Servant",
    author_email="victor.servant@ledger.fr",
    description="Generic Unicorn tracer for side-channels",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    package_data={'': ['*.pickle']},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Emulators",
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research"
    ],
    python_requires='>=3.7',
    install_requires=[
        "unicorn~=1.0",
        "capstone>=4.0.0",
        "lief>=0.10.0",
        "intelhex",
        "colorama",
        "pygments",
        "numpy",
        "PyQt5"
    ],
    extras_require={
        "examples": ["visplot @ git+https://github.com/Ledger-Donjon/visplot#egg=visplot", "lascar", "pycryptodome"]
    }
)
