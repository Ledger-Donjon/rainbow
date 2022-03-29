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

from setuptools import setup, find_packages

setup(
    name="rainbow",
    install_requires=[
        "unicorn",
        "capstone>=4.0.0",
        "lief>=0.10.0",
        "intelhex",
        "colorama",
        "pygments",
    ],
    packages=find_packages(),
    package_data={'': ['*.pickle', '*.css']},
    version=1.0,
    author="Victor Servant",
    author_email="victor.servant@ledger.fr",
    description="Generic Unicorn tracer for side-channels",
)
