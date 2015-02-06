#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2015 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
from distutils.core import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "vuln2bugs",
    version = "1.0.0",
    author = "Guillaume Destuynder",
    author_email = "gdestuynder@mozilla.com",
    description = ("A glue program to manage bugzilla bugs for vulnerabilities"),
    license = "MPL",
    keywords = "bugzilla vulnerabilities",
    url = "https://github.com/gdestuynder/vuln2bugs",
    long_description=read('README.rst'),
	requires=['Bugsy', 'pyes', 'pytz', 'dateutil', 'hjson'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: System :: Logging",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    ],
)
