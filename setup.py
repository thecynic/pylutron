#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name = 'pylutron',
    version = '0.2.1',
    license = 'MIT',
    description = 'Python library for Lutron RadioRA 2',
    author = 'Dima Zavin',
    author_email = 'thecynic@gmail.com',
    url = 'http://github.com/thecynic/pylutron',
    packages=find_packages(),
    classifiers = [
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Topic :: Home Automation',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=[],
    zip_safe=True,
)
