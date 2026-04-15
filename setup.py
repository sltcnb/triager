#!/usr/bin/env python3
"""
Setup script for ForensicHarvester.
"""

from setuptools import setup, find_packages

setup(
    name='forensic-harvester',
    version='1.0.0',
    author='ForensicHarvester Team',
    description='Comprehensive Python-based forensic triage tool',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/example/forensic-harvester',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Forensics',
    ],
    python_requires='>=3.8',
    install_requires=[
        'pyyaml>=6.0',
        'tqdm>=4.65.0',
    ],
    extras_require={
        'full': [
            'yara-python>=4.3.0',
            'regipy>=2.0.0',
            'pytsk3>=20220826',
            'pyewf>=20220826',
            'pycryptodome>=3.18.0',
            'pyzipper>=0.3.4',
        ],
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'forensic-harvester=forensic_harvester:main',
        ],
    },
)
