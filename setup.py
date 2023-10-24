#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-vpn-session",
    version="0.6.2",
    description="ProtonVPN Session wrapper",
    author="Proton AG",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-protonvpn-session",
    install_requires=["proton-core", "proton-vpn-logger", "cryptography", "PyNaCl"],
    extras_require={
        "development": ["pytest", "pytest-coverage", "flake8", "pylint"]
    },
    packages=find_namespace_packages(include=['proton.*']),
    include_package_data=True,
    python_requires=">=3.8",
    license="GPLv3",
    platforms="OS Independent",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
