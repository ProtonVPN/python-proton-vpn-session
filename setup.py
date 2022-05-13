#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-vpn-session",
    version="0.0.1",
    description="ProtonVPN Session wrapper",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-protonvpn-session",
    install_requires=["requests", "bcrypt", "python-gnupg", "pyopenssl", "importlib-metadata; python_version < '3.8'","PyNaCl"],
    packages=find_namespace_packages(include=['proton.*']),
    include_package_data=True,
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
