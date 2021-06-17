"""Crypt4GH GUI for SDS."""

from setuptools import setup

setup(
    name="crypt4sds",
    version="0.1.0",
    license="Apache-2.0",
    author="CSC - IT Center for Science Ltd.",
    author_email="",
    description="Encryption and uploading tool.",
    long_description="",
    entry_points={"console_scripts": ["crypt4sds=sds.crypt4SDS_gui:main"]},
    platforms="any",
    packages=["sds"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.6",
    ],
    install_requires=["crypt4gh"],
)
