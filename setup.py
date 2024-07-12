from setuptools import setup, find_packages

packages = find_packages(where=".", include=["hsmk*"])

setup(
    packages=packages,
)
