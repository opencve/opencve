from pathlib import Path

from setuptools import find_packages, setup


with open(
    Path(__file__).parent.resolve() / "opencve" / "VERSION", encoding="utf-8"
) as ver:
    version = ver.readline().rstrip()

with open("requirements.txt", encoding="utf-8") as req:
    requirements = [r.rstrip() for r in req.readlines()]


dev_requirements = [
    "pytest==5.4.1",
    "pytest-cov==2.11.1",
    "pytest-freezegun==0.4.2",
    "black==20.8b1",
    "beautifulsoup4==4.9.3",
]
sendmail_requirements = ["Flask-Sendmail-ng==0.3"]


setup(
    name="opencve",
    version=version,
    author="Nicolas Crocfer",
    author_email="ncrocfer@gmail.com",
    description="CVE Alerting Platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/opencve/opencve",
    packages=find_packages(),
    install_requires=requirements,
    extras_require={"dev": dev_requirements, "sendmail": sendmail_requirements},
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    entry_points={"console_scripts": ["opencve=opencve.cli:cli"]},
    python_requires=">=3.6",
)
