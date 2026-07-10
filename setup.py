from setuptools import setup, find_packages

setup(
    name="iris-enrichment-module",
    version="1.0.0",
    author="Huzzi Khan",
    author_email="",
    description="Automated IOC enrichment module for DFIR-IRIS — Cydea Tech",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests",
        "pyyaml",
        "iris-module-interface>=1.1.0",
    ],
    entry_points={
        "iris_module": [
            "iris_enrichment_module=iris_enrichment_module"
            ".IrisEnrichmentInterface:IrisEnrichmentModInterface",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)