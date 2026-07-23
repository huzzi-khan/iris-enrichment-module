from setuptools import setup, find_packages

setup(
    name="iris-enrichment-module",
    version="1.0.0",
    author="Huzzi Khan",
    description="Automated IOC enrichment module for DFIR-IRIS — Cydea Tech",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
    "requests",
    "pyyaml",
    "dnspython",
    ],
    entry_points={
        "iris_module": [
            "iris_enrichment_module=iris_enrichment_module"
            ".IrisEnrichmentInterface:IrisEnrichmentModInterface",
        ]
    },
)