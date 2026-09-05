from setuptools import setup, find_packages

setup(
    name="meshkor",
    version="1.0.0",
    description="MeshKor SDK and Sidecar Daemon for Cryptographic AI Verification",
    packages=find_packages(include=["meshkor", "kormic", "kormic.*"]),
    install_requires=[
        "grpcio",
        "grpcio-tools",
        "protobuf",
        "pyyaml",
        "fastapi",
        "uvicorn",
        "requests"
    ],
    entry_points={
        "console_scripts": [
            "meshkor-sidecar=meshkor.cli:start_sidecar",
        ]
    },
)
