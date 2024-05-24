from setuptools import setup, find_packages

setup(
    name='eagle_packets_scanner',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'scapy',
        'ipwhois'
    ],
    entry_points={
        'console_scripts': [
            'eagle_scanner = eagle_packets_scanner:main',
        ],
    },
)
