from setuptools import setup, find_packages

setup(
    name='eagle_packets_scanner',
    version='1.8.5',
    packages=find_packages(),
    install_requires=[
        'blessed==1.18.1',
        'ipwhois==1.3.0',
        'mac-vendor-lookup==0.2.3',
        'psutil==5.8.0',
        'scapy==2.4.5',
        'termcolor==1.1.0',
        'tabulate==0.8.9'
    ],
    entry_points={
        'console_scripts': [
            'epscanner = eagle_packets_scanner:main'
        ]
    },
)
