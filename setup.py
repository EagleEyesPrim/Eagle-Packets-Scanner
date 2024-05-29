from setuptools import setup, find_packages

setup(
    name='eagle_packets_scanner',
    version='1.8.5',
    packages=find_packages(),
    install_requires=[
        'blessed',
        'ipwhois',
        'mac-vendor-lookup',
        'psutil',
        'scapy',
        'termcolor',
        'tabulate',
        'build'
    ],
    entry_points={
        'console_scripts': [
            'epscanner = eagle_packets_scanner:main'  # تأكد أن `main` هو دالة البدء في `eagle_packets_scanner`
        ]
    },
    author='Eagle Eyes Prim',
    description='Eagle Packets Scanner is a network monitoring and analysis tool.',
    long_description="""Eagle Packets Scanner is a powerful network tool for monitoring and analyzing network traffic in real-time. 
    It provides users with the ability to capture, inspect, and analyze packets flowing through their network interfaces. 
    With its intuitive interface and rich features, Eagle Packets Scanner is suitable for network administrators, cybersecurity professionals, and enthusiasts 
    who want to gain insights into their network activity.""",
    long_description_content_type='text/plain',
    url='https://github.com/EagleEyesPrim/eagle-packets-scanner',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'Topic :: Utilities'
    ],
    python_requires='>=3.8'
)
