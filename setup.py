# Copyright 2024 Eagle Eyes Prim
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.



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
            'epscanner = eagle_packets_scanner.main:main' 
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
