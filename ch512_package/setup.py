from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import os
import sys
import subprocess

class BuildCH512(build_ext):
    def run(self):
        if sys.platform == 'win32':
            subprocess.run(['mingw32-make', '-f', 'Makefile.win'], check=True)
        else:
            subprocess.run(['make', 'clean'], check=False)
            subprocess.run(['make'], check=True)
        super().run()

setup(
    name='ch512-crypto',
    version='1.0.0',
    author='Underscore000_',
    description='CH512 - CrashHybrid 512-bit block cipher with GCM authentication',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license='MIT',
    packages=['ch512'],
    package_data={
        'ch512': [
            'bin/libch512.so',
            'bin/libch512.dylib', 
            'bin/ch512.dll',
            'bin/ch512_enc',
            'bin/ch512_dec'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: C',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
    ],
    python_requires='>=3.6',
    install_requires=['cffi>=1.15.0'],
)