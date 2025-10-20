from setuptools import setup, find_packages
import os

def read_readme():
    with open('README.md', 'r', encoding='utf-8') as fh: return fh.read()

def read_requirements():
    with open('requirements.txt', 'r', encoding='utf-8') as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith('#')]
    
setup(
    name='ml-sdn-defense',
    version='1.0.0',
    author='jynoh00',
    author_email='wndus123sh@naver.com',
    description='Machine Learning-based Software Defined Network Defense System',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/jynoh00/ML-based_attack_defense_system_in-SDN',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Artificial Intelligence :: Machine Learning',
        'Topic :: Network :: Software Defined Network',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
    install_requires=read_requirements(),
    extras_require={
        'dev': [
            'pytest>=6.2.0',
            'pytest-cov>=3.0.0',
            'black>=21.0.0',
            'flake8>=3.9.0',
            'mypy>=0.910',
        ],
        'docs': [
            'sphinx>=4.0.0',
            'sphinx-rtd-theme>=0.5.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'ml-sdn-controller=sdn.ml_defense_controller:main',
            'ml-sdn-trainer=ml_models.ml_trainer:main',
            'ml-sdn-monitor=monitoring.real_time_monitor:main',
            'ml-sdn-topology=network.advanced_topology:main',
            'ml-sdn-attack-network.attack_simulator_enhanced:main',
        ],
    },
    include_package_data=True,
    package_data={
        '': ['*.yaml', '*.json', '*.txt'],
    },
    zip_safe=False
)