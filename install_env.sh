#!/usr/bin/env bash
sudo apt-get update
sudo apt-get install -y python3-dev python3-pip libffi-dev build-essential virtualenvwrapper

pip config set global.index-url 'https://mirrors.aliyun.com/pypi/simple'
pip config set global.timeout '120'
pip config set global.trusted-host 'mirrors.aliyun.com'

python -m pip install update && python -m pip install --upgrade pip
python3 -m pip install update && python3 -m pip install --upgrade pip

pip install pwntools==4.0.1

virtualenv --python=python3 angr_env
source ./angr_env/bin/activate

path=`pwd`
echo "alias angr_env='source $path/angr_env/bin/activate'" > ~/.bashrc
source ~/.bashrc
pip install angr==8.19.10.30
echo "has install angr in virtual python env"
echo "you can use 'angr_env' to switch virtual env"
deactivate
