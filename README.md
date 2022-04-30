# CFGFuzz
This is a simple test case generation method based on control flow diagram. The control flow generation tool we rely on is ANGR, and we also rely on a fuzzer with Drille as this tool. In fact, this tool can be used to generate test cases for the fuzzier used.

## Licences
 CFGFuzz is an extension of American Fuzzy Lop written and maintained by Michał Zalewski <lcamtuf@google.com>. For details on American Fuzzy Lop, we refer to README-AFL.md.

AFL: Copyright 2013, 2014, 2015, 2016 Google Inc. All rights reserved. Released under terms and conditions of Apache License, Version 2.0.

## Installation (16.04 64-bit)
It is recommended that PyEnv be installed to control the Python version
```
git clone git://github.com/yyuu/pyenv.git ~/.pyenv
 
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
 
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
 
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
 
exec $SHELL -l
```
### Prerequisites
```
sudo apt-get install libc6-dev gcc

sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm
```
### install python 
```
pyenv install 3.7.0 -v

pyenv rehash

pyenv install 2.7.17 -v

pyenv global 3.7.0 
```
### install angr
```
sudo python -m pip install --upgrade pip

pip install angr
```
### install AFL
```
sudo apt install build-essential libtool-bin automake bison flex python libglib2.0-dev

mkdir ~/driller

cd ~/driller

wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz

tar xf afl-2.52b.tgz

cd afl-2.52b

make

cd qemu_mode

wget -O patches/memfd.diff https://salsa.debian.org/qemu-team/qemu/raw/ubuntu-bionic-2.11/debian/patches/ubuntu/lp1753826-memfd-fix-configure-test.patch
sed -i '/syscall.diff/a patch -p1 <../patches/memfd.diff || exit 1' build_qemu_support.sh

pyenv global 2.7.17 

 ./build_qemu_support.sh
 
pyenv global 3.7.0 
```
### install Driller
```
sudo apt install python3 virtualenv git python3-dev

cd ~/driller
```
### Setting up the Virtual Environment
```
which python

virtualenv -p <python path> ENV
```
### Activate/exit the virtual environment
```
cd ENV

source bin/activate

cd ..
```
### Install Driller in a virtual environment
The source code to install
```
$ pip install git+https://github.com/angr/archinfo
$ pip install git+https://github.com/angr/cle
$ pip install git+https://github.com/angr/claripy
$ pip install git+https://github.com/angr/angr
$ pip install git+https://github.com/angr/tracer
$ pip install git+https://github.com/shellphish/driller
```
or
`pip install driller`
## Usage
`python run.py <Binary program> <fuzzer_output_dir>`
## Tutorial
The test file contains the test program
 Start the AFL
  
  `afl-fuzz -i <test case input> -o <The output> -m none -d -Q -- <Program execution command>`
 
 `python run.py <Binary program> <fuzzer_output_dir>`
  
We integrate that into shellphuzz as well

 ` cd fuzzer`
 
 `shellphuzz -d 1 -c 1 -w <The output path> -C --length-extension 4 <Program execution command> `
