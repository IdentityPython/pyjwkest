.. _install:

Quick install guide
###################

Before you can use pyJWKEST, you'll need to get it installed. This guide
will guide you to a simple, minimal installation.

Install pyJWKEST
================

For all this to work you need to have Python installed.
The development has been done using 2.7.
There will shortly be a 3.4 version.

Prerequisites
=============

For installing pyJWKEST you will need

* pycrypto

and for running the examples:

* mako
* cherrypy
* beaker
* pyOpenSSL
* argparse
* importlib
* M2Crypto
* swig

For running the tests you will additionally need to install:

* pytest

Debian/Mac
==========

If you don't want to install pyjwkest and all it's dependencies manually you can use yais

Open a terminal and enter::

    git clone https://github.com/its-dirg/yais [your path]
    cd [your path]
    sudo python setup.py install
    cd [your path]/yais/script
    ./yais.sh

On the question “Do you want to install pyjwkest (Y/n):”, type Y. Everything else should be ignored, by typing n. The script will install pyjwkest and all it's dependencies.

Quick build instructions
------------------------

Once you have installed all the necessary prerequisites a simple::

    python setup.py install

will install the basic code.

Note for rhel/centos 6: cffi depends on libffi-devel, and cryptography on
openssl-devel to compile. So you might want first to do:
yum install libffi-devel openssl-devel

After this you ought to be able to run the tests without an hitch.
The tests are based on the pypy test environment, so::

    cd tests
    py.test

is what you should use. If you don't have py.test, get it it's part of pypy!
It's really good!
