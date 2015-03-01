#!/bin/sh
rm -f jwkest*
sphinx-apidoc -F -o ../doc/ ../src/jwkest
make clean
make html