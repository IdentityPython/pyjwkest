#!/usr/bin/env python
import sys
from jwkest import jwe
from jwkest import jws

__author__ = 'roland'

jwt = open(sys.argv[1]).read()

_jw = jwe.factory(jwt)
if _jw:
    print("jwe")
else:
    _jw = jws.factory(jwt)
    if _jw:
        print("jws")
        print(_jw.jwt.headers)
        print(_jw.jwt.part[1])
