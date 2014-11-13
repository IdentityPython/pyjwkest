#!/usr/bin/python

import sys
import pytest

sys.path.append('./src')
sys.path.append('./tests')

if __name__ == '__main__':
    pytest.main(['tests'])

