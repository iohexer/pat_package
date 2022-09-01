#! /usr/bin/env python
# coding: utf-8
import os
import re
import json
import pdb
from collections import *

# load gremlin
try:
    from gremlins.gremlin_handler import *
except ImportError:
    _gremlin_load_fail = True

gremlin = gremlinHandler()


# logging
def logging(func):
    def wrapper(*args, **kwargs):
        print(color['yellow'])
        print("[!] %s..."%func.__name__)
        temp_file = 'Info/'+func.__name__+'.json'
        if os.path.exists(temp_file):
            print("[!] has backup")
        print(color['reset'])
        func(*args, **kwargs)
    return wrapper


# exception
class Abort(Exception):
    pass


# shell colorful
color = {'red':'\033[91m', 'green':'\033[92m', 'yellow':'\033[93m', 'blue':'\033[94m', 'reset':'\033[0m', 'apple':'\033[90m'}


_apple = '\033[90m'
_red = '\033[91m'
_green = '\033[92m'
_banana = '\033[93m'
_blue = '\033[94m'
_reset = '\033[0m'


# banner
print(color['red'])
print( '''
______  ___ _____ 
| ___ \/ _ \_   _|
| |_/ / /_\ \| |  
|  __/|  _  || |  
| |   | | | || |  
\_|   \_| |_/\_/
''')
print(color['reset'])


def real_path(cpg_node, proj="works/pie-register"):
    path_info = "/Users/he/www/"+proj+"/"
    _info = ""
    for k, v in cpg_node.items():
        if k == 'file_name':
            _info =  v.replace("/cpg", path_info)
        if k == 'lineno':
            _info += ":" + str(v)
        if k == 'type':
            print(v+ ": ")
        if k == 'id':
            print(v)
    return _info


if __name__ == '__main__':
    for k, v in color.items():
        print('%s%s'%(v, k))

    _ql = "; g.V.filter{ isFuncDecl(it) }.transform{ getFuncInfo(it) }.count()"

    res = gremlin.query(_ql)
    print(res)