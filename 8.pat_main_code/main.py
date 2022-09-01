#! /usr/bin/env python
#coding=utf-8

import time
import sys
from common import *
from sanitizer import *
from info import *
from slice import *
from scan import * 

#
# Scanner
#
class Scanner(object):
    '''
        1. load info
        2. sanitize inference
        3. source, sink analysis
    '''
    def __init__(self):
        self.sanitize_info = []
        self.source_info = []
        self.sink_info = []
        target = xInfoer()
        


    def features(self):
        '''
            find the sanitizers
            @returns: sanitize_info
        '''
        self.sanitize_info = find_sanitizer()
        print(self.sanitize_info)


    def slice(self):
        '''
            find the sources and sinks
            @returns: source_info, sink_info
        '''
        _slice = xSlicer()
        self.source_info = _slice.slicing()


#
def getNodeInfo(node_id):
    '''
        Get a node's information in detail.
    '''
    if isinstance(node_id, list):
        for _id in node_id:
            _ql = "g.v(%s).name"%str(_id)
            res= gremlin.query(_ql)
            print("{}{}{}".format(color['yellow'], str(res), color['reset']))
    else:
        _ql = "nodeInfo(%s)"%node_id
        res = gremlin.query(_ql)
        print(color['yellow'])
        print(res)
        print(color['reset'])

#
# main
#
def main():
    scanning = Scanner()
    scanning.features()
    scanning.slice()

#
# enterance
#
if __name__ == '__main__':
    if len(sys.argv) > 1:
        os.system("python fix_cpg.py")
        pass

    start_time = time.time()
    main()
    print("[Total Time]: {}".format(time.time() - start_time))

