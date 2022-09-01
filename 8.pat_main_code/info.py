#! /usr/bin/env python
# coding=utf-8

import sys
from common import *

#
#xInfoer
#
class xInfoer():
    def __init__(self):
        print("[!] collect feauters")
        self.func_info = []
        if os.path.exists('Info/func_info.json'):
            with open('Info/func_info.json', 'r') as fh:
                self.func_info = json.load(fh)
        else:
            _ql = """
                      g.V.filter{ isFuncDecl(it) }.transform{ getFuncInfo(it) }
                  """
            self.func_info = gremlin.query(_ql)
            with open('Info/func_info.json', 'w') as fh:
                json.dump(self.func_info, fh)


    def getFuncInfo(self, func_id=None):
        '''
            @param func_name
        '''
        if func_id is None:
            return self.func_info
        else:
            target_funcs = []
            for _func in self.func_info:
                if _func['func_id'] == func_id:
                    target_funcs.append(_func)
            return target_funcs
    

    def setFuncInfo(self, func_name, key, value):
        for _id, _func in enumerate(self.func_info):
            if _func['func_name'] == func_name:
                self.func_info[_id][key] = value


    @property
    def getDocs(self):
        '''
            get function comments
        '''
        if os.path.exists('Info/doc_contents.json'):
            with open('Info/doc_contents.json', 'r') as fh:
                doc_contents = json.load(fh)
        else:
            _ql = """
                    getDocs();
                  """
            _docs = gremlin.query(_ql)
            doc_contents = { int(_doc_id):_doc_content for _doc_id, _doc_content in _docs.items() }
            with open('Info/doc_contents.json', 'w') as fh:
                json.dump(doc_contents, fh)
        return doc_contents


    @property
    def getCodes(self):
        '''
            get funtion codes
        '''
        if os.path.exists('Info/code_contents.json'):
            with open('Info/code_contents.json', 'r') as fh:
                code_contents = json.load(fh)
        else:
            _ql = """
                     getCodes();
                  """
            _codes = gremlin.query(_ql)
            code_contents = { int(_code_id.encode('utf-8')):_code_content for _code_id, _code_content in _codes.items() }
            with open('Info/code_contents.json', 'w') as fh:
                json.dump(code_contents, fh)
        return code_contents
    