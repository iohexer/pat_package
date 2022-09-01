#! /usr/bin/env python
# coding=utf-8

import os
from py2neo import Graph
from py2neo.ext.gremlin import Gremlin
from py2neo.packages.httpstream import http

#Socket
http.socket_timeout = 9999
GDB_URL = "http://127.0.0.1:7474/db/data/"

#
# gremlinHandler
#
class gremlinHandler:
    def __init__(self):
        self.connectGDB()

    def connectGDB(self):
        self.graphDB = Graph(GDB_URL)
        self.gremlin_handle = Gremlin(self.graphDB)

    def query(self, _ql=''):
        load_file_query = ''
        load_file_query += self.load_query()
        _ql = load_file_query +_ql
        return self.gremlin_handle.execute(_ql)

    def load_query(self):
        _ql = ""
        for roots, dirs, files in os.walk('./'):
            files.sort()
            for f in files:
                if f.endswith('.groovy'):
                    file_path = './gremlins/'+f
                    with open(file_path, 'r') as fh:
                        _ql += fh.read()
        return _ql


if __name__ == '__main__':
    print("[!] neo4j connect test...")
    g = gremlinHandler()
    print(g.query("g.v(1)"))
