#! /usr/bin/env python
# coding=utf-8

import time
from common import *

# in order to remove the built-in functions in the potential sources and sinks results.
built_in = ["str_replace", "substr", "strstr", "absint", "mysqli_init", "strip_tags", "htmlentities", "htmlspecialchars", "md5", "implode", "explode", "sprintf", "print", "current", "date", "urlencode", "urldecode", "array_map", "round", "preg_replace", "str_replace", "compact", "trim", "rtrim", "basename", "bl2br", "chr", "array_merge", "getenv", "ord", "html_entity_decode"]

#
# xSlicer
#
class xSlicer():
    def __init__(self):
        default_sanitizers = ["htmlspecialchars", "htmlentities", "strip_tags"]
        with open('/Users/he/Lab/pat_final/Info/target_san.json', 'r') as fh:
            user_defined_sanitizers = json.load(fh)
        self.sanitize_list = [str(i) for i in user_defined_sanitizers]+default_sanitizers
        print("[!] Sanitizers: {}".format(self.sanitize_list))

        self.sanitize_calls = {}
        self.source_apis = []
        self.sink_apis = []


    def slicing(self):
        '''
            @returns: potential sources and sinks
        '''
        # 0. analyze sanitizaters sites
        self.sanitize_calls = self.getSanitizeCalls()

        print(self.sanitize_calls)

        # 1. forward
        _slices = {}
        _slices["fd"] = self.sliceFeatures_FD()
        self.sink_apis = self.anaFeatures_FD(_slices["fd"])
        with open('Info/target_sinks.json', 'w') as fh:
            json.dump(self.sink_apis, fh)
        
        #2. backward
        _slices["bd"] = self.sliceFeatures_BD()
        self.source_apis = self.check_sources(self.anaFeatures_BD(_slices["bd"]))
        with open('Info/target_sources.json', 'w') as fh:
            json.dump(self.source_apis, fh)

    def getSanitizeCalls(self):
        '''
            @returns: sanitization_calls: sanitize's call sites
        '''
        print("{}[!] Found sanitize calls{}".format(color["yellow"],color["reset"]))

        sanitize_calls = {}

        _ql = """ 
                List sanitize_list = {};
                getSanitizeCalls(sanitize_list);
              """.format(self.sanitize_list) 
        res = gremlin.query(_ql)
        _counter =Counter()
        for _san, call_site in res.items():
            print("{}{}: {}{}".format(color['blue'], _san, len(call_site), color['reset']))
            if len(call_site) != 0: 
                _counter[_san] = len(call_site)
                sanitize_calls[str(_san)] = call_site

        with open('Info/san_calls.json', 'w') as fh:
            json.dump(sanitize_calls, fh)
        return sanitize_calls


    # ----------------- slice FD ---------------------
    def sliceFeatures_FD(self):
        '''
            slice forward
            @returns: fd_features_info
        '''
        fd_paths_info = self.slicePaths_FD()
        print("---- analysis taint exits --------")
        fd_features_info = {}
        for _sanitize, fd_paths in fd_paths_info.items():
            last_info_list = self.sliceLastCallees_FD(fd_paths)
            fd_features_info[_sanitize] = last_info_list

        for k, v in fd_features_info.items():
            print(k, v)
        return fd_features_info


    def slicePaths_FD(self):
        '''
           find the sinks
           @returns reahces_path_info 
        '''
        if os.path.exists('Info/FD_pathss.json'):
            with open('Info/FD_paths.json', 'r') as fh:
                fd_paths_info = json.load(fh)
        else:
            for _san, _calls in self.sanitize_calls.items():
                if _calls == []:   
                    continue
                print("{}Target sanitization: {}{}".format(color['red'], _san, color['reset']))
                #
                _ql = """
                         List sanitize_calls = {};
                         sliceFDPaths(sanitize_calls);
                      """.format(_calls)
                res = gremlin.query(_ql)
                if res is not None:
                    fd_paths_info[_san] = res
            with open('Info/FD_Paths.json', 'w') as fh:
                json.dump(fd_paths_info, fh)
        return fd_paths_info
                     
                
    def sliceLastCallees_FD(self, fd_path_info):
        '''
            @param fd_path_info: find all the call-sites forward 
            @returns：return the lastest stmt
        '''
        inline_list = []
        outline_list = []
        array_list = []
        for _call, _paths in fd_path_info.items():
            if _paths == []:
                _call = int(_call.encode('utf-8'))
                inline_list.append(_call)
            elif len(_paths)==1 and _paths[0] == "array":
                array_list.append(_call) 
            else:
                for _p in _paths: 
                    outline_list.append(_p[-1])

        print(color["yellow"])
        print("inline list {}".format(inline_list))
        print("outline list {}".format(outline_list))
        print("array list {}".format(array_list))
        print(color["reset"])
        try: 
            _ql = """
                    List last_callee_info = {};
                    sliceFDLast(last_callee_info, true);
                  """.format(inline_list)
            inline_res = gremlin.query(_ql)
        except Exception as e:
            print(e)
            exit()
        try:
            _ql = """
                    List last_callee_info = {};
                    sliceFDLast(last_callee_info)
                  """.format(outline_list)
            outline_res = gremlin.query(_ql)
        except Exception as e:
            print(e)
            exit()

        fd_res = inline_res + outline_res
        return fd_res
    # 
    def anaFeatures_FD(self, slice_fd):
        '''
            forward slice info analysis
        '''
        sink_api = []
        sink_dict = {}
        _returns = []
        _apis = []
        _exts = []
        _sinks = []
        count_total = 0
        num_returns = 0
        num_apis = 0
        num_exts = 0
        num_sinks = 0

        for _sanitize, _features in slice_fd.items():
            if _sanitize != "getArrayVal":
                continue

            count_total += len(_features)
            print("{}------> {} {}".format(color['yellow'], _sanitize, color['reset']))
            _types = [_feature['type'] for _feature in _features]
            type_counter = Counter(_types)

            print("{} [+] Forward: \n Count: {}\n Type: {}\n{}".format(color['apple'], len(type_counter), type_counter, color['reset']))

            for _f in _features:
                if _f['type'] == 'AST_RETURN':
                    _returns.append(_f)
                    num_returns+=1
                elif _f['type'] in ['AST_ECHO', 'AST_EXIT', 'AST_PRINT']:
                    _sinks.append(_f)
                    num_sinks+=1
                elif _f['type'] in ['AST_CALL', 'AST_METHOD_CALL', 'AST_STATIC_CALL']:
                    _apis.append(_f)
                    num_apis+=1
                else:
                    _exts.append(_f)
                    num_exts+=1

        num_returns = len(_returns)
        num_apis = len(_apis)
        num_exts = len(_exts)
        num_sinks = len(_sinks)
        try:
            print("{}count: {} \n{}".format(color['apple'], count_total, color['reset']))
            print("{}returns: {:.1%} \n{}".format(color['apple'], (float(num_returns)/float(count_total)), color['reset']))
            print("{}apis: {:.1%} \n{}".format(color['apple'], (float(num_apis)/float(count_total)), color['reset']))
            print("{}exts: {:.1%} \n{}".format(color['apple'], (float(num_exts)/float(count_total)), color['reset']))
            print("{}sinks: {:.1%} \n{}".format(color['apple'], (float(num_sinks)/float(count_total)), color['reset']))
        except Exception as e:
            print(e)

        inner_strings = []
        outter_calls = []

        for _sanitize, _features in slice_fd.items():
            for _f in _features:
                if _f.has_key('inner_strings'):
                    for _s in _f['inner_strings']:
                        inner_string.append(str(_s))
                if _f.has_key('outter_calls'):
                    for _s in _f['outter_calls']:
                        outter_calls.append(str(_s))
                if _f['type'] == 'AST_METHOD_CALL' and _f.has_key('name'):
                    outter_calls.append(str(_f['name']))

        inner_strings = Counter(inner_strings)
        outter_calls = Counter(outter_calls)
        infer_list = inner_strings + outter_calls

        _resources = {}
        for func_name, _count in Counter(infer_list).items():
            _ql = """
                    def sanitizer_list = {sanitizer_list};
                    countReaches_sink("{key_word}", sanitizer_list);
                  """.format(key_word=str(func_name), sanitizer_list=str(self.sanitize_list))
            _total = gremlin.query(_ql)

            print("===> func_name: {}, total: {}, count: {}".format(func_name, _total, _count))
            if _total != 0:
                try:
                    _weight = (float(_count)/float(_total))*_count
                    if _weight > 3:
                        _resources[func_name] = _weight
                except TypeError as e:
                    print("Forward analysis Type error...")
        count_resources = Counter(_resources)
        count_resources = {k: v for k, v in sorted(count_resources.items(), key=lambda item: item[1])}
        for k, v in count_resources.items():
            if v<1:
                continue
            print("{}: {}".format(k, v))
            if v>=1:
                sink_api.append(k)
        return sink_api


    # ----------------- slice BD ---------------------
    def sliceFeatures_BD(self):
        '''
            The enterence of backward analysis
        '''
        sliceFeatures_info = {}
        print("slice backword...")
        bd_paths_info = self.slicePaths_BD()
        print("----analysis taint enters --------")
        bd_features_info = {}
        for _sanitize, bd_paths in bd_paths_info.items():
            if bd_paths != {}:
                last_info_list  = self.sliceLastCallees_BD(bd_paths)
                bd_features_info[_sanitize] = last_info_list
        print(bd_features_info)
        return bd_features_info


    def slicePaths_BD(self):
        '''
            the source analysis by slice backwordk
            @return bd_paths_info
        '''
        bd_paths_info = {}
        if os.path.exists('Info/BD_Pathss.json'):
            with open('Info/BD_Paths.json', 'r') as fh:
                bd_paths_info = json.load(fh)
        else:
            for _san, _calls in self.sanitize_calls.items():
                print(_calls)
                if _calls == []:
                    continue

                print("{}Target sanitization: {}{}".format(color['red'] ,_san ,color['reset']))

                #
                _ql = """
                         List sanitize_calls = {calls};
                         sliceBDPaths(sanitize_calls); 
                      """.format(calls = _calls)
                res = gremlin.query(_ql)
                print(color['red'])
                for i in res:
                    print(i)
                print(color['reset'])
                if res is not None:
                    bd_paths_info[_san] = res

            with open('Info/BD_Paths.json', 'w') as fh:
                json.dump(bd_paths_info, fh)
        print(bd_paths_info)
        return bd_paths_info
                        

    def sliceLastCallees_BD(self, bd_path_info):
        '''
            @param bd_path_info 
            @return: all the callees collect by backword slice  
        '''
        inline_list = []
        outline_list = []
        print(len(bd_path_info))
        for _call, _paths in bd_path_info.items():
            if _paths == []: 
                _call = int(_call.encode('utf-8'))
                inline_list.append(_call) 
            else:
                for _p in _paths: 
                    outline_list.append(_p[-1]) 

        inline_list_single = []
        outline_list_single = []
        [inline_list_single.append(_c) for _c in inline_list if not _c in inline_list_single]
        [outline_list_single.append(_c) for _c in outline_list if not _c in outline_list_single]
        _ql = """
                List last_bd_list = {};
                sliceBDLast(last_bd_list, true);
              """.format(inline_list_single)
        inline_res = gremlin.query(_ql) 

        _ql = """
                List last_bd_list = {};
                sliceBDLast(last_bd_list)
              """.format(outline_list_single)
        outline_res = gremlin.query(_ql) 
        bd_res = inline_res+outline_res
        return bd_res


    def anaFeatures_BD(self, slice_dict):
        '''
           sanitization backword analysis
           @param slice_dict
        '''
        source_api = []
        source_dict = {}
        _params = [] 
        _apis = []
        _exts = []
        _sources = []

        count_total = 0
        num_params  = 0
        num_apis = 0
        num_exts = 0
        num_sources = 0
        for _sanitize, _features in slice_dict.items():
            count_total += len(_features)
            print("{}------> {} {}".format(color['yellow'], _sanitize, color['reset']))
            _types = [_feature['type'] for _feature in _features]
            type_counter = Counter(_types)
            print("{} [+] Backward: \n Count: {}\n Type: {}\n{}".format(color['apple'], len(_features), type_counter, color['reset']))

            for _f in _features:
                if _f['type'] == "AST_PARAM":
                    _params.append(_f)
                    num_params += 1
                elif _f['type'] in ['_GET', '_POST', '_COOKIE', '_REQUEST']:
                    _sinks.append(_f)
                    num_sources += 1
                elif _f['type'] in ['AST_CALL', 'AST_METHOD_CALL', 'AST_STATIC_CALL']:
                    _apis.append(_f)
                    num_apis += 1
                else:
                    _exts.append(_f)
                    num_exts += 1
        # _weight
        assert count_total != 0, "There is sanitizer no call site" 
        print("{}count: {} \n{}".format(color['apple'], count_total, color['reset']))
        print("{}params: {:.1%} \n{}".format(color['apple'], (float(num_params)/float(count_total)), color['reset']))
        print("{}apis: {:.1%} \n{}".format(color['apple'], (float(num_apis)/float(count_total)), color['reset']))
        print("{}exts: {:.1%} \n{}".format(color['apple'], (float(num_exts)/float(count_total)), color['reset']))
        print("{}sources: {:.1%} \n{}".format(color['apple'], (float(num_sources)/float(count_total)), color['reset']))

        # ASSIGN:
        # inner
        # FOR
        # GLOBAL
        # WHILE
        # EXPR_LIST

        _c = []
        for i in _exts:
            print(i)
        print("~~~~~~")

        # obtain inner_strings,
        inner_strings = []
        for _sanitize, _features in slice_dict.items():
            for _f in _features:
                if _f.has_key('inner_strings'):
                    for _s in _f['inner_strings']:
                        try:
                            inner_strings.append(str(_s))
                        except Exception as e:
                            pass

        inner_strings = Counter(inner_strings)

        # backup
        back_1 = {}
        inner_calls = []
        for _sanitize, _features in slice_dict.items():
            for _f in _features:
                if _f.has_key('inner_calls'):
                    for _s in _f['inner_calls']:
                        inner_calls.append(str(_s))
                        back_1[_f['id']] = _f
                        back_1[_f['type']] = 'inner'
        stmt_calls = []
        for _sanitize, _features in slice_dict.items():
            for _f in _features:
                if _f.has_key('stmt_calls'):
                    for _s in _f['stmt_calls']:
                        stmt_calls.append(str(_s))
                        back_1[_f['id']] = _f
                        back_1['type'] = 'stmt'

        infer_list = inner_calls + stmt_calls
        inner_calls = Counter(inner_calls)
        stmt_calls = Counter(stmt_calls)

        with open('Info/back_1.json', 'w') as fh:
            json.dump(back_1, fh)

        #print(inner_calls)
        #print(stmt_calls)
        print(infer_list)

        # check all of the infere apis are validation
        target_apis = []
        for i in infer_list:
            if i not in built_in:
                target_apis.append(i)

        _resources = {}
        bak_2 = {}
        for func_name, _count in Counter(target_apis).items():
            if _count == 0:
                continue
        
            print("==>"+func_name)
            if func_name == 'phpbb\config_php_file::convert_30_dbms_to_31':
                continue

            _ql = """
                    List sink_apis = {sink_apis};
                    countReaches_source("{key_word}", sink_apis)
                  """.format(sink_apis=self.sink_apis, key_word=str(func_name))
            _total = gremlin.query(_ql) 

            if _total == 0:
                continue
            print(_count)
            print(_total)

            bak_2['func_name'] = func_name
            bak_2['count'] = _count
            bak_2['total'] = _total

            # count
            if _total != 0:
                try:
                    weight_1 = (float(_count)/float(_total))
                    _weight = weight_1 * float(_count)
                    if _weight > 3:
                        _resources[func_name] = _weight
                except TypeError as e:
                    print("Back analysis Type error...")

        count_resources = Counter(_resources)

        with open('Info/bak_2.json', 'w') as fh:
            json.dump(bak_2, fh)

        for k, v in count_resources.items():
            print("{}:{}".format(k, v))
            source_api.append(k)
        return source_api


    def check_sources(self, source_apis):
        '''
            check the target source api
            @ param source_apis: the source apis we get
            @ return: the soure apis after validation
        '''
        sources = []
        print(source_apis)
        sources=source_apis

        with open('Info/func_info.json', 'r') as fh:
            funcs_info = json.load(fh)

        source_info = {}
        res_sources = []
        # the target source api must have a function body in the codebase.
        for s in sources:
            target_source = self.split_method_name(s)
            # not in sanitize
            if target_source in self.sanitize_list:
                continue
            # 
            for _func in funcs_info:
                if self.split_method_name(_func['func_name']) == target_source:
                    if source_info.has_key(s):
                        source_info[s].append(_func['func_id'])
                    else:
                        source_info[s] = [_func['func_id']]

        for k, v in source_info.items():
            _ql = """
                    def target_sources = {};
                    def sources = {}
                    check_sources(target_sources, sources);
                    """.format(v, sources)
            res = gremlin.query(_ql);
            if res and k not in res_sources:
                res_sources.append(k)

        print(res_sources)


    def split_method_name(self, func_name):
        '''
            split and only use the method name
        '''
        if func_name.find("->") != -1:
            return func_name.split("->")[-1]
        if func_name.find("::") != -1:
            return func_name.split("::")[-1]
        return func_name



if __name__ == "__main__":
    start = time.time()
    s = xSlicer()
    s.slicing()
    end = time.time()
    print("[+] Consume: {}".format(str(end-start)))

