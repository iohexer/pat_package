#! /usr/bin/env python
# coding=utf-8

import re

from numpy import outer
import nltk
from common import *
from features import deal_word

# Keywords
_sources = ["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILE", "GET_VARS", "POST_VARS"]
builtin_apis = ['htmlspecialchars', 'htmlentities', 'strip_tags']
string_apis = ["str_replace", "preg_replace", "strtr", "str_replace_all", "preg_match_all", "preg_match", "str_ireplace", "substr_replace", "str_repeat"]
resource_apis = ["mysqli", "query", "pdo", "file_get_contents", "file_put_contents", "curl", "exec", "system"]


# target: find transform function     
def find_sanitizer():
    sanitizer_list = []

    ## code mining
    _ql = """
            findingTrans()
          """
    res = gremlin.query(_ql)

    func_features = []
    for k, v in res.items():
        func_features.append(v)
   ## features engineer
    clear_features_list = []
    for i, _func in enumerate(func_features):
        clear_feature = analyze_func_features(_func)
        if clear_feature.has_key('returns') and not clear_feature.has_key('del'):
            clear_features_list.append(clear_feature)

    with open('Info/san_mining.json', 'w') as fh:
        json.dump(clear_features_list, fh)

    if len(clear_features_list) == 0:
        return []

    for _func in clear_features_list:
        # 1. get trust sans
        if _func['trust_sans'] != 0:
            sanitizer_list.append(_func['func_name'])
        # 2. get sanitizers by function name
        if _func['func_name_info'] > 1:
            print(_func['func_name'])
            sanitizer_list.append(_func['func_name'])

    # get sanitizers by comment name
    res = analyze_comment()
    sanitizer_list+=res
    output = []
    
    for i in sanitizer_list:
        if i not in output:
            output.append(i)
    with open('Info/target_san.json', 'w') as fh:
        json.dump(output, fh)
    return output


def analyze_func_features(_func):
    """
    get features
    """
    clear_feature = {}
    for k, v in _func.items():
        # file
        if k == 'file_name':
            clear_feature['file_name'] = v
        if k == 'size':
            clear_feature['size'] = v
        # comments
        if k == 'comments':
            clear_feature['comments'] = v[0] if len(v)>0 else ""
            pass
        # func_name
        if k == 'func_name':
            clear_feature['func_name'] = v
        # params
        if k == 'params':
            clear_feature['params'] = [val+[key] for key, val in v.items()]
            clear_feature['params_count'] = len(v)
        # returns
        if k == 'returns':
            clear_feature['returns'] = v
            clear_feature['returns_count'] = len(v)
        # codes
        if k == 'codes':
            sources_count = 0
            for _c in v:
                if _c in _sources:
                    sources_count+=1
            clear_feature['sources_count'] = sources_count
        # callees
        if k == 'sinks':
            clear_feature['sinks_count'] = v
        if k == 'callees':
            clear_feature['callees_count'] = len(v)
            string_apis_count = 0
            resource_apis_count = 0
            builtin_sans_count = 0
            for _callee in v:
                if _callee in string_apis:
                    string_apis_count+=1
                if _callee in resource_apis:
                    resource_apis_count+=1
                if _callee in builtin_apis:
                    builtin_sans_count+=1
            clear_feature['string_apis_count'] = string_apis_count
            clear_feature['resource_apis_count'] = resource_apis_count
            clear_feature['builtin_sans_count'] = builtin_sans_count
        # handle str_replace
        san_str_op = 0
        if _func.has_key('str_replace_rules'):
            san_str_op += handle_str_replace(_func['str_replace_rules'])
        # handle preg_replace
        if _func.has_key('preg_replace_rules'):
            san_str_op += handle_preg_replace(_func['preg_replace_rules'])
        clear_feature['san_str_op'] = san_str_op
        # semantic features
        if k == 'trust_sans':
            clear_feature['trust_sans'] = v
        ##################
        # text features #
        #################
        # function comments weight
        if k == 'comments':
            if len(v)==0:
                clear_feature['comments_info'] = 0
            else: 
                clear_feature['comments_info'], _del = handle_docs(v)
                if _del: 
                    clear_feature['del'] = True
        # function name
        if k =='func_name':
            clear_feature['func_name_info'] = handle_func_name(_func['func_name'])
        if clear_feature.has_key('comments_info') and clear_feature.has_key('func_name_info'):
            clear_feature['true_text'] = clear_feature['comments_info'] + clear_feature['func_name_info']
    return clear_feature


def handle_str_replace(rules):
    '''
        judget the string replace rule is about XSS
    '''
    sensitive_op_count = 0
    sensitive_strings = ["<", ">", '"',"'"]
    if rules.has_key('search'):
        for search_string in rules['search']:
                for _ss in sensitive_strings:
                    if search_string.find(_ss) != -1:
                        sensitive_op_count+=1
    return sensitive_op_count


def handle_preg_replace(rules):
    '''
        judget the regex replace rule is about XSS
        ! Now it's same to the str_replace
    '''
    sensitive_op_count = 0
    sensitive_strings = ["<", ">", '"',"'"]
    if rules.has_key('search'):
        for search_string in rules['search']:
                for _ss in sensitive_strings:
                    if search_string.find(_ss) != -1:
                        sensitive_op_count+=1
    return sensitive_op_count


def handle_docs(docs):
    """
    get params and returns
    and judege the type
    """
    sen_word_count = 0
    _del = False
    for _doc in docs:
        doc_list =_doc.split('* ')
        param_anno = []
        return_anno = []
        for i in doc_list:
            if i.startswith('@param'):
                param_anno.append(i)
            elif i.startswith('@return'):
                return_anno.append(i)
            else:
                target_words = []
                for _word in i.split(' '):
                    if _word and not _word.startswith('@') and len(_word)>=3 and _word != "/**n":
                        target_words.append(_word)

                _count = deal_word.simWords(target_words)
                if _count > 0:
                    sen_word_count +=_count
    if len(return_anno) == 1:
        if str(return_anno[0]).lower().find("string") == -1:
            _del = True
    return sen_word_count, _del


def handle_func_name(func_name):
    func_name_info = deal_word.matchWords(func_name)
    return func_name_info


# use the nltk to handle comments
from nltk.corpus import stopwords
nltk.download('stopwords')
from nltk.stem.wordnet import WordNetLemmatizer
lem = WordNetLemmatizer()
from nltk.stem.porter import PorterStemmer
stem = ()

lem_token_list = []
token_info = {}
stop_words = stopwords.words("english")
must_words = ["xss", "evil", "htmlspecialchar","htmlentity","htmlspecialchars", "htmlentities", "strip_tags", "htmlpurifier"]


def analyze_comment():
    with open('Info/san_mining.json', 'r') as fh:
        san_json = json.load(fh)
    data = pd.DataFrame(san_json)

    # function name
    sans = []
    trust_list = []
    func_name_list = []
    func_name_trust = []

    for num, i in enumerate(san_json):
        if i['trust_sans'] == 1: 
            trust_list.append(i['func_name'])
            del san_json[num] 
            continue
        func_name_list = str(deal_word.splitFuncName(i['func_name']))
        for word in func_name_list:
            if word in must_words:
                func_name_trust.append(i['func_name'])
    #
    print("trust list=====>")
    print(len(trust_list))
    print(trust_list)
    sans+=trust_list
    print("function name...")
    print(func_name_trust)
    sans+=func_name_trust 
    token_data = data[["file_name", "func_name", "comments"]]
    san_list = []
    _count = 0
    _sum = 0
    res = []
    for index, _row in token_data.iterrows():
        if len(_row["comments"]) != 0:
            _sum+=1
        if judgeToken(_row["comments"]):
            san_list.append(_row)
            print("==>[{}]: {}: {}".format(index, _row["func_name"], _row["file_name"]))
            res.append(_row["func_name"])
            _count += 1
        else:
            pass
    res.sort()
    sans+=res
    output = []
    for i in sans:
        if i not in output:
            output.append(i)
    return output

#
# judge token
def judgeToken(comment, _type="lem"):
    comment = re.sub("rn\s\*", "", comment)
    comment = re.sub("\/\*[\*](.+)[\*]\/", "\\1", comment)
    comment = re.sub("@[(param)|(return)|(verion)|(since)].+n\s", "", comment)
    comment = re.sub("[(n\s\*)|(n\*)]{1-3}", "", comment)
    comment = re.sub("\.n", "", comment)
    tokenized_sen = nltk.tokenize.sent_tokenize(comment)
    _words = []
    for _sen in tokenized_sen:
        tokenized_word = nltk.word_tokenize(_sen)
        _words+=tokenized_word
    ## stop words
    _words = [w for w in _words if w not in stop_words] 
    #special_chars = ["<", ">","[", "]", "(", ")", "`","``","'","\"", ".", "*", ";", "n"]
    special_chars = ["``", "\\r", "\\n", "''", "..", "...", "\"\"", ".n", "amp", "lt", "n't", "rn *"]
    _words = [w.lower().rstrip("n") for w in _words if len(w)>1 and w not in special_chars]
    if _words == []:
        return False

    lem_tokens = [lem.lemmatize(w, "v") for w in _words]

    for _must in must_words:
        if _must in lem_tokens:
            return True
    
    # noun first
    syn_words = [w.rstrip("s") for w in lem_tokens]
    noun_list = ["character", "html", "xml", "text", "textarea", "attrrbute", "entities", "input", "sqli"]
    verb_list = ["escape", "clean", "cleanup", "strip", "filter", "remove"]

    #
    for s in syn_words:
        if s in black_list:
            return False

    #
    for i, v in enumerate(verb_list):
        if v in syn_words:
            for n in noun_list:
                if n in syn_words[i:]:
                    return True
    return False

# 
if __name__ == '__main__':
    find_sanitizer()
    analyze_comment()