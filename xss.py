import json
import datetime
import urllib
from sklearn.externals import joblib
import re
import traceback

clf = joblib.load('xss-2017-11-22.m')


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        else:
            return json.JSONEncoder.default(self, obj)


def decode_url_none(url):
    """
    URL decode到明文
    """
    flag = urllib.parse.unquote(url)
    while flag != url:
        url = flag
        flag = urllib.parse.unquote(url)
    return url


def get_params(query):
    params = []
    if '&' in query:
        # 多参数
        for item in query.split('&'):
            if item and '=' in item:
                key = item[:item.index('=')]
                if key:
                    params.append((key, item[item.index('=') + 1:]))
    else:
        # 单参数
        if '=' in query:
            key = query[:query.index('=')]
            if key:
                params.append((key, query[query.index('=') + 1:]))
    return params


def get_evil_char(url):
    return len(re.findall("[<>`\(\)\/]", url, re.IGNORECASE))


def get_evil_word(url):
    # /* 是注释
    # 空格不要用
    # |(src=)
    return len(re.findall("(/\*)|(alert)|(script)|(onerror)|(onload)|(eval)|(prompt)|(document)|(window)|(confirm)|(onmouseover)|(onclick)|(console)|(onfocus)|(setinterval)|(settimeout)", url, re.IGNORECASE))


def get_last_char(url):
    if re.search('/$', url, re.IGNORECASE):
        return 1
    else:
        return 0


def get_url_count(url):
    if re.search('(http://)|(https://)', url, re.IGNORECASE):
        return 1
    else:
        return 0


def get_feature(url):
    return [[get_last_char(url), get_url_count(url), get_evil_char(url), get_evil_word(url)]]


white_list = [
    '/Script/fly/zz.swf',
]


def check(vaule):
    if isinstance(vaule, str):
        if len(vaule) <= 6:
            return False
        # elif re.match("^[\u4E00-\u9FA5A-Za-z0-9_\-\.]+$", vaule):
        #     """
        #     中文，数字，字母
        #     符号：_ -
        #     """
        #     return False
        # elif re.match("^[a-zA-Z0-9\+/=]+$", vaule):
        #     """a-z A-Z 0-9 / + =这种类base64 """
        #     return False
        # elif vaule.startswith('Mozilla/5.0 ') or vaule.startswith('Mozilla/4.0 '):
        #     return False
        # elif vaule in white_list:
        #     return False
        else:
            return True
    else:
        return False


def check_json_format(value):
    """
    用于判断一个字符串是否符合Json格式
    :param self:
    :return:
    """
    json_value = ''
    if isinstance(value, str):  # 首先判断变量是否为字符串
        try:
            json_value = json.loads(value, encoding='utf-8')
        except ValueError:
            return False, json_value
        return True, json_value
    else:
        return False, json_value


def is_chinese(s):
    if u"\u4e00" <= s <= u"\u9fa6":
        return True
    else:
        return False


def vtohmm(str):
    vers = ''
    for i, c in enumerate(str):
        c = c.lower()
        if ord('a') <= ord(c) <= ord('z'):
            vers += 'A'
        elif ord('0') <= ord(c) <= ord('9'):
            vers += 'N'
        elif is_chinese(c):
            vers += 'Z'
        else:
            vers += c
    return vers


def predict_model(v):
    if check(v):
        predict = clf.predict(get_feature(v))
        result = predict[0]
        if result == 1:
            # print(type(v))
            # print(v.replace('\n', '\\n'))
            return True
    return False


def model(request_uri):
    hits = []
    request_uri = decode_url_none(request_uri)
    params = get_params(request_uri)
    for k, v in params:
        if v:
            is_json, json_value = check_json_format(v)
            if is_json:
                if isinstance(json_value, dict):
                    for item in json_value.values():
                        if predict_model(item):
                            hits.append(item)
                elif isinstance(json_value, list):
                    for item in json_value:
                        if predict_model(item):
                            hits.append(item)
                else:
                    pass
            else:
                if predict_model(v):
                    hits.append(v)
    return hits


def work(newmsg):
    try:

        hits = model(newmsg)
        if len(hits) > 0:
            print(hits)
    except:
        print(traceback.format_exc())


def main():
    try:
        v = '%3Cimg%20src%3D%22x%60%20%60%3Cscript%3Ejavascript%3Aalert%281%29%3C/script%3E%22%60%20%60%3E'
        v = decode_url_none(v)
        print(v)
        print(predict_model(v))
    except:
        print(traceback.format_exc())


if __name__ == '__main__':
    main()
