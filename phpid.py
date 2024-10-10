# coding=utf-8
'''
by：Segador
'''
import re
import os
import optparse
import sys
import chardet
from lxml.html import etree

class phpid(object):
    def __init__(self, dir):
        self._function = ''
        self._fpanttern = ''
        self._line = ''
        self._dir = dir
        self._filename = ''
        self._vultype = ''
        self.choice = '1'

    def _run(self):
        try:
            self.handlePath(self._dir)
            print("danger information Finished!")
        except Exception as e:
            print(f"Error: {e}")
            raise

    def report_id(self, vul):
        message = f"[+{vul}] danger information [{self._function}] in file [{self._filename}]"
        print(message)  # 添加这行
        sys.stdout.write(message + '\n')
        sys.stdout.flush()

    def report_line(self):
        print(f" --> [+] on line: {str(self._line)}")

    def handlePath(self, path):
        dirs = os.listdir(path)
        for d in dirs:
            subpath = os.path.join(path, d)
            if os.path.isfile(subpath):
                if os.path.splitext(subpath)[1] in ['.php', '.html']:
                    self._filename = subpath
                    file = "regexp"
                    self.handleFile(subpath, file)
            else:
                self.handlePath(subpath)

    def handleFile(self, fileName, file):
        with open(fileName, 'rb') as f:  # 以二进制模式打开
            raw_data = f.read()
            result = chardet.detect(raw_data)  # 检测编码
            encoding = result['encoding']

        # 使用检测到的编码读取文件
        with open(fileName, 'r', encoding=encoding, errors='ignore') as f:
            self._line = 0
            content = f.read()
            content = self.remove_comment(content)
            self.check_regexp(content, file)

    def function_search_line(self):
        with open(self._filename, 'r', encoding='utf-8', errors='ignore') as fl:
            self._line = 0
            while True:
                line = fl.readline()
                if not line:
                    break
                self._line += 1
                if self._function in line:
                    if len(line) <= 30:
                        print(f'find danger information on line: {line.strip()}')
                    self.report_line()

    def regexp_search(self, rule_dom, content):
        regmatch_doms = list(rule_dom[0].xpath("regmatch"))
        exp_patterns_list = []
        for regmatch_dom in regmatch_doms:
            regexp_doms = regmatch_dom.xpath("regexp")
            exp_patterns = [re.compile(regexp_dom.text) for regexp_dom in regexp_doms]
            exp_patterns_list.append(exp_patterns)

        match_results = [all(exp_pattern.search(content) for exp_pattern in exp_patterns) for exp_patterns in exp_patterns_list]
        if all(match_results):
            self.report_id(self._vultype)
            self.function_search_line()
        return True

    def check_regexp(self, content, file):
        if not content:
            return
        xml_file = "regexp.xml"
        self._xmlstr_dom = etree.parse(xml_file)
        phpid_doms = self._xmlstr_dom.xpath("phpid")
        for phpid_dom in phpid_doms:
            self._vultype = phpid_dom.get("vultype")
            function_doms = phpid_dom.xpath("function")
            for function_dom in function_doms:
                self._function = function_dom.xpath("rule")[0].get("name")
                self.regexp_search(function_dom, content)
        return True

    def remove_comment(self, content):
        # TODO: remove comments from content
        return content

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog [options](eg: python %prog -d /user/php/demo)')
    parser.add_option('-d', '--dir', dest='dir', type='string', help='source code file dir')

    (options, args) = parser.parse_args()

    if options.dir is None or options.dir == "":
        parser.print_help()
        sys.exit()
    dir = options.dir
    phpididentify = phpid(dir)
    phpididentify._run()
