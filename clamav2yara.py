#!/usr/bin/env python3
'''
File name: clamav2yara.py
Author: chouchouzzj
Date created: 7/28/2023
Date last modified: 8/1/2023
Python Version: 3.8.10
'''

DEBUG = False
import subprocess
import argparse
import requests
import glob
import sys
import re
import os
from ignored import *



# VARIABLES
INPUT = None
OUTPUT = None
TYPE = None
URL = "http://database.clamav.net/daily.cvd"
DB_FILE = "daily.cvd"
EXTENSIONS = ['.ndu', '.ndb', '.hdb', '.hsb', '.ldb']

FORMAT = {
    'tab': '\t',
    'nl': '\n'
}

CONDITION = {
    'ne': lambda var, expVal: var != expVal,
    'eq': lambda var, expVal: var == expVal,
    'sw': lambda var, expVal: var.startswith(expVal),
    'snw': lambda var, expVal: not var.startswith(expVal),
    'ew': lambda var, expVal: var.endswith(expVal),
    'enw': lambda var, expVal: not var.endswith(expVal),
    'in': lambda var, expVal: var in expVal,
    'nin': lambda var, expVal: var not in expVal
}

REGEX = {
    'name': re.compile(r'[^:]+'),
    'strings': re.compile(r'[^:]+'),
    'ftype': re.compile(r'.[^.]+'),
    'ldb': re.compile(r'[^;]+')
}

REGEX_SUB_EXPRESSIONS ={
    'AAXY': re.compile(r'\([^\(\)]+\)[<>=]{1}[\d]+[,]{0,1}[\d]*'),     # A>X,Y | A>X | A<X | A<X,Y   A 是一个(逻辑)签名块
    'AXY': re.compile(r'\d+[<>=]{1}[\d]+[,]{0,1}[\d]*'),              # 同上, A指向单个签名

    # 'AAeqXY': re.compile(r'\([^\(\)]+\)=[\d]+[,]{0,1}[\d]*'),     # A=X | A=0 | A=X,Y   A 是一个(逻辑)签名块
    'AeqXY': re.compile(r'\d+=[\d]+[,]{0,1}[\d]*'),              # 同上, A指向单个签名
}

PRINTABLE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ \t"


# DOWNLOAD CLAMAV VIRUS DATABASE AND EXTRACT DATA
def download(url, dbfile):
    with open(dbfile, "wb") as db:
        print("Downloading", dbfile)
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')

        if total_length is None:
            f.write(response.content)
        else:
            dl = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                db.write(data)
                done = int(100 * dl / total_length)
                sys.stdout.write("\r[%s%s]" % ('#'*done, ' '*(100-done)))
                sys.stdout.flush()
    print()

    print("Extracting data from", DB_FILE)
    proc = subprocess.Popen(["sigtool", "-u", DB_FILE])
    proc.wait()


# MERGE ALL AVAILABLE .YARA RULES
def merge():
    rules = glob.glob("*.yara")
    with open("total.yara", 'w') as total:
        for yara in rules:
            total.write(open(yara, 'r').read())


# STATUS BAR FOR CONVERSION PROCESS
def status(msg, pos, limit, width):
    x = int((width/limit)*pos)
    print(f"{msg} [{x*'#'}{(width-x)*' '}] {pos}/{limit}", end='\r')
    if pos == limit:
        print(f"{msg} [{x*'#'}{(width-x)*' '}] {pos}/{limit}", end='\r')
        print()


# BATCH REPLACEMENT BY USING DICT
# {'key to replace': 'replacement'}
def repl(s, sub):
    for i in sub.keys():
        s = s.replace(i, sub[i])

    return s.replace("\n", "")


# SHORT CONDITIONS BASED ON LAMBDA FUNCTIONS
def check(var, condition, expVal, msg):
    if not CONDITION[condition](var, expVal):
        print(msg)
        exit(1)


# GET FILETYPE FROM FILENAME
def get_file_ext(fname):
    return re.findall(REGEX['ftype'], fname)[-1]


def handle_hex(string_t):
    """
    将16进制字符串转换成ascii字符串. 41424344 转成 "abcd"
    这样方便处理 41424344::w 转换成 "abcd" wide
    """
    hexs = re.findall(re.compile(r'\[[^\]]+\]'), string_t)
    if len(hexs) == 0:
        hex_nums = re.findall(re.compile(r'[\da-f]{2}'), string_t)
        ascii_string = ''.join([chr(int(_,16)) for _ in hex_nums])
        return ascii_string
    length = hexs[0]
    return handle_hex(string_t[:string_t.find(length)]) +  length + handle_hex(string_t[string_t.find(length)+len(length):])


def is_hex(string_t):
    """
    True: 16进制字符串
    False: ascii 字符串
    """
    regex = re.compile(r'[^0-9a-fA-F\(\)\[\]\?\*|-]')
    matches = re.findall(regex, string_t)
    return len(matches) == 0

def del_invisiable(string_t):
    return repl(string_t, {
        "\r": "",
        "\n": "",
        chr(0x0b): "",
        chr(0x0c): ""
    })

def logic_len(logic):
    regex_l = re.compile(r'[\d]+')
    matches = re.findall(regex_l, logic)
    subsig_count = 0
    for i in range(0, 65):
        if str(i) in matches:
            subsig_count = i+1
        else:
            break
    return subsig_count

# REFORMAT LDB STRING TO YARA
def formatLDB(string_t, index=0):
    """
    string_t: SubsigN
    index:  上面SubsigN 中的 N. 从0开始
    return: (SubsigN, {"EOF":(N, m, n), "EP":position})
    如果 SubsigN 以 EOF-m,n 开头 则返回值中有 "EOF":(N, m, n)
    如果 SubsigN 以 EP[+-]{1}开头 则返回值中有 "EP":position
    如什么都没, 则返回  SubsigN,{}
    """
    # 但凡字符串里有 / 就认为是 正则
    # 正则的前缀和后缀的描述见(https://docs.clamav.net/manual/Signatures/LogicalSignatures.html#pcre-subsignatures)
    # 但是看不懂，文档也不是完整的
    condition_ex = {}
    if string_t.find("/") != -1:
        re_str = string_t[string_t.index("/"):string_t.rindex("/")+1]
        # fix bugs: greedy and ungreedy quantifiers can't be mixed in a regular expression
        re_str = re_str.replace("*?","*").replace("+?","+").replace("(?", "(\\?")
        #.replace("}?", "?")
        return f"{2*FORMAT['tab']}$a{index} = {re_str}", condition_ex

    # 处理 EOF-m,n
    regex = re.compile(r'^EOF-([\d]+)[,]{0,1}([\d]*):')
    matches = re.findall(regex, string_t)
    if len(matches) > 0:
        condition_ex["EOF"]= (index, matches[0][0], matches[0][1])
    
    # 处理 EP+n
    # daily.ldb 未发现 EP+n 的字符串. 这里略过

    string_t = repl(string_t, {
        "{": "[",
        "}": "]",
        "[-": "[0-",
        "*": "[-]"      # Starting with YARA 2.0 you can also use unbounded jumps:
    })
    if string_t.endswith("]"):
        string_t = re.sub(r'\[\d+\-?\d*\]$', '', string_t)
    if string_t.endswith(")"):
        string_t = re.sub(r'\([\|0-9A-F]*\)$', '', string_t)
    # 格式化类似的异常Subsig: 0:7b5c727466  转换成 7b5c727466
    regex = re.compile('([^:]+):([^:]+)')
    if len(re.findall(regex, string_t)) > 0:
        string_t = regex.sub('\g<2>', string_t)

    # 处理特征修饰符 Subsignature Modifiers 
    if string_t.find("::") > -1:
        # 有修饰符的，必然要转换成ascii字符串
        modifiers = string_t.split("::")[1]
        hexstring = string_t.split("::")[0]
        s = []
        for _ in modifiers:
            if _ == "w":
                s.append("wide")
                continue
            if _ == "a":
                s.append("ascii")
                continue
            if _ == "f":
                s.append("fullword")
                continue
            if _ == "i":
                s.append("nocase")
                continue
        modifiers = " ".join(s)
        
        string_t = handle_hex(hexstring)
        string_t = repl(string_t, {
            "\\": "\\\\",
            "\"": "\\\""
        })

        res = f"\"{del_invisiable(string_t)}\" {modifiers}"
        return f"{2*FORMAT['tab']}$a{index} = {res}", condition_ex
    else:
        if is_hex(string_t=string_t):
            res = f"{{ {string_t} }}"
        else:
            res = f"\"{del_invisiable(string_t)}\""
        return f"{2*FORMAT['tab']}$a{index} = {res}", condition_ex


def handle_AXY(string_t):
    # 注意 = 要替换成 == 
    # 1>20  1<20    2=0
    # 转换成    #a>20    #a1<20    #a2==0
    if string_t.find('(') == -1:
        # 假设当logic类似 (1|2|3)>2 时 1/2/3这三个subsig中都不会有规则子集(sub-signatures)
        # 那么将 1=1 转换时，就要判断是否存在规则子集
        #egex = re.compile('[\d]+[<>=]{1}[\d]+')
        regex = re.compile('([\d]+)([<>=]{1})([\d]+)[,]{0,1}([\d]*)')
        matches = re.findall(regex, string_t)
        index,spliter,X,Y = matches[0][0], matches[0][1], matches[0][2], matches[0][3]
        if DEBUG: print("index,spliter,X,Y ", index,spliter,X,Y)

        string_t = regex.sub('#a\g<0>', string_t)
        return string_t.replace("=", "==")

    # (0|1|2|3)>1,2
    # 转换成 for all of ($a0, $a1, $a2, $a3): (# > 1) and 2 of ($a0, $a1, $a2, $a3)
    spliter = '>' if string_t.find('>') > 0 else '<' if string_t.find('<') > 0 else '='
    arr = string_t.split(spliter)
    left = arr[0]
    rigth = arr[1]
    regex = re.compile('[\d]+')
    left = regex.sub('$a\g<0>', left)
    condition = "all" if left.find("&") != -1 else "any"
    left = left.replace('|', ', ').replace('&', ', ')      # (1|2|3) 或者 (1&2&3) 转换成 ($a1, $a2, $a3)
    
    if rigth.find(',') != -1:
        X, Y = rigth.split(',')[0], rigth.split(',')[1]
    else:
        X, Y = rigth, None

    res = f"for {condition} of {left}: ( # {spliter} {X})"
    if Y:
        res += f" and {Y} of {left}"
    return res.replace("=", "==")


def get_next_sub_expressions(string_t):
    regex = REGEX_SUB_EXPRESSIONS['AAXY']
    matches = re.findall(regex, string_t)
    if len(matches) > 0:
        expressions = matches[0]
        pre = string_t[:string_t.find(expressions)]
        after = string_t[string_t.find(expressions)+len(expressions):]
        return f"{get_next_sub_expressions(pre)}{handle_AXY(expressions)}{get_next_sub_expressions(after)}"
    else:
        regex = REGEX_SUB_EXPRESSIONS['AXY']
        matches = re.findall(regex, string_t)
        if len(matches) > 0:
            expressions = matches[0]
            pre = string_t[:string_t.find(expressions)]
            after = string_t[string_t.find(expressions)+len(expressions):]
            return f"{get_next_sub_expressions(pre)}{handle_AXY(expressions)}{get_next_sub_expressions(after)}"
        else:
            regex = REGEX_SUB_EXPRESSIONS['AeqXY']
            matches = re.findall(regex, string_t)
            if len(matches) > 0:
                expressions = matches[0]
                pre = string_t[:string_t.find(expressions)]
                after = string_t[string_t.find(expressions)+len(expressions):]
                return f"{get_next_sub_expressions(pre)}{handle_AXY(expressions)}{get_next_sub_expressions(after)}"
            else:
                regex = re.compile('[\d]+')
                string_t = regex.sub('$a\g<0>', string_t)
                # Subsig with sub-signatures
                return repl(string_t, {
                            "|": " or ",
                            "&": " and "
                        })


# REFORMAT LDB LOGIC TO YARA CONDITION
def format_logic(string_t):
    # format weird logics
    if DEBUG: print("format_logic", string_t)
    string_t = re.sub(r'[a-z]+', '', string_t)  # drop the 'i' in 0:(0&1&2&3i)|4
    string_t = re.sub(r'\s+', '', string_t)     # drop space in 0& 1 > 200
    if string_t.find(":") != -1:              # drop the ':' in 0:(0&1&2&3i)|4
        string_t = string_t.split(":")[1]
    yara_condition = get_next_sub_expressions(string_t)
    return yara_condition


def format_target(TargetDescriptionBlock):
    targets = TargetDescriptionBlock.split(",")
    res = ""
    for _ in targets:
        if _.find("FileSize") !=  -1:
            sizes = _.split(":")[1].split("-")
            res += f" and (filesize > {sizes[0]} and filesize < {sizes[1]})"
        if _.find("NumberOfSections") !=  -1:
            regex = re.compile(r'NumberOfSections:([\d]+)[-]{0,1}([\d]*)')
            matches = re.findall(regex, _)
            minS, maxS = matches[0][0], matches[0][1]
            if len(maxS) == 0 or minS == maxS:
                res += f" and (pe.number_of_sections == {minS})"
            else:
                res += f" and (pe.number_of_sections > {minS} and pe.number_of_sections < {maxS})"
    return res


def convertLDB(line):
    line = line.strip()
    if len(line) == 0:
        return ""
    # 排除 Image Fuzzy Hash subsignatures
    if line.find("fuzzy_img#") > -1:
        return ""
    # SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;Subsig2;...
    subsigs = re.findall(REGEX['ldb'], line)
    if len(subsigs) < 4:
        return ""
    
    name, TargetDescriptionBlock, logic, strings = subsigs[0], subsigs[1], subsigs[2], subsigs[3:]

    if name in IGNORED_LDB:
        return ""

    # 排除带有宏子规则(Macro subsignatures)的
    # Engine:51-255,Target:0
    # Signatures using macro subsignatures require Engine:51-255 for backwards-compatibility.
    # 还不能排除，51开头的太多了
    for info in TargetDescriptionBlock.split(","):
        BlockName = info.split(":")[0]
        # if BlockName == "Engine":
        #     value_min = info.split(":")[1].split("-")[0]
        #     if DEBUG: print("convertLDB Engine", value_min)
        #     if int(value_min) == 51:
        #         return ""
        if BlockName == "Container":
            return ""

    # 排除类似的logic: 0,1-4&1,1-4&2,1-4
    if logic.find("-") != -1:
        return ""
    # 有些ldb特征很多，但是logic中就只有一个0,因此要将其补齐.例如 subsigs有3个，就补齐成 0&1&2
    # 感觉不对劲，后面继续看看文档吧
    if len(logic) < len(subsigs[3:]):
        if len(logic) == 1:
            logics = []
            for i in range(0, len(subsigs[3:])):
                logics.append(str(i))
            logic = "&".join(logics)
        else:
            return ""
    
    # 排除某些logic不包含规则集中的某一条 例如 缺少 $a0. 
    # 不过，要先执行上面的补齐操作
    subsigs_count = logic_len(logic=logic)
    if subsigs_count != len(subsigs[3:]):
        return ""

    yara_name = repl(name, {'.': '_', '-': '_', '/': '_'})
    yara_condition = format_logic(logic) + format_target(TargetDescriptionBlock)
    ldbs = []
    for i in range(len(strings)):
        ldbs.append(formatLDB(strings[i], index=i))

    yara_rules = []
    for _ in ldbs:
        yara_rules.append(_[0])
    yara_rules_string = FORMAT['nl'].join(yara_rules)

    for _ in ldbs:
        ex_condition = _[1]
        if len(ex_condition) == 0:
            continue
        if "EOF" in ex_condition:
            N, m, n = ex_condition["EOF"]
            if len(n) > 0:
                n = f"-{n}"
            if len(m) > 0:
                m = f"-{m}"
            if m == n:
                yara_condition = yara_condition.replace(f"$a{N}", f"$a{N} at filesize{m}")
            else:
                yara_condition = yara_condition.replace(f"$a{N}", f"$a{N} in (filesize{m}..filesize{n})")
        if "EP" in ex_condition:
            pos = ex_condition["EP"]
            yara_condition = yara_condition.replace(f"$a{N}", f"$a{N} at entrypoint{'+' if pos > 0 else ''}{pos}")

    rule = f"""
rule {yara_name}
{{
    strings:
{yara_rules_string}
    condition:
        {yara_condition}
}}"""
    return rule


# REFORMAT NDB STRING TO YARA
def formatNDB(string_t):
    string_t = repl(string_t, {
        "{": "[",
        "}": "]",
        "[-": "[0-"
    })
    if string_t.endswith("]"):
        string_t = re.sub(r'\[\d+\-?\d*\]$', '', string_t)
    if string_t.endswith(")"):
        string_t = re.sub(r'\([\|0-9A-F]*\)$', '', string_t)

    return string_t


# REFORMAT NDU STRING TO YARA
def formatNDU(string_t):
    string_t = repl(string_t, {
        "{": "[",
        "}": "]",
        "[-": "[0-"
    })
    if string_t.endswith("]"):
        string_t = re.sub(r'\[\d+\-?\d*\]$', '', string_t)
    if string_t.endswith(")"):
        string_t = re.sub(r'\([\|0-9A-F]*\)$', '', string_t)

    return string_t


# CREATE RULE FROM NDB STRINGS
def convertNDB(line):
    name = re.findall(REGEX['name'], line)[0]
    strings = re.findall(REGEX['strings'], line)[
        3].replace("\n", "").split("*")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    strings:
{FORMAT['nl'].join([f"{3*FORMAT['tab']}$a{i} = {{ {formatNDB(strings[i])} }}" for i in range(len(strings))])}

    condition:
        any of them
}}"""

    return rule


# CREATE RULE FROM NDU STRINGS
def convertNDU(line):
    name = re.findall(REGEX['name'], line)[0]
    strings = re.findall(REGEX['strings'], line)[
        3].replace("\n", "").split("*")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    strings:
{FORMAT['nl'].join([f"{3*FORMAT['tab']}$a{i} = {{ {formatNDU(strings[i])} }}" for i in range(len(strings))])}

    condition:
        any of them
}}"""

    return rule


# CREATE RULE FROM HSB STRINGS
def convertHSB(line):
    md5 = line.split(":")[0].replace("\n", "")
    name = line.split(":")[2].replace("\n", "")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    condition:
        hash.md5(0, filesize) == "{md5}"
}}"""

    return rule


# CREATE RULE FROM HDB STRINGS
def convertHDB(line):
    md5 = line.split(":")[0].replace("\n", "")
    name = line.split(":")[2].replace("\n", "")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    condition:
        hash.md5(0, filesize) == "{md5}"
}}"""

    return rule

# WRITE RULE TO OUTFILE
def write(outfile, rule):
    with open(outfile, 'a') as of:
        of.write(rule)


# WRITE IMPORT TO OUTFILE
def setup(filename):
    with open(filename, 'w') as yara:
        yara.write("import \"hash\"\n")

# SETTINGS
MODES = {
    'LDB': convertLDB,
    'NDU': convertNDU,
    'NDB': convertNDB,
    'HDB': convertHDB,
    'HSB': convertHSB
}

# ARGPARSE
parser = argparse.ArgumentParser()
parser.add_argument('-i', metavar='inputfile', type=str,
                    help=f'clamav database [{", ".join(EXTENSIONS)}]')
parser.add_argument('-o', metavar='outputfile', type=str,
                    help='yara ruleset [.yara]')
parser.add_argument(
    '-a', help="convert all supported filetypes to .yara files", action="store_true")
parser.add_argument(
    '-d', help="download current clamav virus database", action="store_true")
parser.add_argument(
    '-m', help="merge all available yara rules", action="store_true")
args = parser.parse_args()

if args.i and args.o:
    check(get_file_ext(args.i), 'in', EXTENSIONS,
          f'Wrong input file format, [{", ".join(EXTENSIONS)}]')
    check(get_file_ext(args.o), 'eq', '.yara', 'Wrong output file format, [.yara]')
    INPUT = args.i
    OUTPUT = args.o
    TYPE = get_file_ext(INPUT)[1:].upper()

    limit = sum(1 for line in open(INPUT, 'r'))
    with open(INPUT, 'r') as f:
        c = 0
        for line in f:
            if c%100000 == 0:
                OUTPUTFILE =  OUTPUT.replace('.', f"_{int(c/100000)}.")
            
            if not os.path.exists(OUTPUTFILE):
                write(OUTPUTFILE, "import \"pe\"\n")
                if TYPE in ["HDB", "HSB"]:
                    setup(OUTPUTFILE)
            yara_rule = MODES[TYPE](line)
            if len(yara_rule) > 1:
                write(OUTPUTFILE, yara_rule)
                status("Converted", c+1, limit, 100)
                c += 1
            else:
                write('error.ldb', line)
    print()
elif args.a:
    for t in EXTENSIONS:
        TYPE = t[1:].upper()
        INPUT = "daily" + t
        OUTPUT = "daily_" + t[1:] + ".yara"
        limit = sum(1 for line in open(INPUT, 'r'))
        with open(INPUT, 'r') as f:
            c = 1
            for line in f:
                yara_rule = MODES[TYPE](line)
                if len(yara_rule) > 1:
                    write(OUTPUT, yara_rule)
                    status("Converted " + TYPE, c, limit, 100)
                    c += 1
elif args.m:
    merge()

elif args.d:
    download(URL, DB_FILE)

else:
    parser.print_help(sys.stderr)
