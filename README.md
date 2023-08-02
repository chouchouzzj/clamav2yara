## Comment:
Thanks [Jakob Schaffarczyk](https://github.com/js-on/clamav2yara)

All I did was add support for ldb files

## Reference

### Clamav
  [Logical signatures](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html)

  [Extended signature format](https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html#extended-signature-format)

### Yara
  [Writing YARA rules](https://yara.readthedocs.io/en/stable/writingrules.html)

## Script usage:

### Prerequisites:

[ClamAV Installation](https://www.clamav.net/documents/installing-clamav)

usage: clamav2yara.py [-h] [-i inputfile] [-o outputfile] [-a] [-d] [-m] 

optional arguments: 
  -h, --help   show this help message and exit 
  -i inputfile  clamav database [.ndu, .ndb, .hdb, .hsb .ldb] 
  -o outputfile  yara ruleset [.yara] 
  -a       convert all supported filetypes to .yara files 
  -d       download current clamav virus database 
  -m       merge all available yara rules

### Download current database
Downloads current database (daily.cvd) file.

`python3 clamav2yara.py -d`

### Convert specific file
Converts specified input file to Yara ruleset

`python3 clamav2yara.py -i daily.(ndu|ndb|hdb|hsb|ldb) -o output.yara`

### Convert all files
Converts all supported filetypes to Yara rulesets

`python3 clamav2yara.py -a`

### Merge files
Merge all available Yara rules to one large ruleset

`python3 clamav2yara.py m`
  
### Help
Print the given help message.

`python3 clamav2yara.py --help`

## 转换规则

clamav 官方文档 Logical signatures 这章描述到：
ldb每一行一条规则，形式如下：
SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;Subsig2;...

### 0. SubsigN 的分类
  1. 正则表达式
    
    默认只要有 / 就认为是正则
    0&1/(?P<object>\d\s*\d)\s*obj[^>]*\x2fParent\s*\d\s*-\d\s*R.*?\x2fKids\s*\[\s*(?P=object)\s*R/smi

  2. 十六进制字符串

    SubsigN 没有::后缀，且 所有字符均在 [^0-9a-fA-F\(\)\[\]\?\*|-]范围内的，就是十六进制字符串，否则就换成ascii码字符串

    433a5c55736572735c5075626c69635c;

  3. 字符串

    2f432072656720616464*2f7620*2f74205245475f535a202f64*2022433a5c55736572735c5075626c69635c*2e65786522::i

### 1. 常规转换方法

举个例子，LogicalExpression 是 0|1|2  正常情况会转换成
```yara
  rule SignatureName
  {
      strings:
        $a0 = { Subsig0 }
        $a1 = { Subsig1 }
        $a2 = { Subsig2 }

      condition:
          $a0 or $a1 or $a2
  }
```

### 2. SubsigN 带前缀

#### a. EOF-n
 参考 [Extended signature format](https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html#extended-signature-format)

ldb规则如下:

Win.Downloader.ModernLoader-9963808-0;Engine:90-255,Target:7;0&1&2;EOF-300,300:66756e6374696f6e20554e4958207b{10-40}2d73706c69742027282e2e2927::awi;EOF-300,300:5b427974655b5d5d{3-10}554e4958::awi;EOF-50,50:5d3a3a4d61696e2829::awi

yara规则:
```yara
rule Win_Downloader_ModernLoader_9963808_0
{
    strings:
		$a0 = "function UNIX {[10-40]-split '(..)'" ascii wide nocase
		$a1 = "[Byte[]][3-10]UNIX" ascii wide nocase
		$a2 = "]::Main()" ascii wide nocase
    condition:
        $a0 at filesize-300 and $a1 at filesize-300 and $a2 at filesize-50
}
```

#### b. EP+n
文档同上, 文档中举例在 [Logical signatures](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html)

    Sig4;Engine:51-255,Target:1;((0|1)&(2|3))&4;EP+123:33c06834f04100f2aef7d14951684cf04100e8110a00;S2+78:22??32c2d252229{-15}6e6573(63|64)61706528;S3+50:68efa311c3b9963cb1ee8e586d32aeb9043e;f9c58dcf43987e4f519d629b103375;SL+550:6300680065005c0046006900

对应yara规则中的condition应该是

    $a at entrypoint + 123

但是从文档看，也存在 EP+n,y的情况，因此也会转成

    $a in (entrypoint+n..entrypoint+y)

### 3. SubsigN 带后缀
这个指的是 Subsignature Modifiers. 就是修饰符.

常见修饰符就是 i w f a 四种. 分别对应 nocase wide fullword ascii

上面 Win.Downloader.ModernLoader-9963808-0 这条规则中已经有示例了


### 4. SubsigN 带修饰符
  带修饰符的规则，需要将16进制字符串转换成ascii字符串.
  这里需要注意的是，有些16进制字符转换后，具有换行的效果，而yara规则中，单条是不能有换行的。
  因此就只有删掉这些换行符了，不过也就增加了漏报的风险.
  
  其实用16进制去匹配可是可以的，但是偏偏有些规则，又带了 ::i 或者 ::w 这样的后缀，不区分大小写活宽字符！ 那就又必须转换成字符串.
  ```python
  repl(string_t, {
        "\r": "",
        "\n": "",
        chr(0x0b): "",
        chr(0x0c): ""
    })
  ```

### 5. 以下情况不转换

#### a. 黑名单
  有些ldb的特征字符串确实不知道怎么转成yara规则，就放到单独一个忽略列表中。这个后面会详细讲到

#### b. 带宏的规则
  TargetDescriptionBlock 中包含 "Container" 关键字的，就直接略过.

#### c. LogicalExpression 字符串异常
  LogicalExpression 中带字符"-"的，直接略过

    Win.Countermeasure.G2JS_Script_Generic_1-9818937-0;Engine:81-255,Target:7;0,1-4&1,1-4&2,1-4;2e646573657269616c697a655f3228::i;53797374656d2e494f2e4d656d6f727953747265616d::i;53657269616c697a6174696f6e2e466f726d6174746572732e42696e6172792e42696e617279466f726d6174746572::i

#### d. LogicalExpression 解析失败
  有些 LogicalExpression 字符串只有 5&6 但是根据解析后面的字符串 Subsig0;Subsig1;Subsig2;... 发现特征数量明显对不上,就只有忽略了。

  例如有些LogicalExpression，少个0，那yarac编译的时候，就会报 $a0 缺失。例如：

    Win.Malware.GraphSteel-9946923-0;Engine:90-255,Target:1;5&6;2e7a6970;2e617669;2e6a7067;2e706466;43726564456e756d657261746557;80383074308038317418803832745d{-50}813866756c6c{-50}81386e6f6e65;0&1&2&3&4/\.([a-z]{3}\.[a-z]{3})+\.[a-z]{3}/

  当然，也可能是我没找到这个正则含义的文档.

    0&1&2&3&4/\.([a-z]{3}\.[a-z]{3})+\.[a-z]{3}/   


#### e. 前缀为 fuzzy_img#

    Xls.Downloader.Trojan-a3552b953bb78322-a3552b953bb78322-9950267-0;Engine:150-255,Target:0;0;fuzzy_img#a3552b953bb78322

  没有找到转换的方法。

## 坑

### 正则表达式异常

#### 1. 后缀的含义不理解
参考文档 [PCRE subsignatures](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html#pcre-subsignatures)
这个可能是我的问题，给了文档，但是我确实不知道这些正则怎么转换, 所以就把后缀统统忽略了，如果有人知道怎么转换，请不吝赐教！

Pdf.Exploit.CVE_2019_5067-7054139-0;Engine:81-255,Target:10;2;2F506172656E74;2F4B696473;0&1/(?P<object>\d\s*\d)\s*obj[^>]*\x2fParent\s*\d\s*-\d\s*R.*?\x2fKids\s*\[\s*(?P=object)\s*R/smi


#### 2. 正则错误 error: greedy and ungreedy quantifiers can't be mixed in a regular expression

    Win.Exploit.PowerSploit-6982894-2;Engine:81-255,Target:0;1;496E766F6B652D5265666C6563746976655045496E6A656374696F6E;0/inflatebin.*?(?P<main>\$\w+)\s?=\s?\[System\.Convert\]::FromBase64String\([\x22\x27].*[\x22\x27]\)\x3b.*?(?P=main)\s?=\s?.*?(?P=main).*?(?P=main).*?HKCU:\\Software\\Classes\\.*?(?P=main).*?Invoke-ReflectivePEInjection/smi


yara规则如下

    rule Win_Exploit_PowerSploit_6982894_2
    {
        strings:
            $a0 = { 496E766F6B652D5265666C6563746976655045496E6A656374696F6E }
            $a1 = /inflatebin.*?(?P<main>\$\w+)\s?=\s?\[System\.Convert\]::FromBase64String\([\x22\x27].*[\x22\x27]\)\x3b.*?(?P=main)\s?=\s?.*?(?P=main).*?(?P=main).*?HKCU:\\Software\\Classes\\.*?(?P=main).*?Invoke-ReflectivePEInjection/smi
        condition:
            $a0 and $a1
    }

解决方案：
```python
re_str = re_str.replace("*?","*").replace("+?","+").replace("(?", "(\\?")
```

### 规则异常
#### 3. SubsigN 以 [\d]+, 或者 [\d]+: 开头

ldb规则如下：

    Win.Malware.Cridex-7129958-0;Engine:51-255,Target:1;0&1&2&3&4;263,503:00000000400100000000100000001000000500000000{3772-3836}909090909090904883ec28b930000000{213-233}884424074889c859c39090909090909090904883;4335,4527:4424074889c859c39090909090909090904883ec{96-164}9090909090909090909090909041565657555348{515-1427}90909090909041574156415456575553;5035,6075:90909090904157415641545657555348{3728-302904}cccccccccc0f0bcccccccccccccccccccccccccccc4881ec{2746-3408}00004531c04489c141b80010000041b904000000;11550,312384:004531c04489c141b80010000041b90400000044{2722-3556}488b4424504883f8000f95c180e10188;14914,308978:cccccccccccccccccccccccccccc4881ecd8000000488d15

没找到文档在哪里，只有把:前面都删了


#### 4. SubsigN 以 \[\d\] 开头

ldb规则如下：

    Html.Trojan.Phishing-9988006-0;Engine:90-255,FileSize:312000-318000,Target:3;0&1&2&3&4;646f63756d656e742e626f64792e717565727973656c6563746f7228{8}2822{4}222c22{3}2229292e73657461747472696275746528{8}2822{4}222c22{3}22292c{8};{8}2b3d{8}28{8}2e63686172636f6465617428{8}295e{8}5b{8}25{8}2e6c656e6774685d2e63686172636f6465617428302929;6966286e657772656765787028{8}2822{148}222c22{109}22292c226922292e74657374286e6176696761746f722e757365726167656e7429297b72657475726e7d;646f63756d656e742e6164646576656e746c697374656e657228{8}2822{12}222c22{9}22292c66756e6374696f6e28297b69662877696e646f772e{9}297b72657475726e7d{8}28{8}293b;2e636c69636b28293b

这里以[8]开头，没找到文档在哪里，只有把整条规则都忽略了。


#### 5. SubsigN 以 00 开头，又带修饰符

ldb如下:
    Win.Trojan.Inject-9885349-0;Engine:81-255,Target:1;0&1&2&3;0050726F6A656374312E646C6C00::w;0050726F6A656374312E70646200;00526573756D6554687265616400;005F436F72446C6C4D61696E00

0050726F6A656374312E646C6C00::w   这里要求转换成wide 宽字符，但是第一个字节又是 00，这样又只能二进制匹配。只有手动忽略这种奇葩规则了。


#### 6. SubsigN 出现 [\d]{1} 半个字节

ldb如下：

    Win.Trojan.SaintbotDropper-9941327-0;Engine:90-255,Target:1;0&1&2&3;0608060817DA9A1472DA050070168D??0000011414142{2}0000A2{2}0000AA22B17;4765745265736f75726365537472696e67;5265736f757263654d616e61676572;53797374656d2e5265736f7572636573

    06 08 06 08 17 DA 9A 14 72 DA 05 00 70 16 8D ?? 00 00 01 14 14 14 2{2} 00 00 A2 {2} 00 00 AA 22 B1 7
    格式化之后发现，数量对不上

#### 7. SubsigN 中出现 ([\d]+|[\d]\?)

ldb如下：

    Win.Backdoor.CrimsonRAT-9953760-0;Engine:90-255,Target:1;0&1&2&3&(4|5);00546370436c69656e7400;00436f707946726f6d53637265656e00;006765745f4d616368696e654e616d6500;007365745f53686f77496e5461736b62617200;6f??00000a031f645a0?6f??00000a5b5a1f645b(130?|0?)03031f645a0?6f??00000a5b035a1f645b581f6458130?0?110?(110?|0?)73??00000a73??00000a;11046f2f00000a2526031f4028650000065a11046f2f00000a(2526|)5b5a1f4428650000065b130503031f4828650000065a11046f3000000a5b035a1f4c2865000006

    (2526|) 这个不知道怎么解释。忽略！
    其实下面这样的规则，yara 4.3.0以上也是认的。但是我装的是 yara 3.9.0 所以还是算了。
    { 6f ?? 00 00 0a 03 1f 64 5a 0? 6f ?? 00 00 0a 5b 5a 1f 64 5b [130?|0?] 03 03 1f 64 5a 0? 6f ?? 00 00 0a 5b 03 5a 1f 64 5b 58 1f 64 58 13 0? 0? 11 0? [110?|0?] 73 ?? 00 00 0a 73 ?? 00 00 0a }


#### 8. SubsigN 转换成ascii字符串之后，出现特殊符号

    Win.Trojan.Generic-0-6517450-0;Engine:81-255,Target:1;0&1&2&3&4;4f6e457865637574654d6163726f;3a2a3a303a403a443a503a583a5c3a603a643a683a6c3a703a743a783a7c3a;43616e6e6f742064726167206120666f726d22416e206572726f722072657475726e65642066726f6d2044444520202824302578292f444445204572726f72202d20636f6e766572736174696f6e206e6f742065737461626c697368656420282430257829304572726f72206f63637572726564207768::w;446f776e476c7970682e44617461;3624362c3634363c3644364c3654365c3664366c367436343738373c37403748374c375037543758375c376037643768376c377037743778377c37

  前面有提到，规则带修饰符的话，需要转换成ascii码字符串，但是有些ascii字符串带回车换行这些特殊字符，导致yarac编译错误，前面也有提到。除此之外还有引号。