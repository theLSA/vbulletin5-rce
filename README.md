# vbulletin5 rce漏洞检测工具



# 0x00 概述

201909 vbulletion5(5.0.0-5.5.4)爆出rce漏洞（CVE-2019-16759），利用文件ajax/render/widget_php和post参数widgetConfig[code]可直接远程代码执行。

20200811，网上爆出CVE-2019-16759补丁可被绕过，利用ajax/render/widget_tabbedcontainer_tab_panel和构造post参数subWidgets[0][config][code]可直接远程代码执行。

本工具支持单url检测，cmdshell，get web shell(写入一句话木马)，批量检测，批量getshell。



## 0x01 需求

python2.7

pip install requests



## 0x02 快速开始

使用帮助: python vbulletin5-rce.py -h


![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin00.png)


单url漏洞检测: python vbulletin5-rce.py -u "http://www.xxx.com/"


![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin01.png)

![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin06.png)


cmdshell: python vbulletin5-rce.py -u "http://www.xxx.com/" --cmdshell


![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin02.png)

![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin07.png)

单url getshell: python vbulletin5-rce.py -u "http://www.xxx.com/" --getshell


![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin03.png)

![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin08.png)

批量检测: python vbulletin5-rce.py -f urls.txt


![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin04.png)


批量getshhell: python vbulletin5-rce.py -f urls.txt --getshell


![](https://github.com/theLSA/vbulletin5-rce/raw/master/demo/vbulletin05.png)



## 0x03 反馈

[issus](https://github.com/theLSA/vbulletin5-rce/issues)

gmail：[lsasguge196@gmail.com](mailto:lsasguge196@gmail.com)

qq：[2894400469@qq.com](mailto:2894400469@qq.com)