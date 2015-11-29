# Sina Level2 Quote Python API
该软件需要自行购买新浪的level2标准版 (168每月, 998每年)

暂时不支持新浪的level2普及版 (60每月, 298每年) (楼主正在研究中...)

购买地址 http://stock.finance.sina.com.cn/stock/buy.php

标准版网页 http://stock.finance.sina.com.cn/lv2/sh603001.html

普及版网页 http://finance.sina.com.cn/realstock/company/sh603001/l2.shtml

版本要求 Python3.4+

# 安装
```
git clone https://github.com/flycandy/sinalv2
cd sinalv2
pip install -r requirements.txt
vim account.example.json # 修改account.example.json 为自己的用户名密码
python sinalv2.py
```



# 新浪level2行情接口 说明

## Step 1 登陆新浪

登陆脚本参考该页面 Reference https://gist.github.com/mrluanma/3621775

## Step 2 请求一个token


请求地址: https://current.sina.com.cn/auth/api/jsonp.php/varxxxl/AuthSign_Service.getSignCode
方法: Get

字段       | 说明 
---------|-------
query_type | A_hq (A股行情)
 ip  | 当前机器的公网IP
list | 请求的查看股票的列表 
kick | 设置为1, 否则可能出现取不到token的情况




## 使用token用websocket获取行情

获取token是一个websocket协议

ws://ff.sinajs.cn/wskt?token={token}&list={list}

token必须是使用该{list}得到的token. 不然会报错

token需要定时更新. 每一个websocket只会持续大概3-5分钟. 当websocket disconnect之后, 需要重新请求一个token. 然后再次链接websocket
