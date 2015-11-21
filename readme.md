#软件使用 该软件需要自行购买新浪的level2标准版

在windows, linux, mac下都可以运行 支持python3.4+

# 安装
```
git clone https://github.com/flycandy/sinalv2
cd sinalv2
pip3 install -r requirements.txt
vim account.example.json # 修改account.example.json 为自己的用户名密码
python3 sinalv2.txt
```

# 新浪level2行情接口 说明

## 登陆新浪

不过新浪登陆后, 一个cookie能够使用很久. 所以, 就算不写自动登陆的脚本也是没有问题的, 可以从浏览器取得cookie, 然后存在文件里, 每次从文件里读取cookie即可

登陆脚本参考该页面 Reference https://gist.github.com/mrluanma/3621775

## 请求一个token


URL:     'https://current.sina.com.cn/auth/api/jsonp.php/varxxxl/AuthSign_Service.getSignCode'
方法: Post

字段       | 说明 
---------|-------
query | query_type
 ip  | 当前机器的公网IP
list | 请求的查看股票的列表 
kick | 1 就是把其余的请求踢掉, 0就是如果有其他地方登陆的话. 返回错误 
    |经过测试. 这里应该可以一直设置成1 有0这个选项. 是因为网页登陆level2行情的时候. 默认都只会发送0请求, 防止你同一个账户异地多浏览器登陆




## 使用token用websocket获取行情

token需要定时更新. 每一个websocket只会持续大概3-5分钟. 当websocket disconnect之后, 需要重新请求一个token.

然后再次链接websocket

