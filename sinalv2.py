import util
import socket
import traceback
import asyncio
import os
import re
import json
import base64
import binascii
import rsa
import requests
import logging
import threading
from autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory


class NotLoginException(Exception):
    pass


class Config:
    primary = 'primary'
    advanced = 'advanced'

    for f in ['account.json', 'account.example.json']:
        if os.path.isfile(f):
            js = json.loads(open(f).read())
            username = js['username']
            password = js['password']
            # sinalv2_payment_level = js['sinalv2_payment_level']
            # assert sinalv2_payment_level in (advanced, primary)
            break


def parse_payload(payload):
    for line in payload.splitlines():
        sp = line.split('=')
        if sp[0].startswith('2cn'):
            lst = sp[1].split(',')
            bids = []
            asks = []
            try:
                for x, y in zip(map(float, lst[26:36]), map(float, lst[36:46])):
                    if y:
                        bids.append({'price': x, 'volume': y})

                for x, y in zip(map(float, lst[46:56]), map(float, lst[56:66])):
                    if y:
                        asks.append({'price': x, 'volume': y})
            except:
                pass

            price = float(lst[7])
            print(price, bids, asks)


def create_protocal(kls, symbol):
    class MyClientProtocal(WebSocketClientProtocol):
        def onConnect(self, response):
            logging.debug('server connect')

        def onOpen(self):
            logging.debug('open')

        @asyncio.coroutine
        def onMessage(self, payload, isBinary):
            # logging.debug('payload {} {}'.format(len(payload), isBinary))
            try:
                parse_payload(str(payload, 'utf8'))
            except:
                logging.debug('parse payload error {}'.format(payload))
                logging.info('parse payload error')

        @asyncio.coroutine
        def onClose(self, wasClean, code, reason):
            logging.debug('closed {} {} {}'.format(wasClean, code, reason))
            yield from kls.execute(symbol)

    return MyClientProtocal


def encrypt_passwd(passwd, pubkey, servertime, nonce):
    key = rsa.PublicKey(int(pubkey, 16), int('10001', 16))
    message = str(servertime) + '\t' + str(nonce) + '\n' + str(passwd)
    passwd = rsa.encrypt(message.encode('utf-8'), key)
    return binascii.b2a_hex(passwd).decode('ascii')


class Sinaquote:
    token_url = 'https://current.sina.com.cn/auth/api/jsonp.php/varxxxl/AuthSign_Service.getSignCode'
    not_login_msg = 'pls login'
    WBCLIENT = 'ssologin.js(v1.4.5)'
    user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36'

    lock = threading.Lock()

    @asyncio.coroutine
    def execute(self, symbol):
        try:
            base_url = 'ws://ff.sinajs.cn/wskt'
            token = yield from self.get_token(symbol)
            url = base_url + '?' + 'token=' + token + '&' + 'list=' + ','.join(symbol)
            logging.debug('start {}'.format(url))
            factory = WebSocketClientFactory(url, debug=False)
            factory.protocol = create_protocal(self, symbol)
            loop = asyncio.get_event_loop()

            coro = loop.create_connection(factory, self.host, 80)
            asyncio.async(coro)
        except requests.RequestException:
            logging.warning('requests error, don"t worry')
            yield from asyncio.sleep(3)
            yield from self.execute(symbol)
        except NotLoginException:
            logging.warning('not login error, try again')
            yield from asyncio.sleep(3)
            yield from self.execute(symbol)
        except:
            traceback.print_exc()
            logging.warning('unexpected error')

    @property
    def cookie_path(self):
        return os.path.join('log', 'sina_cookie_%s.txt' % self.username)

    def __init__(self):
        self.host = socket.gethostbyname('ff.sinajs.cn')
        self.init_public_ip()
        self.username = Config.username
        self.password = Config.password
        self.sess = requests.session()
        self.sess.headers['User-Agent'] = self.user_agent
        util.load_cookie(self.sess, self.cookie_path)

    @asyncio.coroutine
    def is_login(self):
        try:
            yield from self.get_token('2cn_sh600000')
            return True
        except:
            return False

    @asyncio.coroutine
    def login(self):
        logging.debug('sina quote login')
        islogin = yield from self.is_login()
        if islogin:
            logging.info('sina quote already login')
            return
        resp = self.sess.get(
            'http://login.sina.com.cn/sso/prelogin.php?'
            'entry=sso&callback=sinaSSOController.preloginCallBack&'
            'su=%s&rsakt=mod&client=%s' %
            (base64.b64encode(self.username.encode('utf-8')), self.WBCLIENT)
        )

        pre_login_str = re.match(r'[^{]+({.+?})', resp.text).group(1)
        pre_login = json.loads(pre_login_str)

        data = 'entry=finance&gateway=1&from=&savestate=30&useticket=0&pagerefer=http%3A%2F%2Fstock.finance.sina.com.cn%2Flv2%2Fsh603001.html&vsnf=1&door=xxxxx&su=dGFuZ3lvdXplJTQwZ21haWwuY29t&service=sso&servertime=1441555474&nonce=CNHWKG&pwencode=rsa2&rsakv=1330428213&sp=c040887d248832cbecdc029dc57a55a6710d5c46f84deb39a479cee8d8a91290183df12d1f3692c19fe7c81eb652372bd9e6b6a6815547530a1db4a89c35180976b1036714cc2d94bd5ef81466a143da6cfdb1df4104f289987e79e31d30f2c5b294fb04dce4a4c48da27eaa6cd61b7de14108f428964046f11620729915e3cf&sr=1920*1080&encoding=UTF-8&cdult=3&domain=sina.com.cn&prelt=112&returntype=TEXT'
        yzm = util.get_yzm(self.sess, 'http://login.sina.com.cn/cgi/pin.php', 'sina_yzm.jpg')
        dct = {}
        for d in data.split('&'):
            sp = d.split('=')
            dct[sp[0]] = sp[1]
        dct['door'] = yzm
        dct['sp'] = encrypt_passwd(self.password, pre_login['pubkey'], pre_login['servertime'], pre_login['nonce'])
        dct['rsakv'] = pre_login['rsakv']
        dct['su'] = base64.b64encode(requests.utils.quote(self.username).encode('utf-8')).decode('ascii')
        dct['servertime'] = pre_login['servertime']
        dct['nonce'] = pre_login['nonce']
        r = self.sess.post('http://login.sina.com.cn/sso/login.php', data=dct)
        logging.info('login rsp %s ' % r.text)
        util.save_cookie(self.sess, self.cookie_path)

    @asyncio.coroutine
    def get_token(self, symbols):
        if not isinstance(symbols, list):
            symbols = [symbols]
        # if Config.sinalv2_payment_level == Config.advanced:
        #     query_type = 'A_hq'
        # elif Config.sinalv2_payment_level == Config.primary:
        query_type = 'hq_pjb'
        # else:
        #     assert False

        public_ip = self.get_public_ip()
        query_list = ','.join(symbols)

        token_url = self.token_url
        dct = {'query': query_type,
               'ip': public_ip,
               'list': query_list,
               'kick': 1
               }

        def sess_get_wrapper():
            logging.debug('dct {}'.format(dct))
            logging.debug('token_url {}'.format(token_url))
            logging.debug('cookie {}'.format(self.sess.cookies))
            return self.sess.get(token_url, params=dct).text

        loop = asyncio.get_event_loop()
        future1 = loop.run_in_executor(None, sess_get_wrapper)
        res = yield from future1
        logging.debug('res {}'.format(res))

        if self.not_login_msg in res:
            raise NotLoginException()
        else:
            token_start = res.find('\"') + 1
            token_end = res.find('\"', token_start)
            token = res[token_start: token_end]
            logging.debug('found token:  %s' % token)
            return token

    def init_public_ip(self):
        txt = requests.get('http://ipinfo.io/ip').text.strip()
        self.ip = txt
        logging.info('public ip %s' % self.ip)

    def get_public_ip(self):
        return self.ip

    @staticmethod
    def get_instance():
        return Sinaquote()

    @asyncio.coroutine
    def add_cons(self, cons):

        symbol = []
        for c in cons:
            if c.exchange == 'sh':
                symbol.append('2cn_sh%s' % c.fund_code)
            elif c.exchange == 'sz':
                symbol.append('2cn_sz%s' % c.fund_code)
            else:
                assert False

        yield from self.execute(symbol)


class Contract:
    def __init__(self, unique_symbol):
        self.unique_symbol = unique_symbol
        self.fund_code = unique_symbol[2:]
        if unique_symbol.startswith('sh'):
            self.exchange = 'sh'
        else:
            self.exchange = 'sz'


@asyncio.coroutine
def main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("requests").setLevel(logging.WARNING)

    cons = [Contract('sh600000'), Contract('sz150150')]
    print('len cons {}'.format(len(cons)))
    instance = Sinaquote.get_instance()
    yield from instance.login()
    cut = 50
    chunks = [cons[x:x + cut] for x in range(0, len(cons), cut)]
    for c in chunks:
        logging.debug('addcon {}'.format(c))
        asyncio.async(instance.add_cons(c))


if __name__ == '__main__':
    os.makedirs('log', exist_ok=True)
    asyncio.async(main())
    asyncio.get_event_loop().run_forever()
