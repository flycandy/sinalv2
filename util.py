import calendar
from importlib import reload
import logging
import traceback
from unittest import TestCase

import pandas as pd
import pytz
import requests
import shutil

__author__ = 'tyz'

from datetime import timedelta, tzinfo, datetime, date
import asyncio
import os
import time
import threading


def get_yzm(sess, url, path):
    yzm = sess.get(url, stream=True)
    yzm_jpg_path = os.path.join('log', path)
    with open(yzm_jpg_path, 'wb') as f:
        yzm.raw.decode_content = True
        # f.write(yzm.text.encode('utf8'))
        shutil.copyfileobj(yzm.raw, f)

    # yzm = yundama(yzm_jpg_path)
    print('close jpg, and input the verification code')
    os.system(yzm_jpg_path)
    x = input('verification code:')
    return x


def load_cookie(sess, cookie_path):
    sess.cookies.clear()
    if os.path.isfile(cookie_path):
        with open(cookie_path) as f:
            for line in f.read().splitlines():
                sp = line.split(',')
                if len(sp) == 4:
                    sess.cookies.set(sp[0], sp[1], domain=sp[2], path=sp[3])


def save_cookie(sess, cookie_path):
    # time.sleep(5)
    # print(requests.utils.dict_from_cookiejar(sess.cookies))
    # print('save cookie', sess.cookies)
    try:
        with open(cookie_path, 'w') as f:
            for c in sess.cookies:
                f.write('%s,%s,%s,%s\n' % (c.name, c.value, c.domain, c.path))
    except:
        logging.warning('save cookie error')
