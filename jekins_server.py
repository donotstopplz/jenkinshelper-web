#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  Lv Lifeng
# @Time    2022-05-04 20:06

import jenkins
import xml.dom.minidom
import sys


# 官方文档 https://python-jenkins.readthedocs.io/en/latest/
# 获取jenkins server
# username,password为登录jenkins web ui的账号密码,url为登录jenkins web ui之后浏览器中显示的链接
# e.g. 开发环境jenkins登录之后显示 http://jenkins.killerwhale.cn/jenkins
#      测试环境jenkins登录之后显示 http://cii.szzbmy.com
#      生产环境jenkins登录之后显示 https://rp-fe-jenkins.szzbmy.com
def login_jeknis(url, username, password):
    global server
    server = jenkins.Jenkins(url, username, password)
    # user = server.get_whoami()
    # version = server.get_version()
    # print('Hello %s from Jenkins %s' % (user['fullName'], version))
    return server
