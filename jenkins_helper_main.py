#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  Lv Lifeng
# @Time    2022-05-05 02:23

import jenkins_helper

# Config
ipaddress = '0.0.0.0'
port = 11111
# set username and password for this web server not jenkins
username = None
password = None

if __name__ == '__main__':
    jenkins_helper.start(
        jenkins_helper.JenkinsHelper,
        address=ipaddress,
        port=port,
        multiple_instance=True,
        debug=False,
        username=username,
        password=password
    )

