#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author  Lv Lifeng
# @Time    2022-05-05 02:23

"""
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
import datetime
import os

import jenkins
import xml.dom.minidom
import sys
import remi.gui as gui
from remi import start, App
import random
import threading


class CookieInterface(gui.Tag, gui.EventSource):
    def __init__(self, remi_app_instance, **kwargs):
        """
        This class uses javascript code from cookie.js framework ( https://developer.mozilla.org/en-US/docs/Web/API/document.cookie )
        /*\
        |*|
        |*|  :: cookies.js ::
        |*|
        |*|  A complete cookies reader/writer framework with full unicode support.
        |*|
        |*|  Revision #2 - June 13th, 2017
        |*|
        |*|  https://developer.mozilla.org/en-US/docs/Web/API/document.cookie
        |*|  https://developer.mozilla.org/User:fusionchess
        |*|  https://github.com/madmurphy/cookies.js
        |*|
        |*|  This framework is released under the GNU Public License, version 3 or later.
        |*|  http://www.gnu.org/licenses/gpl-3.0-standalone.html
        |*|
        \*/
        """
        super(CookieInterface, self).__init__(**kwargs)
        gui.EventSource.__init__(self)
        self.app_instance = remi_app_instance
        self.EVENT_ONCOOKIES = "on_cookies"
        self.cookies = {}

    def request_cookies(self):
        self.app_instance.execute_javascript("""
            var aKeys = document.cookie.replace(/((?:^|\s*;)[^\=]+)(?=;|$)|^\s*|\s*(?:\=[^;]*)?(?:\1|$)/g, "").split(/\s*(?:\=[^;]*)?;\s*/);
            var result = {};
            for (var nLen = aKeys.length, nIdx = 0; nIdx < nLen; nIdx++) { 
                var key = decodeURIComponent(aKeys[nIdx]);
                result[key] = decodeURIComponent(document.cookie.replace(new RegExp("(?:(?:^|.*;)\\s*" + encodeURIComponent(key).replace(/[\-\.\+\*]/g, "\\$&") + "\\s*\\=\\s*([^;]*).*$)|^.*$"), "$1")) || null; 
            }
            remi.sendCallbackParam('%s','%s', result);
            """ % (self.identifier, self.EVENT_ONCOOKIES))

    @gui.decorate_event
    def on_cookies(self, **value):
        self.cookies = value
        return (value,)

    def remove_cookie(self, key, path='/', domain=''):
        if not key in self.cookies.keys():
            return
        self.app_instance.execute_javascript("""
            var sKey = "%(sKey)s";
            var sPath = "%(sPath)s";
            var sDomain = "%(sDomain)s";
            document.cookie = encodeURIComponent(sKey) + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT" + (sDomain ? "; domain=" + sDomain : "") + (sPath ? "; path=" + sPath : "");
            """ % {'sKey': key, 'sPath': path, 'sDomain': domain})

    def set_cookie(self, key, value, expiration='Infinity', path='/', domain='', secure=False):
        """
        expiration (int): seconds after with the cookie automatically gets deleted
        """

        secure = 'true' if secure else 'false'
        self.app_instance.execute_javascript("""
            var sKey = "%(sKey)s";
            var sValue = "%(sValue)s";
            var vEnd = eval("%(vEnd)s");
            var sPath = "%(sPath)s"; 
            var sDomain = "%(sDomain)s"; 
            var bSecure = %(bSecure)s;
            if( (!sKey || /^(?:expires|max\-age|path|domain|secure)$/i.test(sKey)) == false ){
                var sExpires = "";
                if (vEnd) {
                    switch (vEnd.constructor) {
                        case Number:
                            sExpires = vEnd === Infinity ? "; expires=Fri, 31 Dec 9999 23:59:59 GMT" : "; max-age=" + vEnd;
                        break;
                        case String:
                            sExpires = "; expires=" + vEnd;
                        break;
                        case Date:
                            sExpires = "; expires=" + vEnd.toUTCString();
                        break;
                    }
                }
                document.cookie = encodeURIComponent(sKey) + "=" + encodeURIComponent(sValue) + sExpires + (sDomain ? "; domain=" + sDomain : "") + (sPath ? "; path=" + sPath : "") + (bSecure ? "; secure" : "");
            }
            """ % {'sKey': key, 'sValue': value, 'vEnd': expiration, 'sPath': path, 'sDomain': domain,
                   'bSecure': secure})


class LoginManager(gui.Tag, gui.EventSource):
    """
    Login manager class allows to simply manage user access safety by session cookies
    It requires a cookieInterface instance to query and set user session id
    When the user login to the system you have to call
        login_manager.renew_session() #in order to force new session uid setup

    The session have to be refreshed each user action (like button click or DB access)
    in order to avoid expiration. BUT before renew, check if expired in order to ask user login

        if not login_manager.expired:
            login_manager.renew_session()
            #RENEW OK
        else:
            #UNABLE TO RENEW
            #HAVE TO ASK FOR LOGIN

    In order to know session expiration, you should register to on_session_expired event
        on_session_expired.do(mylistener.on_user_logout)
    When this event happens, ask for user login
    """

    def __init__(self, cookieInterface, session_timeout_seconds=60, **kwargs):
        super(LoginManager, self).__init__(**kwargs)
        gui.EventSource.__init__(self)
        self.expired = True
        self.session_uid = str(random.randint(1, 999999999))
        self.cookieInterface = cookieInterface
        self.session_timeout_seconds = session_timeout_seconds
        self.timer_request_cookies()  # starts the cookie refresh
        self.timeout_timer = None  # checks the internal timeout

    def timer_request_cookies(self):
        self.cookieInterface.request_cookies()
        self.cookie_timer = threading.Timer(self.session_timeout_seconds / 10.0, self.timer_request_cookies)
        self.cookie_timer.daemon = True
        self.cookie_timer.start()

    @gui.decorate_event
    def on_session_expired(self):
        self.expired = True
        return ()

    def renew_session(self):
        """Have to be called on user actions to check and renew session
        """
        if ((not 'user_uid' in self.cookieInterface.cookies) or self.cookieInterface.cookies[
            'user_uid'] != self.session_uid) and (not self.expired):
            self.on_session_expired()

        if self.expired:
            self.session_uid = str(random.randint(1, 999999999))

        self.cookieInterface.set_cookie('user_uid', self.session_uid, str(self.session_timeout_seconds))

        # here we renew the internal timeout timer
        if self.timeout_timer:
            self.timeout_timer.cancel()
        self.timeout_timer = threading.Timer(self.session_timeout_seconds, self.on_session_expired)
        self.timeout_timer.daemon = True
        self.expired = False
        self.timeout_timer.start()


class JenkinsServer:
    server = None

    def __init__(self, url, username, password):
        JenkinsServer.server = jenkins.Jenkins(url, username, password)


class XmlStdin:
    def __init__(self):
        self.str = ""

    def write(self, value):
        self.str += value

    def to_string(self):
        return self.str


class JenkinsHelper(App):
    def __init__(self, *args):
        res_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'res')
        super(JenkinsHelper, self).__init__(*args, static_file_path={'hi': res_path})
        self.rebuild = None

    def main(self, name='hello world'):
        self.set_favicon()
        self.login_manager = LoginManager(CookieInterface(self), 60 * 20)
        self.login_manager.on_session_expired.do(self.on_logout)

        # login start
        self.login_container = gui.VBox(width=600, margin='100px auto')
        api_url = gui.Label('Jenkins API url', width=120, height=20, margin='1px auto')
        self.api_url_value = gui.TextInput(width=400, margin='1px auto')
        self.api_url_value.add_class("form-control input-lg")
        api_url_box = gui.HBox(children=[api_url, self.api_url_value],
                               style={'width': '550px', 'margin': '4px auto', 'background-color': 'lightgray'})
        username = gui.Label('Jenkins username', width=120, height=20, margin='1px auto')
        self.username_value = gui.TextInput(width=400, margin='1px auto')
        self.username_value.add_class("form-control input-lg")
        username_box = gui.HBox(children=[username, self.username_value],
                                style={'width': '550px', 'margin': '4px 10px', 'background-color': 'lightgray'})
        password = gui.Label('Jenkins password', width=120, height=20, margin='1px auto')
        self.password_value_text = gui.TextInput(width=400, margin='1px auto')
        self.password_value_text.add_class("form-control input-lg")
        self.password_value_text.onchange.do(self.get_password_value)
        password_box = gui.HBox(children=[password, self.password_value_text],
                                style={'width': '550px', 'margin': '4px auto', 'background-color': 'lightgray'})
        bt_login = gui.Button('LOGIN', width=200, height=30, margin='10px')
        bt_login.onclick.do(self.on_login)
        # bt_renew = gui.Button('RENEW BEFORE EXPIRATION')
        # bt_renew.onclick.do(self.on_renew)
        self.lblsession_status = gui.Label()
        self.login_container.append([api_url_box, username_box, password_box, bt_login, self.lblsession_status])
        # login end

        # main start
        self.main_container = gui.Container(width=900, margin='0px auto')
        # self.main_container.set_size(1020, 600)
        self.main_container.set_layout_orientation(gui.Container.LAYOUT_VERTICAL)

        # maine-center start
        self.center_container = gui.HBox(children=[],
                                         style={'margin': '4px auto',
                                                'background-color': 'lightgray'})

        # head start
        self.login_api = gui.Label()
        self.login_user = gui.Label()
        self.logout_bt = gui.Button('LOG OUT', width=80, height=20, margin='4px')
        self.logout_bt.onclick.do(self.on_logout)
        self.head = gui.HBox(children=[self.login_api, self.login_user, self.logout_bt],
                             style={'margin': '4px auto', 'background-color': 'lightgray'})
        self.main_container.append(self.head)
        # head end

        # view list
        self.view_lable = gui.Label("View", style={'margin': '0px 10px'})
        self.view_list_dd = gui.DropDown(width='200px')
        self.view_list_dd.style.update({'font-size': 'large'})
        self.view_list_dd.add_class("form-control dropdown")
        self.view_list_dd.onchange.do(self.list_view_on_selected)
        self.search_text = gui.TextInput(style={'margin': '0px 4px'})
        self.search_text.onchange.do(self.on_search_jobs)
        self.view_search_container = gui.HBox(children=[self.view_lable, self.view_list_dd, self.search_text],
                                              style={'margin': '0px auto',
                                                'background-color': 'lightgray'})
        self.main_container.append(self.view_search_container)
        # maine-center start
        self.left_container = gui.VBox(children=[],
                                       style={'margin': '4px 4px',
                                              'background-color': 'lightgray'})
        # job list
        self.job_list = []
        self.job_list_view = gui.ListView.new_from_list(self.job_list, width=300, height=420, margin='10px')
        self.job_list_view.onselection.do(self.select_job)
        self.select_all_bt = gui.Button('Select All', width=100, height=30, margin='10px')
        self.select_all_bt.onclick.do(self.on_select_all)
        # self.left_container.append(self.view_container, 'viewList')
        self.left_container.append(self.job_list_view, 'jobList')
        self.left_container.append(self.select_all_bt, 'all')
        self.center_container.append(self.left_container)

        self.selected_jobs = []
        self.selected_job_list = gui.ListView.new_from_list(self.selected_jobs, width=300, height=420, margin='10px')
        self.selected_job_list.onselection.do(self.un_select_job)
        self.cleal_all_bt = gui.Button('Clear All', width=100, height=30, margin='10px')
        self.cleal_all_bt.onclick.do(self.on_clear_all)
        self.right_container = gui.VBox(children=[self.selected_job_list, self.cleal_all_bt],
                                        style={'margin': '4px 4px',
                                               # 'margin-top': '30px',
                                               'background-color': 'lightgray'})
        self.center_container.append(self.right_container)

        self.button_list = gui.VBox(children=[],
                                    style={'background-color': 'lightgray'})
        self.build_bt = gui.Button('Build', width=100, height=30, margin='10px')
        self.build_bt.onclick.do(self.on_build)
        self.update_bt = gui.Button('Update', width=100, height=30, margin='10px')
        self.update_bt.onclick.do(self.on_update_job)
        self.add_params_bt = gui.Button('Add params', width=100, height=30, margin='10px')
        self.add_params_bt.onclick.do(self.on_add_params)
        self.error_log_bt = gui.Button('Error log', width=100, height=30, margin='10px')
        self.error_log_bt.onclick.do(self.on_error_log)
        self.button_list.append(
            [self.build_bt, self.update_bt, self.add_params_bt, self.error_log_bt])
        self.center_container.append(self.button_list)

        self.log_label = gui.TextInput(single_line=False, height='500px', margin='10px auto',
                                       attributes={'readonly': 'readonly'})
        self.log_container = gui.Container(width='900', margin='4px auto',
                                           style='position: absolute; background-color: lightgray')
        self.log_container.append(self.log_label)
        self.main_container.append([self.center_container, self.log_container])
        # main end
        self.selected_view = ''

        # self.on_login(emitter=None)
        return self.login_container
        # return self.main_container

    def on_search_jobs(self, emitter, value):
        search_job_list = value.split(',')
        if len(search_job_list) == 0 or len(self.job_list) == 0:
            return
        self.selected_jobs = list(set(self.job_list).intersection(set(search_job_list)))
        self.selected_job_list.empty()
        self.selected_job_list.append(self.selected_jobs, "selectJobs")
        self.check_selected_job()


    def get_password_value(self, emitter, value):
        self.password_value = value
        show_value = ''
        for i in range(len(str(value))):
            show_value += '*'
        self.password_value_text.set_text(show_value)


    def on_login(self, emitter):
        if len(self.api_url_value.get_text()) == 0 or len(self.username_value.get_text()) == 0 or len(self.password_value_text.get_text()) == 0:
            self.lblsession_status.set_text('login failed!')
            return
        else:
            self.lblsession_status.set_text('login...')
        jenkins_server = JenkinsServer(self.api_url_value.get_text(), self.username_value.get_text(), self.password_value).server
        # jenkins_server = JenkinsServer('https://jenkins.lvlifeng.com/', 'jenkins', '2bbbbb').server
        try:
            jenkins_server.get_whoami()
        except Exception as result:
            if len(str(result)) != 0:
                self.lblsession_status.set_text('login failed!')
                return
        full_name = jenkins_server.get_whoami()['fullName']
        print('Hello %s from Jenkins %s' % (full_name, jenkins_server.get_version()))
        self.login_manager.renew_session()
        self.login_api.set_text(self.api_url_value.get_text())
        self.login_user.set_text(full_name)

        views = jenkins_server.get_views()
        view_list_str = []
        for i in range(len(views)):
            view_list_str.append(gui.DropDownItem(views[i]['name']))
        self.view_list_dd.empty()
        self.view_list_dd.append(view_list_str, 'view_list_str')
        self.init_job_list()
        self.set_root_widget(self.main_container)

    def init_job_list(self):
        self.refresh_job_list(self.view_list_dd.get_value())

    def on_renew(self, emitter):
        if not self.login_manager.expired:
            self.login_manager.renew_session()
            self.lblsession_status.set_text('RENEW')
        else:
            self.lblsession_status.set_text('UNABLE TO RENEW')

    def on_logout(self, emitter):
        global jenkins_server
        jenkins_server = None
        self.set_root_widget(self.login_container)
        self.lblsession_status.set_text('')

    def list_view_on_selected(self, widget, selected_item_key):
        self.refresh_job_list(selected_item_key)

    def refresh_job_list(self, view):
        jobs = JenkinsServer.server.get_jobs(view_name=view)
        self.job_list = []
        for job in jobs:
            self.job_list.append(job['name'])
        self.job_list_view.empty()
        self.job_list_view.append(self.job_list)
        self.check_selected_job()

    def on_build(self, emitter):
        if self.build_bt.get_text() == 'Build':
            self.show_build_dialog()
        else:
            self.on_stop_rebuild()

    def show_build_dialog(self):
        self.build_dialog = gui.GenericDialog('Build',
                                              width=500)
        self.build_params_input = gui.TextInput(width=300, height=20)
        self.build_dialog.add_field_with_label('build params input',
                                               'Build with params. e.g. docker_image_tag=v1,param_demo=xxx',
                                               self.build_params_input)

        self.rebuild_container = gui.HBox(width='100%')
        self.rebuild_checkbox = gui.CheckBoxLabel('Rebuild time interval if this build failed', style={'width': '60%'})
        self.rebuild_checkbox.onchange.do(self.on_rebuild)
        self.spin_column_count = gui.SpinBox(0, 0, 20, style={'width': '40%'})
        self.rebuild_suffix_lable = gui.Label("min")
        self.rebuild_container.append([self.rebuild_checkbox, self.spin_column_count, self.rebuild_suffix_lable])
        self.build_dialog.add_field('re build', self.rebuild_container)

        self.build_last_failed = False
        self.build_last_failed_checkbox = gui.CheckBoxLabel('build last failed')
        self.build_last_failed_checkbox.onchange.do(self.on_build_last_failed)
        self.build_dialog.add_field('last failed', self.build_last_failed_checkbox)

        self.build_dialog.confirm_dialog.do(self.do_build)
        self.build_dialog.show(self)

    def on_rebuild(self, widget, checked):
        self.rebuild = checked

    def on_build_last_failed(self, widget, checked):
        self.build_last_failed = checked

    def do_build(self, widget):
        if self.rebuild:
            self.build_bt.set_text("Stop Build")
        threading.Thread(target=self.exec_build()).start()

    def on_stop_rebuild(self):
        self.build_bt.set_text("Build")
        self.rebuild = False
        self.log_label.set_text(format_log('Build Stop!'))

    def exec_build(self):
        build_params = self.build_params_input.get_text().strip()
        build_last_failed = self.build_last_failed
        param_d = {}
        if len(build_params) != 0:
            param_list = build_params.split(',')
            for param in param_list:
                if len(param) != 0 and param != 'param_demo=xxx':
                    param_d[param.split('=')[0].strip()] = param.split('=')[1].strip()
        log_str = ''
        for job in self.selected_jobs:
            try:
                job_info = JenkinsServer.server.get_job_info(job)
                if build_last_failed:
                    build_failed = job_info['lastFailedBuild'] is not None and job_info['lastBuild']['number'] is \
                                   job_info['lastFailedBuild']['number']
                    if not build_failed:
                        continue
                if job_info['queueItem'] is not None or job_info['lastCompletedBuild']['number'] != job_info['lastBuild']['number']:
                    continue
                if len(param_d) != 0:
                    JenkinsServer.server.build_job(job, param_d)
                else:
                    JenkinsServer.server.build_job(job)
                log_str += format_log(f'Add [{job}] into build queue!')
            except Exception:
                log_str += format_log(f'Job [{job}] build error! check job params or others')
                if not self.rebuild:
                    self.build_bt.set_text("Build")
            self.log_label.set_text(log_str)
        if self.rebuild:
            threading.Timer(int(self.spin_column_count.get_value()) * 60, self.exec_build).start()

    def select_job(self, emitter, selected_item_key):

        job_str = self.job_list_view.children[selected_item_key].get_text()
        if job_str not in self.selected_jobs:
            self.selected_job_list.append(job_str)
            self.selected_jobs.append(job_str)
        self.check_selected_job()

    def un_select_job(self, emitter, selected_item_key):

        job_str = self.selected_job_list.children[selected_item_key].get_text()
        if job_str in self.selected_jobs:
            self.selected_jobs.remove(job_str)
            self.selected_job_list.empty()
            self.selected_job_list.append(self.selected_jobs)
        self.check_selected_job()

    def check_selected_job(self):
        if len(self.selected_jobs) == 0:
            self.build_bt.set_enabled(False)
            self.update_bt.set_enabled(False)
            self.add_params_bt.set_enabled(False)
            self.error_log_bt.set_enabled(False)
        else:
            self.build_bt.set_enabled(True)
            self.update_bt.set_enabled(True)
            self.add_params_bt.set_enabled(True)
            self.error_log_bt.set_enabled(True)

    def on_error_log(self, emitter):
        threading.Thread(target=self.do_error_log).start()

    def do_error_log(self):
        self.error_log_bt.set_enabled(False)
        log_str = format_log('Query error log start!')
        self.log_label.set_text(log_str)
        for job in self.selected_jobs:
            job_info = JenkinsServer.server.get_job_info(job)
            build_failed = job_info['lastFailedBuild'] is not None and job_info['lastBuild']['number'] is \
                           job_info['lastFailedBuild']['number']
            if build_failed:
                log_str += format_log(f'Job  [{job}] build failed!')
                build_info = JenkinsServer.server.get_build_console_output(job, job_info['lastBuild']['number'])
                err_msgs = build_info.splitlines(False)
                for err_msg in err_msgs:
                    if 'error' in err_msg.lower() or 'failure' in err_msg.lower():
                        log_str += format_log(err_msg)
                log_str += '\n'
        log_str += format_log('Query error log end!\n')
        self.log_label.set_text(log_str)
        self.error_log_bt.set_enabled(True)

    def on_update_job(self, widget):
        self.add_params_dialog = gui.GenericDialog('Update Job', width=500)
        self.add_params_dialog.confirm_dialog.do(self.do_update)
        self.git_branch_input = gui.TextInput(width=300, height=20)
        # self.git_branch_input.set_value('prod')
        self.add_params_dialog.add_field_with_label('u_git_branch', 'new git branch', self.git_branch_input)

        self.string_param_input = gui.TextInput(width=300, height=20)
        # self.git_branch_input.set_value('prod')
        self.add_params_dialog.add_field_with_label('u_string_params', 'string params(a=1,b=2)',
                                                    self.string_param_input)

        self.add_params_dialog.show(self)

    def do_update(self, widget):
        threading.Thread(target=self.do_update_in_thread).start()

    def do_update_in_thread(self):
        self.update_bt.set_enabled(False)
        new_branch = self.git_branch_input.get_text().strip()
        new_string_params = self.string_param_input.get_text()
        if len(new_branch) == 0 and len(new_string_params) == 0:
            self.log_label.set_text(format_log('Update failed. update params is null'))
            return
        log_str = ''
        for job in self.selected_jobs:
            try:
                config = JenkinsServer.server.get_job_config(name=job)
                dom = xml.dom.minidom.parseString(config)
                update = False
                if len(new_branch) != 0:
                    branches = dom.getElementsByTagName("hudson.plugins.git.BranchSpec")
                    for branch in branches:
                        name = branch.getElementsByTagName('name')[0]
                        name.childNodes[0].data = new_branch
                        update = True
                if len(new_string_params) != 0:
                    param_d = {}
                    param_list = new_string_params.split(',')
                    for param in param_list:
                        if len(param) != 0:
                            param_d[param.split('=')[0].strip()] = param.split('=')[1].strip()
                    parameters = dom.getElementsByTagName("hudson.model.StringParameterDefinition")
                    for parameter in parameters:
                        param_name = parameter.getElementsByTagName('name')[0].childNodes[0].data
                        if param_name in param_d.keys():
                            param_default_value = parameter.getElementsByTagName('defaultValue')
                            if len(param_default_value) != 0:
                                parameter.getElementsByTagName('defaultValue')[0].childNodes[0].data = param_d[
                                    param_name]
                            else:
                                default_value_str = f'<defaultValue>{param_d[param_name]}</defaultValue>'
                                default_value_dom = xml.dom.minidom.parseString(default_value_str)
                                parameter.appendChild(default_value_dom.getElementsByTagName('defaultValue')[0])
                            update = True
                if update:
                    xml_stdin = XmlStdin()
                    sys.stdin = xml_stdin
                    dom.writexml(sys.stdin, addindent='\t', newl='\n', encoding='utf-8')
                    JenkinsServer.server.upsert_job(name=job, config_xml=xml_stdin.to_string())
                log_str += format_log(f'Job {job} update successful!')
            except Exception as result:
                log_str += format_log(f'Job {job} update failed! error msg: {result}')
            self.log_label.set_text(log_str)
        self.update_bt.set_enabled(True)

    def on_add_params(self, widget):
        self.add_params_dialog = gui.GenericDialog('Add params', width=500)
        self.add_params_dialog.confirm_dialog.do(self.do_add_params)
        self.add_string_param_input = gui.TextInput(width=300, height=50)
        self.add_string_param_input.set_value('name=docker_image_tag,description=镜像tag,defaultValue=v1')
        self.add_params_dialog.add_field_with_label('u_add_string_params', 'add_string_params',
                                                    self.add_string_param_input)

        self.add_params_dialog.show(self)

    def do_add_params(self, widget):
        threading.Thread(target=self.do_add_params_in_thread).start()

    def do_add_params_in_thread(self):
        self.add_params_bt.set_enabled(False)
        string_param = self.add_string_param_input.get_text()
        if len(string_param) == 0:
            self.log_label.set_text(format_log('Add params failed. string params is null'))
            return
        param_d = {}
        param_list = string_param.split(',')
        for param in param_list:
            if len(param) != 0:
                param_d[param.split('=')[0].strip()] = param.split('=')[1].strip()
        if len(param_d) == 0:
            self.log_label.set_text(format_log('Add params failed. string params is null'))
            return
        string_param_str = \
            '<hudson.model.ParametersDefinitionProperty> \n' \
            '     <parameterDefinitions> \n' \
            '         <hudson.model.StringParameterDefinition> \n' \
            '             <name>' + param_d['name'] + '</name> \n' \
                                                      '             <description>' + param_d[
                'description'] + '</description> \n' \
                                 '             <defaultValue>' + param_d['defaultValue'] + '</defaultValue> \n' \
                                                                                           '             <trim>false</trim>  \n' \
                                                                                           '         </hudson.model.StringParameterDefinition> \n' \
                                                                                           '     </parameterDefinitions> \n' \
                                                                                           '</hudson.model.ParametersDefinitionProperty>'
        string_param_dom = xml.dom.minidom.parseString(string_param_str)
        log_str = ''
        for job in self.selected_jobs:
            try:
                config = JenkinsServer.server.get_job_config(name=job['name'])
                dom = xml.dom.minidom.parseString(config)
                properties = dom.getElementsByTagName('properties')
                properties[0].appendChild(
                    string_param_dom.getElementsByTagName('hudson.model.ParametersDefinitionProperty')[0])
                xml_stdin = XmlStdin()
                sys.stdin = xml_stdin
                dom.writexml(sys.stdin, addindent='\t', newl='\n', encoding='utf-8')
                JenkinsServer.server.upsert_job(name=job, config_xml=xml_stdin.to_string())
                log_str += format_log(f'Job {job} add params successful!')
            except Exception as result:
                log_str += format_log(f'Job {job} add params failed! error msg: {result}')
            self.log_label.set_text(log_str)
        self.add_params_bt.set_enabled(True)

    def on_select_all(self, widget):
        self.selected_jobs = self.job_list
        # for job_str in self.job_list:
        #     self.selected_jobs.append(job_str)
        self.selected_job_list.empty()
        self.selected_job_list.append(self.selected_jobs, "selectJobs")
        self.check_selected_job()

    def on_clear_all(self, widget):
        self.selected_jobs = []
        self.selected_job_list.empty()
        self.selected_job_list.append(self.selected_jobs, "selectJobs")
        self.rebuild = False
        self.check_selected_job()

    def set_favicon(self):
        # custom additional html head tags
        my_html_head = """
                    """

        # custom css
        my_css_head = """
                    <link rel="stylesheet" href="" type="text/css">
                    """

        # custom js
        my_js_head = """
                    <script></script>
                    """
        # appending elements to page header
        self.page.children['head'].add_child('myhtml', my_html_head)
        self.page.children['head'].add_child('mycss', my_css_head)
        self.page.children['head'].add_child('myjs', my_js_head)

        # setting up the application icon
        self.page.children['head'].set_icon_file("/hi:favicon.svg")


def format_log(log):
    time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f'{time}   {log}\n'


if __name__ == "__main__":
    # starts the webserver
    start(JenkinsHelper, address='0.0.0.0', port=11111, multiple_instance=True, debug=False)
