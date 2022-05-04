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
import jenkins
import remi.gui as gui
from remi import start, App
import random
import threading

jenkins_server = None


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


class JenkinsHelper(App):
    def __init__(self, *args):
        super(JenkinsHelper, self).__init__(*args)

    def main(self, name='hello world'):
        self.login_manager = LoginManager(CookieInterface(self), 5)
        self.login_manager.on_session_expired.do(self.on_logout)

        self.wid = gui.VBox(width=600, margin='100px auto')
        # Text Input
        api_url = gui.Label('Jenkins API URL')
        self.api_url_value = gui.TextInput()
        self.api_url_value.add_class("form-control input-lg")
        api_url_box = gui.HBox(children=[api_url, self.api_url_value],
                               style={'width': '500px', 'margin': '4px auto', 'background-color': 'lightgray'})
        username = gui.Label('Jenkins username')
        self.username_value = gui.TextInput()
        self.username_value.add_class("form-control input-lg")
        username_box = gui.HBox(children=[username, self.username_value],
                                style={'width': '500px', 'margin': '4px 10px', 'background-color': 'lightgray'})
        password = gui.Label('Jenkins password')
        self.password_value = gui.TextInput()
        self.password_value.add_class("form-control input-lg")
        password_box = gui.HBox(children=[password, self.password_value],
                                style={'width': '500px', 'margin': '4px auto', 'background-color': 'lightgray'})

        bt_login = gui.Button('LOGIN')
        bt_login.onclick.do(self.on_login)
        # bt_renew = gui.Button('RENEW BEFORE EXPIRATION')
        # bt_renew.onclick.do(self.on_renew)

        self.lblsession_status = gui.Label('NOT LOGGED IN')

        self.wid.append(api_url_box)
        self.wid.append(username_box)
        self.wid.append(password_box)
        self.wid.append(bt_login)
        # wid.append(bt_renew)
        self.wid.append(self.lblsession_status)

        self.logined_api = gui.Label()
        self.logined_user = gui.Label()
        self.bt_logout = gui.Button('退出')
        self.bt_logout.onclick.do(self.on_logout)
        self.logged_info = gui.HBox(children=[self.logined_api, self.logined_user, self.bt_logout],
                                    style={'width': '500px', 'margin': '4px auto', 'background-color': 'lightgray'})
        # Drop Down
        self.dd = gui.DropDown(width='200px')
        self.dd.style.update({'font-size': 'large'})
        self.dd.add_class("form-control dropdown")
        self.dd.onchange.do(self.list_view_on_selected)
        # self.item1 = gui.DropDownItem("First Choice")
        # self.item2 = gui.DropDownItem("Second Item")
        # self.dd.append(self.item1, 'item1')
        # self.dd.append(self.item2, 'item2')

        self.datainfo = gui.VBox(children=[self.logged_info, self.dd],
                                 style={'width': '500px', 'margin': '4px auto', 'background-color': 'lightgray'})
        return self.wid

    def on_login(self, emitter):
        global jenkins_server
        jenkins_server = login_jenknis(self.api_url_value.get_text(), self.username_value.get_text(),
                                       self.password_value.get_text())
        try:
            jenkins_server.get_whoami()
        except Exception as result:
            if len(str(result)) != 0:
                self.lblsession_status.set_text('login failed!')
                print("login failed!")
                return
        print('Hello %s from Jenkins %s' % (jenkins_server.get_whoami()['fullName'], jenkins_server.get_version()))
        self.login_manager.renew_session()
        self.logined_api.set_text(self.api_url_value.get_text())
        self.logined_user.set_text(jenkins_server.get_whoami()['fullName'])

        views = jenkins_server.get_views()
        for i in range(len(views)):
            self.dd.append(gui.DropDownItem(views[i]['name']))
        jobs = jenkins_server.get_jobs(view_name=self.dd.get_value())
        liststr = []
        for job in jobs:
            liststr.append(job['name'])
        self.init_list_job = gui.ListView.new_from_list(liststr, width=300, height=120, margin='10px')
        # self.listJob.onselection.do(self.list_job_on_selected)
        self.datainfo.append(self.init_list_job, 'jobList')
        self.set_root_widget(self.datainfo)

    def on_renew(self, emitter):
        if not self.login_manager.expired:
            self.login_manager.renew_session()
            self.lblsession_status.set_text('RENEW')
        else:
            self.lblsession_status.set_text('UNABLE TO RENEW')

    def on_logout(self, emitter):
        global jenkins_server
        jenkins_server = None
        self.set_root_widget(self.wid)
        self.lblsession_status.set_text('LOGOUT')

    def list_view_on_selected(self, widget, selected_item_key):
        jobs = jenkins_server.get_jobs(view_name=selected_item_key)
        liststr = []
        for job in jobs:
            liststr.append(job['name'])
        self.list_job = gui.ListView.new_from_list(liststr, width=300, height=120, margin='10px')
        self.datainfo.append(self.list_job, 'jobList')


def login_jenknis(url, username, password):
    global jenkins_server
    jenkins_server = jenkins.Jenkins(url, username, password)
    return jenkins_server


if __name__ == "__main__":
    # starts the webserver
    start(JenkinsHelper, address='0.0.0.0', port=0, multiple_instance=False, debug=False)
