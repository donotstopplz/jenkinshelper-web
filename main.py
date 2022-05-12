# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
import jenkins_helper

# Config
ipaddress = '0.0.0.0'
port = 11111
username = None
password = None

# Press the green button in the gutter to run the script.
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

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
