import requests
import re
import time

# 最开始写的脚本，以为题目还会有什么坑，所以没猜到flag就在1001次成功后就会显示出来
def original(url):
    # 这是一种又蠢又笨的方法，使用浏览器抓取的cookie
    cookie = {"PHPSESSID":'b76895dff12acb586dd62e272a8d8a5d'}

    res = requests.get(url, cookies=cookie)
    res.encoding = res.apparent_encoding  # 解决中文乱码。方便获取成功次数
    times = re.search(r'第\s*(\d+)\s*次成功啦',res.text)  # 获取成功次数
    times = int(times.group(1))
    exp = re.search(r'(\d{8})\s*([\+\-])\s*(\d{8})',res.text)  # 获取运算数

    # print(type(number), '\t', number)

    first = exp.group(1)  # 获取第一个运算数
    op = exp.group(2)  # 获取运算符
    second = exp.group(3)  # 获取第三个运算数

    # 答对1000次退出循环，实际测试时发现要运行1001次
    while times != 1001:
        if op == '+':
            ans = int(first) + int(second)
        else:
            ans = int(first) - int(second)
        data = {"answer": ans}
        res = requests.post(url, data=data, cookies=cookie)
        res.encoding = res.apparent_encoding

        times = re.search(r'第\s*(\d+)\s*次成功啦',res.text)  # 获取成功次数
        times = int(times.group(1))

        exp = re.search(r'(\d{8})\s*([\+\-])\s*(\d{8})',res.text)  # 获取运算数和操作符
        first = exp.group(1)
        op = exp.group(2)
        second = exp.group(3)
    print(res)

def improve(url):
    # 因为每次都需要保存上一次的状态，所以需要保存session
    session = requests.session()
    res = session.get(url)
    res.encoding = res.apparent_encoding
    flag = ''

    # 运算部分这样写也行
    # search 方法返回的是一个对象
    # 这种方式可以通过捕获组来获取对应的匹配对象
    exp = re.search(r'\d{8}\s*[\+\-]\s*\d{8}',res.text)
    ans = eval(exp.group(0))

    while True:
        time.sleep(0.1)
        data = {'answer' : ans}
        res = session.post(url=url, data=data)
        res.encoding = res.apparent_encoding # 解决响应中问乱码

        # findall方法返回的是一个列表
        # 直接通过索引获取对应值
        exp = re.findall(r'\d{8}\s*[\+\-]\s*\d{8}', res.text)
        ans = eval(exp[0])

        if 'flag{' in res.text:
            flag = re.findall(r'^flag\{[.]*\}', res.text)[0]
            print(flag)
            break
    return flag

if __name__ == '__main__':
    url = 'http://8564875a-d7c3-46fe-9128-8144e8531510.node5.buuoj.cn:81/'
    improve(url=url)