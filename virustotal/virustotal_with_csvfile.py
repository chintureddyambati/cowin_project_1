import requests
from netaddr import IPAddress
from csv import writer, reader

class ip_validation():

    def __init__(self, ip=None):
        if ip is not None:
            self.ip = ip


    def validate_ip(self, ip):
        try:
            ipinfo = IPAddress(ip)
            if ipinfo.version in [4, 6]:
                if ipinfo.is_private():
                    return False
                else:
                    return True
            else:
                return False
        except Exception:
            return False

class virustotal(ip_validation):
    def ip_check(self):
        with open('C:/Users/chint/Desktop/realtime_iplist.csv', 'r') as rd:
            csvreader = reader(rd)
            list1 = []
            for row in csvreader:
                print(row[0])
                self.ip = row[0]
                if self.validate_ip(self.ip):
                    url = f'https://www.virustotal.com/api/v3/ip_addresses/{self.ip}'
                    params = {'x_apikey': '72b416821be764912680aed6348ffc2116f733c63d7eceaf3ccaa60383c10499'}

                    response = requests.get(url, headers=params)
                    if response.status_code == 200:
                        output = response.json()
                        value = (output['data']['attributes']['last_analysis_results']['DNS8'])
                        category = (f'{value["category"]}')
                        result = (f'{value["result"]}')
                        method = (f'{value["method"]}')
                        engine_name = (f'{value["engine_name"]}')
                        data = [f'{category}' ,f'{result}' ,f'{method}' ,f'{engine_name}']

                    else:
                        print(f'error = {response.status_code}| reason = {response.reason}')
                else:
                    print('no data found ,provide valid_ip')
                print(data)
                list1.append(data)
        header = ['category', 'result', 'method', 'engine_name']
        with open("writer_file_virustotal.csv", 'w') as file:
            csvwriter = writer(file, lineterminator='\n')
            csvwriter.writerow(header)
            csvwriter.writerows(list1)


var = virustotal()
var.ip_check()
