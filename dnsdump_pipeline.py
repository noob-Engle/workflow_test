import os , sys
try:
    from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
except ModuleNotFoundError as e:
    os.system("python -m pip install dnsdumpster")
from sys import argv
# try:
#     import ipdb
# except ModuleNotFoundError as e:
#     os.system("python -m pip install dnsdumpster")

def dnsdumpster(target):
    result = DNSDumpsterAPI().search(target)
    if result:
        return result['dns_records']['host']
    else:
        return None
domain = []
ip = []
if len(argv) == 2:
    _ = dnsdumpster(target = argv[1])
    if _:
        # sys.stderr.write("doamin\t\t- ip \t\t- header")
        for i in _:
            domain.append(i['domain'])
            ip.append(i['ip'])

            # normal
            # sys.stdout.write(f"{i['domain']} - {i['ip']} - {i['header']}\n")

            # for pipeline
            sys.stdout.write(f"{i['domain']}\n")
    # ipdb.set_trace()
    # print()
    """ usage : print(domain / ip) """
# txt = "usage : python3 dnsdumper test.com"
# print(txt)
