
#! /usr/bin/python3

from ipaddress import IPv4Address, ip_address
from socket import gethostbyname
from urllib.parse import urlparse
from dns.resolver import Resolver
from sys import argv
import concurrent.futures
import sys , time, re  ,json , ipaddress , ctypes
import sqlite3,logging,io,socket,struct 
logging.basicConfig(format='[%(message)s: %(levelname)s] --> %(asctime)s:[%(levelname)s][%(threadName)s] %(filename)s:%(lineno)d  ',
                    level=logging.ERROR)

class IpRegInfo(object):
    __INDEX_BLOCK_LENGTH = 12
    __TOTAL_HEADER_LENGTH = 8192

    __f = None
    __headerSip = []
    __headerPtr = []
    __headerLen = 0
    __indexSPtr = 0
    __indexLPtr = 0
    __indexCount = 0
    __dbBinStr = ''

    def __init__(self, db_file):
        self.init_database(db_file)

    def memory_search(self, ip):
        """
        " memory search method
        " param: ip
        """
        if not ip.isdigit():
            ip = self.ip2long(ip)

        if self.__dbBinStr == '':
            self.__dbBinStr = self.__f.read()  # read all the contents in file
            self.__indexSPtr = self.get_long(self.__dbBinStr, 0)
            self.__indexLPtr = self.get_long(self.__dbBinStr, 4)
            self.__indexCount = int((self.__indexLPtr - self.__indexSPtr) /
                                    self.__INDEX_BLOCK_LENGTH) + 1

        l, h, data_ptr = (0, self.__indexCount, 0)
        while l <= h:
            m = int((l + h) >> 1)
            p = self.__indexSPtr + m * self.__INDEX_BLOCK_LENGTH
            sip = self.get_long(self.__dbBinStr, p)

            if ip < sip:
                h = m - 1
            else:
                eip = self.get_long(self.__dbBinStr, p + 4)
                if ip > eip:
                    l = m + 1
                else:
                    data_ptr = self.get_long(self.__dbBinStr, p + 8)
                    break

        if data_ptr == 0:
            raise Exception("Data pointer not found")

        return self.return_data(data_ptr)

    def init_database(self, db_file):
        """
        " initialize the database for search
        " param: dbFile
        """
        try:
            self.__f = io.open(db_file, "rb")
        except IOError as e:
            print("[Error]: %s" % e)
            sys.exit()

    def return_data(self, data_ptr):
        """
        " get ip data from db file by data start ptr
        " param: data ptr
        """
        data_len = (data_ptr >> 24) & 0xFF
        data_ptr = data_ptr & 0x00FFFFFF

        self.__f.seek(data_ptr)
        data = self.__f.read(data_len)

        info = {"city_id": self.get_long(data, 0),
                "region": data[4:].decode('utf-8')}
        return info

    @staticmethod
    def ip2long(ip):
        _ip = socket.inet_aton(ip)
        return struct.unpack("!L", _ip)[0]

    @staticmethod
    def is_ip(ip):
        p = ip.split(".")
        if len(p) != 4:
            return False
        for pp in p:
            if not pp.isdigit():
                return False
            if len(pp) > 3:
                return False
            if int(pp) > 255:
                return False
        return True

    @staticmethod
    def get_long(b, offset):
        if len(b[offset:offset + 4]) == 4:
            return struct.unpack('I', b[offset:offset + 4])[0]
        return 0

    def close(self):
        if self.__f is not None:
            self.__f.close()
        self.__dbBinStr = None
        self.__headerPtr = None
        self.__headerSip = None

class IpRegData(IpRegInfo):
    def __init__(self):
        path = 'db/ip2region.db'
        IpRegInfo.__init__(self, path)

    def query(self, ip):
        result = self.memory_search(ip)
        addr_list = result.get('region').split('|')
        addr = ''.join(filter(lambda x: x != '0', addr_list[:-1]))
        isp = addr_list[-1]
        if isp == '0':
            isp = '未知'
        info = {'addr': addr, 'isp': isp}
        return info
    
class IpAsnInfo(object):
    def __init__(self , ip ):
        self._ip = ip   

    def ip_to_int(self , ip):
        if isinstance(ip, int):
            return ip
        try:
            ipv4 = IPv4Address(ip)
        except Exception as e:
            logging.info('[!] cannot find the fuxink ip dude~~~~~~~~~~~~~~~~~')
            return 0
        return int(ipv4)

    def create_connection(self , db_file):
        """ create a database connection to the SQLite database
            specified by the db_file
        :param db_file: database file
        :return: Connection object or None
        """
        conn = None
        try:
            conn = sqlite3.connect(db_file)
        except Error as e:
            # print(e)
            pass

        return conn

    def select_all_tasks(self , conn , ip):
        """
        Query all rows in the tasks table
        :param conn: the Connection object
        :return:
        """
        cur = conn.cursor()
        cur.execute(f'SELECT * FROM asn WHERE ip_from <= {ip} AND ip_to >= {ip}  LIMIT 1;')

        rows = cur.fetchall()

        for row in rows:
            pass
            # print(row)
        return row
    
    def query(self ):
        self._conn = self.create_connection('db/ip2location.db')
        _ = self.select_all_tasks(self._conn , self.ip_to_int(self._ip))
        return {'cidr':_[2] , 'asn':f'AS{_[3]}' , 'org':_[4] , 'ip':self._ip}

def _gethost(domain):
    try:
        domain = urlparse(domain).netloc if domain.startswith('http') else urlparse(domain).path
        resolver = dns_resolver()
        answers = resolver.resolve(domain, 'A')
        return [ i.address for i in answers if i.address is not None]
    except Exception as e:
        logging.info("[!] - gethost Error - {} - {}".format(domain , e.__class__))

def dns_resolver():
    resolver = Resolver()
    resolver.nameservers = [
    '223.5.5.5',  # AliDNS
    '119.29.29.29',  # DNSPod
    '114.114.114.114',  # 114DNS
    '8.8.8.8',  # Google DNS
    '1.1.1.1'  # CloudFlare DNS
    ]
    resolver.timeout = 5.0
    resolver.lifetime = 10.0
    return resolver

def get_cname(subdomain):
    resolver = dns_resolver()
    try:
        answers = resolver.resolve(subdomain, 'CNAME')
    except Exception as e:
        logging.info("[!] trace {}\t{}".format(subdomain , e))
        return None
    for answer in answers:
        return answer.to_text()

''' cdn '''
cdn_ip_cidr = json.loads(open('db/cdn_ip_cidr.json').read())
cdn_asn_list = json.loads(open('db/cdn_asn_list.json').read())
cdn_cname_keyword = json.loads(open('db/cdn_cname_keywords.json').read())
cdn_header_key = json.loads(open('db/cdn_header_keys.json').read())

def check_cname_keyword(cname):
    if not cname:
        return False
    names = cname.lower().split(',')
    for name in names:
        for keyword in cdn_cname_keyword.keys():
            if keyword in name:
                return True

def check_header_key(header):
    if isinstance(header, str):
        header = json.loads(header)
    if isinstance(header, dict):
        header = set(map(lambda x: x.lower(), header.keys()))
        for key in cdn_header_key:
            if key in header:
                return True
    else:
        return False

def check_cdn_cidr(ips):
    if isinstance(ips, str):
        ips = set(ips.split(','))
    else:
        return False
    for ip in ips:
        try:
            ip = ipaddress.ip_address(ip)
        except Exception as e:
            return False
        for cidr in cdn_ip_cidr:
            if ip in ipaddress.ip_network(cidr):
                return True

def check_cdn_asn(asn):
    if isinstance(asn, str):
        if asn in cdn_asn_list:
            return True
    return False


''' cdn end '''
def _query_ipinfo(domain):
    _ = _gethost(domain)
    for index,_ip in enumerate(_):
        if _ip is None:
            return None
        ip_reg = IpRegData()
        ip_info = ip_reg.query(_ip)

        ip_asn = IpAsnInfo(_ip)
        ip_info_ = ip_asn.query()
        ip_info.update(ip_info_)
        ip_info.update( { 'cname' : get_cname(domain) } )
        _[index] = ip_info
        del ip_info
    return _

def terminate_thread(thread):
    """Terminates a python thread from another thread.

    :param thread: a threading.Thread instance
    """
    if not thread.is_alive():
        return

    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident), exc)
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

def main(target):
    try:
        datas = _query_ipinfo(f'{target}')
        for data in datas:
            cname = data.get('cname')
            if check_cname_keyword(cname):
                data['cdn'] = 1
                pass
            # header = data.get('header')
            # if check_header_key(header):
            #     data['cdn'] = 1
            #     pass
            ip = data.get('ip')
            if check_cdn_cidr(ip):
                data['cdn'] = 1
            asn = data.get('asn')
            if check_cdn_asn(asn):
                data['cdn'] = 1
            data['cdn'] = 0
            addr = data['addr'] if data['addr'] else 'None'
            isp = data['isp'] if data['isp'] else 'None'
            cidr = data['cidr'] if data['cidr'] else 'None'
            asn = data['asn'] if data['asn'] else 'None'
            org = data['org'] if data['org'] else 'None'
            ip = data['ip'] if data['ip'] else 'None'
            cname = data['cname'] if data['cname'] else 'None'
            # cdn = "Y" if data['cdn'] == 1 else "N"
            cdn = data['cdn']
            sys.stdout.write("{}|{}|{}|{}|{}|{}|{}|{}|{}\n".format(addr , isp , cidr , asn , org , ip , cname , cdn , target))
            # if cdn == "N":
            #     sys.stdout.write("{}|{}\n".format(target , ip))
            
    except Exception as e:
        pass

if __name__ == '__main__':
    sys.stderr.write("format : \n")
    sys.stderr.write("addr | isp | cidr | asn | org | ip | cname | CDN | domain\n")
    time1 = time.time()
    if len(argv) == 2:
        with open(argv[1]) as f:
            _ = [ i.strip() for i in f.readlines()]
            _run_list = list(set([ i for i in _ ]))
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_run = (executor.submit(main, target) for target in _run_list)
                try:
                    for future in concurrent.futures.as_completed(future_to_run):
                        try:
                            data = future.result()
                        except Exception as e:
                            pass
                except KeyboardInterrupt:
                    sys.stderr.write("Caught KeyboardInterrupt, terminating workers")
                    executor.shutdown(wait= False)
                    for t in executor._threads:
                        terminate_thread(t)
                    exit(1)
    else:
        # for i in _run_list:
        #     main(i.strip())
        _run_list = list(set([ i.strip() for i in sys.stdin ]))
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_run = (executor.submit(main, target) for target in _run_list)
            try:
                for future in concurrent.futures.as_completed(future_to_run):
                    try:
                        data = future.result()
                    except Exception as e:
                        pass
            except KeyboardInterrupt:
                sys.stderr.write("Caught KeyboardInterrupt, terminating workers")
                executor.shutdown(wait= False)
                for t in executor._threads:
                    terminate_thread(t)
                exit(1)
    sys.stderr.write(f"{time.time() - time1}")
