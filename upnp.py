'''
Upnp打洞程序,向你的路由器打洞,把内网映射到外网,实现P2P.
计算机网络应用程序.使用Upnp协议,windows系统使用target方法,linux系统都可以使用.
'''
import urllib3
import re
import socket
from urllib import request
import select
import signal

class Upnp():
    def __init__(self, ipaddr):
        "ipaddr: 网关地址"
        self.ipaddr = ipaddr
        self.tport = 49170
        self.upnport = 1900
        self.msg = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n\r\n"
        self.s = None

    def target(self):
        data = []
        try:
            tar = self.ipaddr
            if self.ipaddr.find("*") != -1:
                star = self.ipaddr.split(".*")
                i = 1
                while i < 255:
                    tar = star[0] + "." + str(i)
                    print("发送UPNP数据包给: " + tar)
                    self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.s.bind(("", self.tport))
                    self.s.sendto(self.msg, (tar, self.upnport))
                    i += 1
            else:
                print("发送UPNP数据包给: " + tar)
                self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.s.bind(("", self.tport))
                self.s.sendto(self.msg, (tar, self.upnport))
            print("等待数据")
            string, addr = self.s.recvfrom(1024)
            data.append([addr[0], string])
            print("已经获得数据")
            self.s.close()
            self.__proc(data)
        except KeyboardInterrupt:
            pass

    def lan(self):
        data = []
        try:
            print("在局域网内发送UPNP广播")
            socket.setdefaulttimeout(3)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", self.tport))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(self.msg, ("239.255.255.250", 1900))
            print("等待数据获取,如果获取失败请重新运行程序")
            while True:
                res = select.select([s], [], [])
                string, addr = res[0][0].recvfrom(1024)
                data.append([addr[0], string])
                print("已经获得数据")
        except KeyboardInterrupt as e:
            s.close()
            self.__proc(data)

    def __sploit(self, host):
        print("Upnp开始打洞工作啦!!!")
        rhost = re.findall("([^/]+)", host)
        print("我正在从目标主机得到东西...")
        try:
            res = request.urlopen(host).read().decode("utf-8")
            res = res.replace("\r", "")
            res = res.replace("\n", "")
            res = res.replace("\t", "")
            pres = res.split("<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>")
            p2res = pres[0].split("</controlURL>")
            p3res = p2res[0].split("<controlURL>")
            ctrl = p3res[1]
            rip = res.split("<presentationURL>")
            rip1 = rip[1].split("</presentationURL>")
            routerIP = rip1[0]
            print("路由器的内网IP: " + routerIP)
            print("端口成功打开:")
            print("内网端口:外网端口:地址:upnp设备名称")
            i = 1
            try:
                while True:
                    self.__printDevice(rhost,ctrl)
                    i = i + 1
            except Exception as e:
                pass
        except Exception as e:
            print("不能从目标主机获取内容 :"+e)
        IP = input("内网IP地址: [192.168.1.100] ")
        if IP == "":
            IP = "192.168.1.100"
        port = input("内网映射端口号: [8000] ")
        if port == "":
            port = "8000"
        extport = input("外网端口号: [8000] ")
        if extport == "":
            extport = "8000"
        try:
            self.__startUpnp(ctrl,rhost,extport,port,IP)
        except Exception as e:
            print(e)
            print("不好意思,没有成功运行~~")

    def __printDevice(self, rhost, ctrl):
        opmsg = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewPortMappingIndex>' + str(
            i) + '</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>'
        open_ports = request.Request("http://" + rhost[1] + "" + ctrl, bytes(opmsg, encoding='utf8'))
        open_ports.add_header("SOAPACTION",
                              '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"')
        open_ports.add_header('Content-type', 'application/xml')
        open_res = request.urlopen(open_ports).read().decode("utf-8")
        int1 = open_res.split('<NewInternalPort>')
        int2 = int1[1].split('</NewInternalPort>')
        intport = int2[0]
        ext1 = open_res.split('<NewExternalPort>')
        ext2 = ext1[1].split('</NewExternalPort>')
        extport = ext2[0]
        addr = open_res.split('<NewInternalClient>')
        addr1 = addr[1].split('</NewInternalClient>')
        address = addr1[0]
        des = open_res.split('<NewPortMappingDescription>')
        des1 = des[1].split('</NewPortMappingDescription>')
        desc = des1[0]
        print(intport + ":" + extport + ":" + address + ":" + desc)

    def __startUpnp(self,ctrl,rhost,extport,port,IP):
        msg = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>' + extport + '</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>' + port + '</NewInternalPort><NewInternalClient>' + IP + '</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>hax0r</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>'
        req = request.Request("http://" + rhost[1] + "" + ctrl, bytes(msg, encoding='utf8'))
        req.add_header('SOAPAction', '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"')
        req.add_header('Content-type', 'application/xml')
        req.add_header('Pragma', 'no-cache')
        req.add_header('Host', '192.168.1.1:1900')
        req.add_header('Connection', 'Close')
        request.urlopen(req)
        print("成功运行Upnp!!!")

    def __proc(self, data):
        if len(data) == 0:
            self.__done("")
        print("\r\n处理得到的数据...")
        pdata = list(dict((x[0], x) for x in data).values())
        rh = []
        for L in pdata:
            rh.append(L[0])
        hosts = []
        pd = []
        url = ""
        print("建立连接...")
        for spot, host in enumerate(rh):
            try:
                hdata = str(pdata[spot][1],encoding='utf8')
                url = "http://" + host + ":"
                port = re.findall("http:\/\/[0-9\.]+:(\d.+)", hdata)
                url += port[0]
                p = request.urlopen(url)
                rd = re.findall("schemas-upnp-org:device:([^:]+)", str(p.read(),encoding="utf8"))
                if rd[0] == "InternetGatewayDevice":
                    addr = re.findall("http://([^:]+)", url)
                    vuln = "Linux/2.6.17.WB_WPCM450.1.3 UPnP/1.0, Intel SDK for UPnP devices/1.3.1"
                    if hdata.find(vuln) != -1:
                        d = input(addr[
                                          0] + " might be open to the unique_service_name() exploit, open msf and give it a go. For more information goto this URL - http://www.osvdb.org/show/osvdb/89611 Press enter to continue.")
                    # yesnosploit = raw_input(addr[0]+" is a router, do you want to try to open ports? (Y)es/(N)o: ")
                    yesnosploit = input(
                        addr[0] + " 是一个路由器, 你想要尝试探索它吗?: (Y)es/(n)o ")
                    if yesnosploit.lower() == "y":
                        self.__sploit(url)
                    if yesnosploit == "":
                        self.__sploit(url)
                pd.append([url, rd[0]])
            except Exception as e:
                err = ""
                print(e)
                pd.append([url, "不能连接..."])
        self.__done(pd)

    def __done(self, data):
        if len(data) == 0:
            print("\r\n没有找到 UPNP 支持的设备 :(")
        for info in data:
            print("设备 UPNP 信息页面: " + str(info[0]))
            print("设备类型: " + str(info[1]) + "\r\n")
        print("不管成功没有,做完了!")
        exit(1)


if __name__ == '__main__':
    test = Upnp("192.168.1.1")
    test.lan()