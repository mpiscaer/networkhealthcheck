#!/usr/bin/python3

from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
import ipaddress
import yaml
import subprocess


class localServerAddresses:

    __allLocalInterfaces__ = []
    __allLocalIpAddressess__ = []
    __allLocalNetworks__ = []
    __networkHash__ = []

    def __init__(self, excludeIf = [], excludeNet = [] ):
        if not isinstance(excludeIf, list):
            raise ValueError('excludeIf is not a list')
        if not isinstance(excludeNet, list):
            raise ValueError('excludeNet is not a list')

        # load local IP addresses
        for interface in netifaces.interfaces():
            interfaceAddressess = netifaces.ifaddresses(interface)
            if AF_INET in interfaceAddressess:
                ipaddressNr = ipaddress.ip_address(interfaceAddressess[AF_INET][0]['addr'])
                netmaskNr = netifaces.ifaddresses(interface)[AF_INET][0]['netmask']
                if (ipaddressNr.is_global or ipaddressNr.is_private) and not ipaddressNr.is_loopback:
                    networkAddress = ipaddress.IPv4Network(str(ipaddressNr) + "/" + netmaskNr, strict=False)
                    if (interface not in excludeIf) and (networkAddress not in excludeNet):
                        self.__allLocalInterfaces__.append(interface)
                        self.__allLocalIpAddressess__.append(ipaddressNr)
                        self.__allLocalNetworks__.append(networkAddress)

                        self.__networkHash__.append({'interface': interface, 'ip': [ipaddressNr], 'network': networkAddress, 'mtu': self.getMTUOfInterface(interface)})

    def getLocalIpAddresses(self):
        test = []
        for k in self.__allLocalIpAddressess__:
            test.append(str(k))
        return test

    def getMTUOfInterface(self, int):
        #print("BBBBB")
        #print("int:  " + int)
        process = subprocess.Popen(["/bin/bash", '-c', "/bin/echo -n $(/bin/ip addr show " + int + " |grep 'mtu'|sed 's/.*mtu//'|awk '{print $1}')"], stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        errcode = process.returncode
        #print("EEEE")
        return str(stdout.decode("utf-8"))
        #print("stdout: " + str(stdout))

    def giveBackDirectConnected(self, hosts, mtu = 1500):
        tobeReturned = []
        for host in hosts:
            for network in self.__networkHash__:
                if ipaddress.ip_address(host) in network['network'] and int(network['mtu']) >= mtu:
                    tobeReturned.append(ipaddress.ip_address(host))
        return tobeReturned

class config:
    __config__ = {}

    def __init__(self, fileName = '/tmp/config.yml'):
        with open(fileName, 'r') as stream:
            try:
                self.__config__ = yaml.load(stream)
            except yaml.YAMLError as exc:
                print(exc)

        if 'excludeNet' in self.__config__:
            if not isinstance(self.__config__['excludeNet'], list):
                raise ValueError('excludeNet is not a list')
            self.__config__['excludeNet'] = self.__convertNetwork__(self.__config__['excludeNet'])
        else:
            self.__config__['excludeNet'] = []


        if 'excludeIf' in self.__config__:
            if not isinstance(self.__config__['excludeIf'], list):
                raise ValueError('excludeIf is not a list')
        else:
            self.__config__['excludeIf'] = []

    def __convertNetwork__ (self, networks):
        r = []
        for v in networks:
            r.append(ipaddress.IPv4Network(v))
        return r

    def ExclN(self):
        return self.__config__['excludeNet']

    def ExclIf(self):
        return self.__config__['excludeIf']

    def getAllHosts(self):
        return self.__config__['hosts']

def testConnection(needToTest):
    for host in needToTest:
        process = subprocess.Popen(["/usr/bin/fping", "-t 1000", str(host)], stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        errcode = process.returncode

        if stdout:
            print(stdout.strip())
        if stderr:
            print(stderr.strip())
        if not errcode == 0:
            raise ValueError("error with host: %s" % host)

def testMTU(needToTest, mtu):
    for host in needToTest:
        process = subprocess.Popen(["/bin/ping", "-M", "do", "-s", str(mtu - 28), "-c", "1", str(host)], stdout=subprocess.PIPE)

        stdout, stderr = process.communicate()
        errcode = process.returncode

        if stdout:
            print(stdout.strip())
        if stderr:
            print(stderr.strip())
        if not errcode == 0:
            raise ValueError("error with host: %s" % host)

print('running test...')

config = config()
thisLocalServer = localServerAddresses(excludeNet = config.ExclN(), excludeIf = config.ExclIf())
testConnection(thisLocalServer.giveBackDirectConnected(config.getAllHosts()))
testMTU(thisLocalServer.giveBackDirectConnected(config.getAllHosts(), mtu = 1500), 1500)
testMTU(thisLocalServer.giveBackDirectConnected(config.getAllHosts(), mtu = 9000), 9000)

print('done')
