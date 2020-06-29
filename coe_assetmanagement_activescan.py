import subprocess   #コマンド実行用
import coe_assetmanagement_common as COE_COMMON
import coe_assetmanagement_class as COE_CLASS
import netifaces
#MACベンダーコードを辞書型で読みこむ
#使い方：macvendors[tmp[0:8].upper()]
macvendors = COE_COMMON.ReadMACVendor()

from scapy.all import *
from netaddr import IPNetwork

#詳細なアクティブスキャンを実施
#引数
#activeAssetList:class CoeAssetのlist　arp-scan結果一覧
#csvAssetList   :class CoeAssetのlist　資産台帳の一覧
#戻り値
#activeAssetList:class CoeAssetのlist　詳細結果の一覧
def CoeActiveScan_Scapy(activeAssetList="",csvAssetList=""):
    for activeAsset in activeAssetList:
        packet = IP(dst=str(activeAsset.ip_src))/UDP(sport="netbios_ns")/NBNSQueryRequest(QUESTION_TYPE=33,QUESTION_NAME=b"*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",FLAGS=0)
        conf.use_pcap=True
        print(activeAsset.ip_src+" running.")
        getpacket = sr1(packet,timeout=1,verbose =0)
        if getpacket is not None:
            if Raw in getpacket:
                try:
                    activeAsset.hostname = getpacket[Raw].load[7:22].decode("utf-8")
                    if "WORKGROUP" in activeAsset.hostname:
                        activeAsset.hostname = getpacket[Raw].load[25:40].decode("utf-8")
                except UnicodeDecodeError:
                    activeAsset.hostname = "unknown"
                for csvAsset in csvAssetList:
                    if(activeAsset.ip_src == csvAsset.ip_src):
                        if(COE_COMMON.HasElementValue(csvAsset.hostname) == False):
                            csvAsset.hostname = activeAsset.hostname
                        elif(activeAsset.hostname != csvAsset.hostname):
                            print("MAdAddress:",csvAsset.mac_src," のホスト名を更新しました。",\
                                "以前：",csvAsset.hostname,\
                                "今回：",activeAsset.hostname)
                            csvAsset.hostname = activeAsset.hostname
        
        icmp = IP(dst=str(activeAsset.ip_src))/ICMP()
        getpacket = sr1(icmp,timeout=1,verbose =0)
        if getpacket is not None:
            activeAsset.osname = COE_COMMON.CheckOSName(ttl=str(getpacket[IP].ttl),windowsize="")
            for csvAsset in csvAssetList:
                if(activeAsset.ip_src == csvAsset.ip_src):
                    if(COE_COMMON.HasElementValue(csvAsset.osname) == False):
                        csvAsset.osname = activeAsset.osname
                    elif(activeAsset.osname != csvAsset.osname):
                        print("MAdAddress:",csvAsset.mac_src," のOS情報を更新しました。",\
                            "以前：",csvAsset.osname,\
                            "今回：",activeAsset.osname)
                        csvAsset.osname = activeAsset.osname

    return activeAssetList

#ARPでリスト作成
#詳細なアクティブスキャンを実施
#引数
#cmd            :string 実行コマンドでarp-scan対象のIPが入っている
#戻り値
#arpAssetList   :class CoeAssetのlist
def CoeArp_Scapy(cmd=""):
    #cmd="ass vmnet2 192.168.0.0/24 -o test.csv"
    #cmd="assl vmnet2 192.168.0.0/24 intput.csv -o test.csv"
    inputcommand = cmd.split()
    ip_range = IPNetwork(inputcommand[2])
    arplists = []
    
    arpPacket = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP()
    conf.use_pcap=True
    arpPacket.hwsrc = netifaces.ifaddresses(inputcommand[1])[netifaces.AF_LINK][0]["addr"]
    arpPacket.psrc = netifaces.ifaddresses(inputcommand[1])[netifaces.AF_INET][0]["addr"]
    for ip_addr in ip_range[1:]:
        arpPacket.pdst = str(ip_addr)
        getpacket = srp1(arpPacket,verbose=0,timeout=0.2,iface=inputcommand[1])
        if getpacket is not None:
            print("\r "+arpPacket.pdst+" found.      ",end='')
            arplists.append(getpacket)
            print("")
        else:
            print("\r "+ arpPacket.pdst+" not found.",end='')

    print("")

    arpAssetList = []

    for arplist in arplists:

        ip= arplist[ARP].psrc
        mac=arplist[ARP].hwsrc

        try:
            vendercode = macvendors[mac[0:8].upper()]
        except Exception as e:
            vendercode = "unknown"
            print("vendercode unknown",e)

        arpAssetList.append(COE_CLASS.CoeAsset(\
            ip_src=ip,\
            mac_src=mac,\
            vendercode=vendercode))

    return arpAssetList






