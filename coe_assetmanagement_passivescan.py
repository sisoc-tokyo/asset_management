import pyshark #元となるtsharkがVLANタグが付いていると正しく検知できないので注意（タグが付いている箇所はトランクポート間ぐらいなのでそうそうないはず
import coe_assetmanagement_class as COE_CLASS
import coe_assetmanagement_common as COE_COMMON

from concurrent.futures import ThreadPoolExecutor
import time
import threading
from scapy.all import *

#MACベンダーコードを辞書型で読みこむ
#使い方：macvendors[tmp[0:8].upper()]
macvendors = COE_COMMON.ReadMACVendor()

#ポート番号とプロトコルが紐付くCSVファイルを読み込む
#使い方：portNumberlist[dport+tcp or dport+udp]
portNumberlist = COE_COMMON.ReadPortNumberCSV()

#EtherTypeとプロトコルが紐付くCSVファイルを読み込む
#使い方：ethTypelist[number]
ethTypelist = COE_COMMON.ReadEtherTypeCSV()

#プロトコル番号とプロトコルが紐付くCSVファイルを読み込む
#使い方：protocolNumberlist[number]
protocolNumberlist = COE_COMMON.ReadProtocolNumberCSV()


#MACアドレスが登録済みの場合、更新処理を実施する
#登録済みの定義：
#   IP?MACどちらはキーにする？→MACかな
#       MACがすでにリスト登録済みならば
#           hostoname : 前データがunknown,error,noneであれば上書き。異なる場合、警告表示
#                       本来はerrorが発生しないようにすべきだが、現状保留
#           ip_src    : 前のデータと異なる場合、警告表示
#           OS        : ここでは判定せず
#           ip_dst    : 前データになければ追記
#           protocol  : 前データになければ追記
#           port_src  : 前データになければ追記
#           port_dst  : 前データになければ追記
#           communication:前データになければ追記
#引数
#pcapAsset      :class CoeAsset これまでのパッシブスキャン結果
#newAsset       :class CoeAsset 今回のパッシブスキャン結果
#戻り値
#updateAsset    :class CoeAsset　これまでのパッシブスキャン結果を更新した結果
def UpdatePcapList(pcapAsset="",newAsset=""):
    updateAsset = pcapAsset
    #ホスト名
    if(COE_COMMON.HasElementValue(newAsset.hostname) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.hostname) == False):
        updateAsset.hostname = newAsset.hostname
    elif(updateAsset.hostname != newAsset.hostname):
        updateAsset.hostname = newAsset.hostname
    
    #IPアドレス
    if(COE_COMMON.HasElementValue(newAsset.ip_src) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.ip_src) == False):
        updateAsset.ip_src = newAsset.ip_src
    
    #OS
    # 通信先のOSなので通信先のデータが必要

    #通信先(MAC)
    #  複数の場合"aa:aa:aa:aa:aa:aa,bb:bb:bb:bb:bb:bb"となる
    if(COE_COMMON.HasElementValue(newAsset.mac_dst) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.mac_dst) == False):
        updateAsset.mac_dst = newAsset.mac_dst
    else:
        mac_dst_list = updateAsset.mac_dst.split(",")
        if(newAsset.mac_dst in mac_dst_list):
            #すでに登録済み
            pass
        else:
            updateAsset.mac_dst = updateAsset.mac_dst + "," + newAsset.mac_dst
    
    #通信先(IP)
    #  複数の場合"192.168.0.1,10.0.1.111"となる
    if(COE_COMMON.HasElementValue(newAsset.ip_dst) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.ip_dst) == False):
        updateAsset.ip_dst = newAsset.ip_dst
    else:
        ip_dst_list = updateAsset.ip_dst.split(",")
        if(newAsset.ip_dst in ip_dst_list):
            #すでに登録済み
            pass
        else:
            updateAsset.ip_dst = updateAsset.ip_dst + "," + newAsset.ip_dst
        
    #通信プロトコル
    #  複数の場合"http(80),bacnet(47808)"となる
    if(COE_COMMON.HasElementValue(newAsset.protocol) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.protocol) == False):
        updateAsset.protocol = newAsset.protocol
    else:
        protocol_list = updateAsset.protocol.split(",")
        if(newAsset.protocol in protocol_list):
            #すでに登録済み
            pass
        else:
            updateAsset.protocol = updateAsset.protocol + "," + newAsset.protocol  
    
    #通信元ポート
    #  複数の場合"80,81"となる
    if(COE_COMMON.HasElementValue(newAsset.port_src) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.port_src) == False):
        updateAsset.port_src = newAsset.port_src 
    else:
        port_src_list = updateAsset.port_src.split(",")
        if(newAsset.port_src in port_src_list):
            #すでに登録済み
            pass
        else:
            updateAsset.port_src = updateAsset.port_src + "," + newAsset.port_src
    
    #通信先ポート
    #  複数の場合"80,81"となる
    if(COE_COMMON.HasElementValue(newAsset.port_dst) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.port_dst) == False):
        updateAsset.port_dst = newAsset.port_dst
    else:
        port_dst_list = updateAsset.port_dst.split(",")
        if(newAsset.port_dst in port_dst_list):
            #すでに登録済み
            pass
        else:
            updateAsset.port_dst = updateAsset.port_dst + "," + newAsset.port_dst

    #通信
    #  複数の場合"192.168.1.10:1000-192.168.1.100:http(80),192.168.1.10:1000-192.168.1.100:http(80)"となる
    if(COE_COMMON.HasElementValue(newAsset.communication) == False):
        pass
    elif(COE_COMMON.HasElementValue(updateAsset.communication) == False):
        updateAsset.communication = newAsset.communication
    else:
        port_communication = updateAsset.communication.split(",")
        if(newAsset.communication in port_communication):
            #すでに登録済み
            pass
        else:
            updateAsset.communication = updateAsset.communication + "," + newAsset.communication
    
    return updateAsset

################################################################################
#パケット解析 
#Scapyのみで解析　プロトコル判別の精度がpysharkより低い
#引数
#scapy_caps     :scapyのpcapファイル読み込み結果
#戻り値
#pcapAssetList  :class CoeAssetのlist pcapファイルのスキャン結果一覧
def FastestAnalysisPacket(scapy_caps=""):
    
    pcapAssetList = []
    count = 0
    
    for scapy_cap in scapy_caps:
        count+=1
        if(count%1000==0):
            print(count,"パケット解析")
        new_data = COE_CLASS.CoeAsset(
            hostname="unknown",\
            ip_src = "unknown",\
            mac_src = "unknown",\
            mac_dst = "unknown",\
            vendercode = "unknown",\
            osname = "unknown" ,\
            ip_dst = "unknown",\
            protocol= "unknown",\
            port_src= "unknown",\
            port_dst= "unknown",\
            communication= "unknown") 
                
        dst_osname = "unknown"
        tcp_flg = False
        udp_flg = False
        ip_flg = False
        eth_flg = False
        dot3_flg = False #802.3
        ttl = -1
        windowsize = -1

        try:
            #通信レイヤーの把握(TTL、Windowsize,通信先ポート把握などのため)
            try:
                if(scapy_cap.haslayer(TCP)):
                    tcp_flg = True
                    ip_flg = True
                elif(scapy_cap.haslayer(UDP)):
                    udp_flg = True
                    ip_flg = True
                elif(scapy_cap.haslayer(IP)):
                    ip_flg = True
                
                if(scapy_cap.haslayer(Ether)):
                    eth_flg = True
                elif(scapy_cap.haslayer(Dot3)):
                    dot3_flg = True

            except Exception as e:
                print("layer error")
            
            #通信元ポート
            try:
                if tcp_flg == True:
                    new_data.port_src = str(scapy_cap[TCP].sport)
                elif udp_flg == True:
                    new_data.port_src = str(scapy_cap[UDP].sport)
            except Exception as e:
                new_data.port_dst = "error"

            #通信先ポート
            try:
                if tcp_flg == True:
                    new_data.port_dst = str(scapy_cap[TCP].dport)
                elif udp_flg == True:
                    new_data.port_dst = str(scapy_cap[UDP].dport)
            except Exception as e:
                new_data.port_dst = "error"


            #通信プロトコル
            try:
                if(tcp_flg == True):
                    if(scapy_cap[TCP].payload.name == "Padding" or \
                        scapy_cap[TCP].payload.name == "NoPayload" or \
                        scapy_cap[TCP].payload.name == "Raw"):
                        if(new_data.port_dst+"tcp" in portNumberlist):
                            new_data.protocol=portNumberlist[new_data.port_dst+"tcp"]
                        else:
                            new_data.protocol="TCP"
                    else:
                        new_data.protocol = scapy_cap[TCP].payload.name
                    new_data.protocol = new_data.protocol + "(" + new_data.port_dst + ")"
                elif(udp_flg == True):
                    if(scapy_cap[UDP].payload.name == "Padding" or \
                        scapy_cap[UDP].payload.name == "NoPayload" or \
                        scapy_cap[UDP].payload.name == "Raw"):
                        if(new_data.port_dst+"udp" in portNumberlist):
                            new_data.protocol=portNumberlist[new_data.port_dst+"udp"]
                        else:
                            new_data.protocol = "UDP"
                    else:
                        if(scapy_cap[UDP].payload.payload.name == "Padding" or \
                                scapy_cap[UDP].payload.payload.name == "NoPayload" or \
                                scapy_cap[UDP].payload.payload.name == "Raw" or \
                                scapy_cap[UDP].payload.payload.name == ""):
                            new_data.protocol = scapy_cap[UDP].payload.name
                        else:
                            #DHCPの場合、UDP.payloadがBOOTPで、UDP.payload.payloadがDHCPになる
                            new_data.protocol = scapy_cap[UDP].payload.payload.name
                    new_data.protocol = new_data.protocol + "(" + new_data.port_dst + ")"
                elif(ip_flg == True):
                    if(scapy_cap[IP].payload.name == "Padding" or \
                        scapy_cap[IP].payload.name == "NoPayload" or \
                        scapy_cap[IP].payload.name == "Raw"):
                        if(str(scapy_cap[IP].proto) in protocolNumberlist):
                            new_data.protocol=protocolNumberlist[str(scapy_cap[IP].proto)]
                        else:
                            new_data.protocol="IP"
                    else:
                        new_data.protocol = scapy_cap[IP].payload.name
                else:
                    if(eth_flg == True):
                        if(scapy_cap[Ether].payload.name == "Padding" or \
                            scapy_cap[Ether].payload.name == "NoPayload" or \
                            scapy_cap[Ether].payload.name == "Raw"):
                            if(scapy_cap[Ether].type in ethTypelist):
                                new_data.protocol=ethTypelist[scapy_cap[Ether].type]
                            else:
                                new_data.protocol="Ethernet"
                        else:
                            new_data.protocol = scapy_cap[Ether].payload.name
                    elif(dot3_flg == True):
                        if(scapy_cap[Dot3].payload.name == "Padding" or \
                            scapy_cap[Dot3].payload.name == "NoPayload" or \
                            scapy_cap[Dot3].payload.name == "Raw"):
                            if(scapy_cap[Dot3].type in ethTypelist):
                                new_data.protocol=ethTypelist[scapy_cap[Dot3].type]
                            else:
                                new_data.protocol="Dot3"
                        else:
                            new_data.protocol = scapy_cap[Dot3].payload.name
                        
            except Exception as e:
                new_data.protocol = "error"
            
            #ホスト名
            try:
                if scapy_cap.haslayer(DHCP):
                    for dhcp_count in range(0,len(scapy_cap[DHCP].options)):
                        if(scapy_cap[DHCP].options[dhcp_count][0]=="hostname"): 
                            new_data.hostname = scapy_cap[DHCP].options[dhcp_count][1].decode('utf-8')
                            break
                elif scapy_cap.haslayer(NBNSQueryRequest):
                    try:
                        if(scapy_cap[NBNSQueryRequest].ARCOUNT==1 and \
                            scapy_cap[NBNSQueryRequest].name.decode('utf-8').strip()!="WORKGROUP"):
                            new_data.hostname = scapy_cap[NBNSQueryRequest].QUESTION_NAME.decode('utf-8').strip()
                    except:
                        hostname = "error"
            except Exception as e:
                hostname = "error"

            #IPアドレス
            try:
                if ip_flg == True:
                    new_data.ip_src = scapy_cap[IP].src
            except Exception as e:
                new_data.ip_src = "none"

            #MACアドレス
            try:
                if(eth_flg == True):
                    new_data.mac_dst = scapy_cap[Ether].dst
                    new_data.mac_src = scapy_cap[Ether].src
                elif(dot3_flg == True):
                    new_data.mac_dst = scapy_cap[Dot3].dst
                    new_data.mac_src = scapy_cap[Dot3].src
            except Exception as e:
                new_data.mac_src = "error"
                new_data.mac_dst = "error"

            #ベンダー情報
            try:
                
                #3000paket  10s
                new_data.vendercode = macvendors[new_data.mac_src[0:8].upper()]
                
            except Exception as e:
                print(e)

            #OS種類、バージョン
            try:
                dst_osname = "unknown"
                #注意：通信相手のOSがわかる。（自分じゃない）
                if tcp_flg == True:
                    ttl = scapy_cap[IP].ttl
                    windowsize = scapy_cap[TCP].window
                    dst_osname = COE_COMMON.CheckOSName(ttl,windowsize)
                elif ip_flg == True:
                    ttl = ttl = scapy_cap[IP].ttl
                    dst_osname = COE_COMMON.CheckOSName(ttl,"")
            except Exception as e:
                dst_osname = "error"

            #通信先(IP)
            try:
                if ip_flg == True:
                    new_data.ip_dst = scapy_cap[IP].dst
            except Exception as e:
                new_data.ip_dst = "error"
            
            #通信（192.168.1.10:1000-192.168.1.100:http(80)）
            try:
                if(tcp_flg == True or udp_flg == True):
                    new_data.communication = new_data.ip_src+":"+new_data.port_src+"-"+\
                                            new_data.ip_dst+":"+new_data.protocol
            except Exception as e:
                new_data.communication = "error"

            
        except Exception as e:
            print(e)
        
        

        update_flg = False
        #pcapファイル内で資産を重複させないようにチェックする
        for pcapAsset in pcapAssetList:
            #以下の条件のいずれかに一致した場合、台帳を更新する
            # MACとIPが一致している場合
            # または　スキャン結果のIPがなく、PCAPのIPがあり、MACが一致した場合　
            # または　スキャン結果のIPがあり、PCAPのIPがなく、MACが一致した場合
            # または　スキャン結果のIPがなく、PCAPのIPがなく、MACが一致した場合
            if(pcapAsset.ip_src == new_data.ip_src and pcapAsset.mac_src.lower() == new_data.mac_src.lower() or \
                (COE_COMMON.HasElementValue(new_data.ip_src)==False and COE_COMMON.HasElementValue(pcapAsset.ip_src)==True and pcapAsset.mac_src.lower() == new_data.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(new_data.ip_src)==True and COE_COMMON.HasElementValue(pcapAsset.ip_src)==False and pcapAsset.mac_src.lower() == new_data.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(new_data.ip_src)==False and COE_COMMON.HasElementValue(pcapAsset.ip_src)==False and pcapAsset.mac_src.lower() == new_data.mac_src.lower())):
                update_flg = True
                pcapAsset = UpdatePcapList(pcapAsset=pcapAsset,newAsset=new_data)
            else:
                pass

            #通信先のOSを更新する そのうち関数化する
            if(pcapAsset.ip_src.lower() == new_data.ip_dst.lower()):
                if(COE_COMMON.HasElementValue(dst_osname) == False):
                    pass
                elif(COE_COMMON.HasElementValue(pcapAsset.osname) == False):
                    pcapAsset.osname = dst_osname
                elif(pcapAsset.osname != dst_osname):
                    pcapAsset.osname = dst_osname
            else:
                pass
                    
        if(update_flg == True):
            pass
        else:
            #MACがLISTに該当しない場合は追加
            pcapAssetList.append(COE_CLASS.CoeAsset(\
                hostname=new_data.hostname,
                ip_src=new_data.ip_src,\
                mac_src=new_data.mac_src,\
                vendercode=new_data.vendercode,\
                mac_dst=new_data.mac_dst,\
                ip_dst=new_data.ip_dst,\
                protocol=new_data.protocol,\
                port_src=new_data.port_src,\
                port_dst=new_data.port_dst,\
                communication=new_data.communication))
    return pcapAssetList

################################################################################
#パケット解析 
#pyshark をサマリーだけにして、プロトコルだけ取得する。それ以外はScapyで解析する
#   pyshark.FileCapture(filepath,only_summaries=True)
#   only_summaries=True　とすると最初のパケットがロストするバグあり
#   https://github.com/KimiNewt/pyshark/issues/148    
#引数
#py_caps        :pysharkのpcap読み込み結果（サマリー情報のみ）
#scapy_caps     :scapyのpcapファイル読み込み結果
#戻り値
#pcapAssetList  :class CoeAssetのlist pcapファイルのスキャン結果一覧
def FastAnalysisPacket(py_caps="",scapy_caps=""):
    
    pcapAssetList = []

    n=1 #解析パケット数のカウント
    m=0 #scapyの配列指定用
    for py_cap in py_caps:
        #pysharkのバグでpy_capとscapy_capsが一つずれているからscapy_capsは[1]から始める
        m+=1
        if(m%1000==0):
            print(n*1000,"パケット解析")
            n+=1

        new_data = COE_CLASS.CoeAsset(
            hostname="unknown",\
            ip_src = "unknown",\
            mac_src = "unknown",\
            mac_dst = "unknown",\
            vendercode = "unknown",\
            osname = "unknown" ,\
            ip_dst = "unknown",\
            protocol= "unknown",\
            port_src= "unknown",\
            port_dst= "unknown",\
            communication= "unknown") 
                
        dst_osname = "unkwown"
        tcp_flg = False
        udp_flg = False
        ip_flg = False
        eth_flg = False
        dot3_flg = False #802.3
        ttl = -1
        windowsize = -1

        try:
            #通信レイヤーの把握
            try:
                if(scapy_caps[m].haslayer(TCP)):
                    tcp_flg = True
                    ip_flg = True
                elif(scapy_caps[m].haslayer(UDP)):
                    udp_flg = True
                    ip_flg = True
                elif(scapy_caps[m].haslayer(IP)):
                    ip_flg = True    
                
                if(scapy_caps[m].haslayer(Ether)):
                    eth_flg = True
                elif(scapy_caps[m].haslayer(Dot3)):
                    dot3_flg = True
            except Exception as e:
                print("layer error")

            #通信元ポート
            try:
                if tcp_flg == True:
                    new_data.port_src = str(scapy_caps[m][TCP].sport)
                elif udp_flg == True:
                    new_data.port_src = str(scapy_caps[m][UDP].sport)
            except Exception as e:
                new_data.port_dst = "error"

            #通信先ポート
            try:
                if tcp_flg == True:
                    new_data.port_dst = str(scapy_caps[m][TCP].dport)
                elif udp_flg == True:
                    new_data.port_dst = str(scapy_caps[m][UDP].dport)
            except Exception as e:
                new_data.port_dst = "error"

            #通信プロトコル
            try:
                new_data.protocol=py_cap.protocol
                if(tcp_flg == True or udp_flg == True):
                    new_data.protocol = new_data.protocol + "(" + new_data.port_dst +")"

            except Exception as e:
                new_data.protocol = "error"

            #ホスト名
            try:
                if py_cap.protocol == "DHCP":
                    for dhcp_count in range(0,len(scapy_caps[m][DHCP].options)):
                        if(scapy_caps[m][DHCP].options[dhcp_count][0]=="hostname"): 
                            new_data.hostname = scapy_caps[m][DHCP].options[dhcp_count][1].decode('utf-8')
                            break
                elif py_cap.protocol == "NBNS":
                    try:
                        #Additional RRsが1だとWPAD(名前解決のサーバ？)の値が入る
                        if(scapy_caps[m][NBNSQueryRequest].ARCOUNT==1 and \
                            scapy_caps[m][NBNSQueryRequest].name.decode('utf-8').strip()!="WORKGROUP"):
                            new_data.hostname = scapy_caps[m][NBNSQueryRequest].QUESTION_NAME.decode('utf-8').strip()
                    except:
                        hostname = "error"
            except Exception as e:
                hostname = "error"

            #IPアドレス
            try:
                if ip_flg == True:
                    new_data.ip_src = scapy_caps[m][IP].src
            except Exception as e:
                new_data.ip_src = "none"

            #MACアドレス
            try:
                if(eth_flg == True):
                    new_data.mac_dst = scapy_caps[m][Ether].dst
                    new_data.mac_src = scapy_caps[m][Ether].src
                elif(dot3_flg == True):
                    new_data.mac_dst = scapy_caps[m][Dot3].dst
                    new_data.mac_src = scapy_caps[m][Dot3].src
            except Exception as e:
                new_data.mac_src = "error"
                new_data.mac_dst = "error"

            #ベンダー情報
            try:
                #3000paket  10s
                new_data.vendercode = macvendors[new_data.mac_src[0:8].upper()]
            except Exception as e:
                print(e)

            #OS種類、バージョン
            try:
                dst_osname = "unknown"
                #注意：通信相手のOSがわかる。（自分じゃない）
                if tcp_flg == True:
                    ttl = scapy_caps[m][IP].ttl
                    windowsize = scapy_caps[m][TCP].window
                    dst_osname = COE_COMMON.CheckOSName(ttl,windowsize)
                elif ip_flg == True:
                    ttl = ttl = scapy_caps[m][IP].ttl
                    dst_osname = COE_COMMON.CheckOSName(ttl,"")
            except Exception as e:
                dst_osname = "error"

            #通信先(IP)
            try:
                if ip_flg == True:
                    new_data.ip_dst = scapy_caps[m][IP].dst
            except Exception as e:
                new_data.ip_dst = "error"
            
            #通信（192.168.1.10:1000-192.168.1.100:http(80)）
            try:
                if(tcp_flg == True or udp_flg == True):
                    new_data.communication = new_data.ip_src+":"+new_data.port_src+"-"+\
                                            new_data.ip_dst+":"+new_data.protocol
            except Exception as e:
                new_data.communication = "error"
            
        except Exception as e:
            print(e)
        
        update_flg = False
        #pcapファイル内で資産を重複させないようにチェックする
        for pcapAsset in pcapAssetList:
            #以下の条件のいずれかに一致した場合、台帳を更新する
            # MACとIPが一致している場合
            # または　スキャン結果のIPがなく、PCAPのIPがあり、MACが一致した場合　
            # または　スキャン結果のIPがあり、PCAPのIPがなく、MACが一致した場合
            # または　スキャン結果のIPがなく、PCAPのIPがなく、MACが一致した場合
            if(pcapAsset.ip_src == new_data.ip_src and pcapAsset.mac_src.lower() == new_data.mac_src.lower() or \
                (COE_COMMON.HasElementValue(new_data.ip_src)==False and COE_COMMON.HasElementValue(pcapAsset.ip_src)==True and pcapAsset.mac_src.lower() == new_data.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(new_data.ip_src)==True and COE_COMMON.HasElementValue(pcapAsset.ip_src)==False and pcapAsset.mac_src.lower() == new_data.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(new_data.ip_src)==False and COE_COMMON.HasElementValue(pcapAsset.ip_src)==False and pcapAsset.mac_src.lower() == new_data.mac_src.lower())):
                update_flg = True
                pcapAsset = UpdatePcapList(pcapAsset=pcapAsset,newAsset=new_data)
            else:
                pass

            #通信先のOSを更新する そのうち関数化する
            if(pcapAsset.ip_src.lower() == new_data.ip_dst.lower()):
                if(COE_COMMON.HasElementValue(dst_osname) == False):
                    pass
                elif(COE_COMMON.HasElementValue(pcapAsset.osname) == False):
                    pcapAsset.osname = dst_osname
                elif(pcapAsset.osname != dst_osname):
                    pcapAsset.osname = dst_osname
            else:
                pass
                    
        if(update_flg == True):
            pass
        else:
            #MACがLISTに該当しない場合は追加
            pcapAssetList.append(COE_CLASS.CoeAsset(\
                hostname=new_data.hostname,
                ip_src=new_data.ip_src,\
                mac_src=new_data.mac_src,\
                vendercode=new_data.vendercode,\
                mac_dst=new_data.mac_dst,\
                ip_dst=new_data.ip_dst,\
                protocol=new_data.protocol,\
                port_src=new_data.port_src,\
                port_dst=new_data.port_dst,\
                communication=new_data.communication))
        
            
    return pcapAssetList

################################################################################
#パッシブスキャン
#リアルタイム処理にするとpysharkがつど、変数定義が必要のため結果、処理が遅かったので、
#一度tsharkで全て読み込んだ後、現在時刻を用いてpcapファイルを作成して、それを読み込んで解析をしている。
#利点としては他のアプリでpcapファイルを生成しなくても良いためこのアプリで完結できる。

#残り時間表示
#引数
#timeout    :int スキャンする時間（秒）
#戻り値
#なし
def Progress(timeout=0):
    i=0
    for i in range(timeout):
        time.sleep(1)
        print("残り",timeout-i,"秒")

#sniff_capsにパケットを保管する
#引数
#frame    :パケット
#戻り値
#なし
sniff_caps = []
def sniff_callback(frame):
    sniff_caps.append(frame)

#引数
#interface          :string パッシブスキャンに使用するNIC
#timeout            :string スキャンする時間（秒）
#戻り値
#passiveAssetList   :class CoeAssetのlist パッシブスキャン結果一覧
def CoePassiveScan(interface="",timeout=0):
    passiveAssetList = []
    
    temp_pcap_path = str(time.time()) + ".pcap"
    
    with ThreadPoolExecutor() as executor:
        executor.submit(Progress,int(timeout))#マルチスレッドで残り時間を表示
        try:
            cmd = "tshark -i " + interface + " -a duration:" + timeout + " -w " + temp_pcap_path
            #cmd="tshark -i  en0 duration:10 -w test.pcap"
            print(cmd)
            packetcount=subprocess.check_output(cmd.split()).decode('utf-8').split("\n") #実行結果を改行で分割する
            
        except Exception as e:
            print("Passive Scan Error:",e)
    


    print("ファイルロード 0/2")
    scapy_caps = rdpcap(temp_pcap_path)

    #pyshark and scapy
    print("ファイルロード 1/2")    
    py_caps = pyshark.FileCapture(temp_pcap_path,only_summaries=True)
    print("ファイルロード 2/2")
    print("解析開始")
    passiveAssetList = FastAnalysisPacket(py_caps,scapy_caps)

    #scapy only
    #passiveAssetList = FastestAnalysisPacket(scapy_caps)

    #temp_pcapの削除をする

    return passiveAssetList

################################################################################
#Pcapファイルのスキャン
#引数
#filepath           :string pcapファイルパス
#戻り値
#pcapAssetList      :class CoeAssetのlist pcapファイルスキャン結果一覧
def CoePcapScan(filepath=""):
    
    start = time.time() 
    pcapAssetList = []
    
    print("ファイルロード 0/2")
    scapy_caps = rdpcap(filepath)
    
    #pyshark and scapy
    print("ファイルロード 1/2")
    py_caps = pyshark.FileCapture(filepath,only_summaries=True)
    print("ファイルロード 2/2")
    print("解析開始")
    pcapAssetList = FastAnalysisPacket(py_caps,scapy_caps)
    
    #scapyのみの場合
    #pcapAssetList = FastestAnalysisPacket(scapy_caps)

    elapsed_time = time.time() - start
    print ("diff_PcapScan:{:.10f}".format(elapsed_time) + "[sec]")


    return pcapAssetList

