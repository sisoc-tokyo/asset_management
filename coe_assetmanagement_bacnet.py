import time
import threading
import pyshark
import datetime as dt
import csv
import netifaces
from scapy.all import *

#PROP_LIST = [12,44,70,75,76,77,96,97,98,112,120,121,139,155]
PROP_LIST = [12,44,70,75,76,77,98,112,120,121,139,155]
INTERVAL = 0.1                            ###readPropertyの送信間隔。ICSの可用性に影響しない値に設定すること！！！！####

def BACnetWhoisSend(whois_s_IF,whois_s_MAC,whois_s_IP,whois_d_IP):      #whoisの送信
    print("Sending whoIs frames...")
    whois_tmp1 = Ether(src=whois_s_MAC,dst="FF:FF:FF:FF:FF:FF") / IP(src=whois_s_IP,dst=whois_d_IP,chksum=None) / UDP(sport=47808,dport=47808,chksum=None) / b"\x81\x0b\x00\x08\x01\x00\x10\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    whois_tmp2 = Ether(src=whois_s_MAC,dst="FF:FF:FF:FF:FF:FF") / IP(src=whois_s_IP,dst=whois_d_IP,chksum=None) / UDP(sport=47808,dport=47808,chksum=None) / b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"
    sendp(whois_tmp1,iface=whois_s_IF,verbose=0)
    sendp(whois_tmp2,iface=whois_s_IF,verbose=0)

def SniffBACnetWhois(sniff_whois_IF):                                   #scapy(sniff)でパケットキャプチャ
    FILT = "udp and port 47808"                                         #BACnetのUDP47808のフィルタ
    print("Start sniffing iAm frames...")
    whois_pcap = sniff(iface=sniff_whois_IF,filter=FILT,count=65535,timeout=2)  #BACnetでフィルタしてsniff
    wrpcap("bacnet.pcap",whois_pcap)                                    #sniffしたデータをPCAPファイルに変換

def MakeIamList():                                                      #受信したiamパケットの解析とCSV化
    pcap = pyshark.FileCapture("bacnet.pcap")                           #キャプチャデータをpysharkで開く
    iam_asset_list = [["0.0.0.0","00:00:00:00:00:00","0","0"]]          #1行目はダミーデータ(あとで項目名に置換)
    for packet in pcap:                                                 #パケットを上から順に比較
        if packet.bacapp.type == "1" and packet.bacapp.unconfirmed_service == "0":  #iamのパケットと一致したらiamリストに追記
#            print("送信元MAC " + packet.eth.src,"送信元IP " + packet.ip.src,"Deviceインスタンス番号 " + packet.bacapp.instance_number,"ベンダID " + packet.bacapp.vendor_identifier)
            iam_asset_list.append([packet.ip.src,packet.eth.src,packet.bacapp.instance_number,packet.bacapp.vendor_identifier])
        else:
            pass
    iam_asset_list = list(map(list, set(map(tuple, iam_asset_list))))   #重複の削除
    iam_asset_list.sort()                                               #行をIPアドレスの昇順にソート
    iam_asset_list[0] = ["IPアドレス","MACアドレス","Deviceインスタンス番号","BACnetベンダID"]    #1行目に項目名を追加
    with open("bacnet_vendor_id_list.csv",encoding="utf_8") as fv:      #以下でベンダIDをベンダ名に置換
        vendor_list = list(csv.reader(fv))                              #csvファイルのデータをlist化
    for dev_num in range(1,len(iam_asset_list)):                        #iam_listの1行目からベンダIDを取得
        vid = 0                                                         #ベンダIDの初期化
        while iam_asset_list[dev_num][3] != vendor_list[vid][0]:        #iam_listのベンダIDとcsvのベンダIDが一致するまでベンダIDを加算
            vid += 1
        iam_asset_list[dev_num][3] = vendor_list[vid][1]                #ベンダIDが一致したところでベンダ名に置換
    return iam_asset_list

def GetNWInfo(ifname=""):                                               #IF名からMACアドレス、IPアドレス、ブロードキャストアドレスを取得
    get_s_MAC =  netifaces.ifaddresses(ifname)[netifaces.AF_LINK][0]["addr"]
    get_s_IP = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]["addr"]
    get_b_IP = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]["broadcast"]
    return get_s_MAC,get_s_IP,get_b_IP

def BACnetReadSend(read_s_IF,read_timeout,read_list):                   #Readpropertyの送信
    print("Sending readProperty packets and capturing Ack packets...")
    print("Please wait for about " + str(int(read_timeout)) + " seconds...")
    read_packet = IP(chksum=None) / UDP(sport=47808,dport=47808,chksum=None) / b"\x81\x0a\x00\x11\x01\x00\x00\x03\x2b\x0c\x0c\x02\x00\x00\x02\x19\x0c"
    for dev in range(1,len(read_list)):                                 #CSVからデバイスのMACアドレスとIPアドレスを取得
        read_packet[IP].dst = read_list[dev][0]
        for prop in PROP_LIST:                                          #対象デバイスの対象プロパティに順番にReadpropertyを送信
            payload = bytearray(read_packet.load)
            payload[14] =  int(read_list[dev][2])
            payload[16] =  prop
            read_packet[Raw].load = bytes(payload)
            read_packet[IP].chksum = None
            read_packet[UDP].chksum = None
            send(read_packet,iface=read_s_IF,verbose=0)
            time.sleep(INTERVAL)

def SniffBACnetReadAck(sniff_IF,sniff_s_IP,sniff_timeout):              #パケットをキャプチャしてbacnet.pcapを作成
    READACK_FILT = "udp and port 47808 and ip dst " + sniff_s_IP
    ack_frame=sniff(iface=sniff_IF,filter=READACK_FILT,count=65535,timeout=sniff_timeout)
    wrpcap("bacnet.pcap",ack_frame)

def MakeReadAckList(read_dev_list,read_csv_filename):                   #pcapファイルから資産情報を抽出してCSVに書き込み
    pcap = pyshark.FileCapture("bacnet.pcap")                           #pcapをpysharkで開く
    ack_frame = rdpcap('bacnet.pcap')                                   #pcapをscapyで開く
    timestamp = dt.datetime.now()                                       #結果のCSVファイルの作成
    csv_asset = open(read_csv_filename, 'w', encoding="shift_jis")
    csv_asset_writer = csv.writer(csv_asset, lineterminator='\n') 
 
    pcap.load_packets()
    pcap_amount = len(pcap)                                             #パケット数のカウント
    print(str(pcap_amount) + " packets were captured.")
    print("A CSV file is being created...")
    item_list = ['IPアドレス', 'MACアドレス', 'Deviceインスタンス番号', 'BACnetベンダ名',\
        'Application Software Version',\
        'Firmware Revision',\
        'Model Name',\
        'Object Identifier',\
        'Object List',\
        'Object Name',\
#        'Protocol Object Types Supported',\
#        'Protocol Services Supported',\
        'Protocol Revision',\
        'System Status',\
        'Vendor Identifier',\
        'Vendor Name',\
        'Protocol Version',\
        'Database Revision']
    csv_asset_writer.writerow(item_list)
    for dev in range(1,len(read_dev_list)):                             #デバイス0から順番に以下を実施
        for num in range(pcap_amount):
            data_array = ""                                             #データの初期化
            if pcap[num].ip.src== read_dev_list[dev][0] and pcap[num].bacapp.type == "3":   #送信元IPが一致、かつComplex-Ackの場合パケットから情報を取得
                ack_apdu = bytearray(ack_frame[num].load)
                if ack_apdu[17] == 63 or ack_apdu[17] == 0:             #open-tag(62)直後にclose-tag(63)もしくはNULLの場合は空なのでNo Dataを出力
                    read_dev_list[dev].append("-")
                else:
                    if ack_apdu[17] & 0b11110000 == 0x20:               #type=2の場合はunsignedのため
                        data_len = ack_apdu[17] & 0b00001111            #18バイト目の下位4bitがLength
                        for l in range(data_len):
                            data_array = data_array + hex(ack_apdu[18+l])
                    elif ack_apdu[17] & 0b11110000 == 0x70:             #type=7の場合はcharacter string
                        if ack_apdu[17] & 0b00001111 == 0x05:           #Extended Valueありの場合
                            data_len = ack_apdu[18]                     #19バイト目がLength
                            if ack_apdu[19] == 1:                       #文字コード指定ありの場合
                                for l in range(data_len-3):
                                    if ack_apdu[22+l] > 31:
                                        data_array = data_array + chr(ack_apdu[22+l])
                                    else:
                                        pass
                            else:                                       #文字コード指定無しの場合
                                for l in range(data_len):
                                    if ack_apdu[19+l] > 31:
                                        data_array = data_array + chr(ack_apdu[19+l])
                                    else:
                                        pass
                        else:                                           #Extended Valueなしの場合
                            data_len = ack_apdu[17] & 0b00001111
                            for l in range(data_len):
                                if ack_apdu[18+l] > 31:
                                    data_array = data_array + chr(ack_apdu[18+l])
                                else:
                                    data_array = data_array + hex(ack_apdu[18+l])
                            if data_array == "0x0":
#                                data_array = "No Data"
                                data_array = "-"
                            else:
                                pass
                    elif ack_apdu[17] & 0b11110000 == 0x80:             #type=8の場合はbitstringのため
                        data_len = ack_apdu[18]                         #19バイト目がLengthとなる
                        for l in range(data_len):
                            if ack_apdu[19+l] > 31:
                                data_array = data_array + hex(ack_apdu[19+l])
                            else:
                                pass
                    elif ack_apdu[17] & 0b11110000 == 0x90:             #type=9の場合はenumerated numberのため
                        data_len = ack_apdu[17] & 0b00001111            #18バイト目の下位4bitがLengthとなる
                        for l in range(data_len):
                            data_array = data_array + hex(ack_apdu[18+l])
                        if data_array == "0x0":
                            data_array = "operational"
                        else:
                            pass
                    elif ack_apdu[17] & 0b11110000 == 0xc0:             #type=cの場合はBACnet Object
                        data_len = ack_apdu[17] & 0b00001111
                        for l in range(data_len):
                            data_array = data_array + str("{:02d}".format(ack_apdu[18+l]))
                        object_name = int(data_array,16) >> 22          #22bit右シフトして上位10bitのObject Nameを取り出す
                        object_id = int(data_array,16) & 0b00000000001111111111111111111111 #下位22bitのObject IDを取り出す
                        if object_name == 8:
                            object_name = "device"
                            data_array = object_name + "," + hex(object_id)
                        else:
                            object_name = hex(object_name) + "," + hex(object_id)
                    else:
                        read_dev_list[dev].append("No Response")
                    read_dev_list[dev].append(data_array)
            elif pcap[num].ip.src== read_dev_list[dev][0] and pcap[num].bacapp.type != "3":  #例外はERRORを出力
                read_dev_list[dev].append("ERROR")
            else:
                pass
        csv_asset_writer.writerow(read_dev_list[dev])
    print(dev,"devices are detected.")

def MakeAssetCSV(command=""):
    commands = command.split()
    s_IF = commands[1]
    s_MAC = ""
    s_IP = ""
    d_IP = ""
    s_MAC,s_IP,d_IP = GetNWInfo(commands[1])
    if len(commands) == 5 and commands[3] == "-o":
        csv_filename = commands[4]
    else:
        csv_filename = "bacnet_asset_list.csv"
    main_thread(s_IF,s_MAC,s_IP,d_IP,csv_filename)

def main_thread(main_s_IF,main_s_MAC,main_s_IP,main_d_IP,main_csv_filename):
    thread_1 = threading.Thread(target=BACnetWhoisSend,args=(main_s_IF,main_s_MAC,main_s_IP,main_d_IP))
    thread_2 = threading.Thread(target=SniffBACnetWhois,args=(main_s_IF,))
    thread_2.start()    #thread_2 パケットキャプチャ開始
    time.sleep(0.1)
    thread_1.start()    #thread_1 whois投げる開始
    thread_1.join()     #thread_1 whois投げる終了
    thread_2.join()     #thread_2 パケットキャプチャ終了
    target_list = MakeIamList()       #受信したiamパケットを解析してCSV化
    search_timeout = (len(target_list)-1) * len(PROP_LIST) * INTERVAL + 5

    thread_3 = threading.Thread(target=BACnetReadSend,args=(main_s_IF,search_timeout,target_list))
    thread_4 = threading.Thread(target=SniffBACnetReadAck,args=(main_s_IF,main_s_IP,search_timeout))
    thread_4.start()    #thread_4 パケットキャプチャ開始
    time.sleep(0.1)
    thread_3.start()    #thread_3 readproperty投げる開始
    thread_3.join()     #thread_3 readproperty投げる終了
    thread_4.join()     #thread_4 パケットキャプチャ終了
    MakeReadAckList(target_list,main_csv_filename)       #受信したAckパケットを解析してCSV化
    