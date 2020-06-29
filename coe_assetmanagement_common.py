import re           #正規表現用
import csv          #csvファイル読み込み
import coe_assetmanagement_class as COE_CLASS

#ip,macの正規表現パターン
ip_pattern = r"(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
mac_pattern =r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
#引数
#checkstr   :string IPアドレス形式かチェックしたい文字列
#戻り値
#MatchObject
def CheckIP(checkstr=""):
    return re.search(ip_pattern, checkstr) #IPアドレスのマッチング
#引数
#checkstr   :string MACアドレス形式かチェックしたい文字列
#戻り値
#MatchObject
def CheckMAC(checkstr=""):
    return re.search(mac_pattern, checkstr) #IPアドレスのマッチング

#OS情報の判定
#TTL(Time to Live) から通信先のOS種類をざっくり推測、windowsizeは現在未使用
#改良の余地あり
#引数
#ttl        :string Time to Liveの値
#windowsize :string WindowSiezの値
#戻り値
#osname     :string OS情報を返す
def CheckOSName(ttl,windowsize):
    osname = "unknown"
    if ttl == "64":
        osname = "linux or MAC"
    elif ttl == "128":
        osname = "windows"
    elif ttl == "255":
        osname = "unix or network"
    return osname

#指定した文字列に値があるか確認する
#値がないとは"unknown","none","error",""を表す
#引数
#ele        :string 確認したい要素
#戻り値
#True/False :bool False True
def HasElementValue(ele=""):
    if ele == "unknown" or ele =="none" or ele=="error" or ele == "":
        return False
    else:
        return True


#資産台帳CSVファイルを読み込む
#引数
#filepath   :string 資産台帳CSVのファイルパス
#戻り値
#assetList  :class CoeAssetのlist 資産台帳一覧
def ReadAssetCSV(filepath=""):
    assetList = []
    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            assetList.append(COE_CLASS.CoeAsset(\
                hostname=row["hostname"],\
                ip_src=row["ip_src"],\
                mac_src=row["mac_src"],\
                vendercode=row["vendercode"],\
                osname=row["osname"],\
                mac_dst=row["mac_dst"],\
                ip_dst=row["ip_dst"],\
                protocol=row["protocol"],\
                port_src=str(row["port_src"]),\
                port_dst=str(row["port_dst"]),\
                communication=row["communication"]))
    return assetList


#資産台帳をCSVファイルへ出力する
#引数
#filepath   :string 資産台帳CSVのファイルパス
#resultList :class CoeAssetのlist スキャン結果
#戻り値
#なし
def WriteAssetCSV(filePath="",resultList=[]):
    resultFilePath = filePath
    with open(resultFilePath, 'w') as f:

        fieldnames = ["hostname", "ip_src","mac_src","vendercode","osname","mac_dst","ip_dst","protocol","port_src","port_dst","communication","status"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for rl in resultList:
            matchstring = "OK"
            if(rl.matchstatus ==2):
                matchstring = "NoDiscovery"
            elif(rl.matchstatus == 3):
                matchstring = "IPOnlyMatch"
            elif(rl.matchstatus == 4):
                matchstring = "MacOnlyMatch"
            elif(rl.matchstatus == 5):
                matchstring = "DiscoveryNewDevice"

            writer.writerow({\
                "hostname":rl.hostname,\
                "ip_src":rl.ip_src,\
                "mac_src":rl.mac_src,\
                "vendercode":rl.vendercode,\
                "osname":rl.osname,\
                "mac_dst":rl.mac_dst,\
                "ip_dst":rl.ip_dst,\
                "protocol":rl.protocol,\
                "port_src":rl.port_src,\
                "port_dst":rl.port_dst,\
                "communication":rl.communication,\
                "status":matchstring})


#MACベンダーのファイル読み込み
#使い方：macvendors[tmp[0:8].upper()]
#引数
#なし
#戻り値
#macvendors :dict MACアドレスとベンダーコードが紐づいている
def ReadMACVendor():
    path = "vender_mac_v3.txt"
    macvendors = {}
    with open(path) as f:
        for s_line in f:
            #末尾の改行コードを決して、カンマで分割して、-を:に置き換えた文字列をキーにする
            #値はカンマ区切りの次の文字列を入れる
            macvendors[s_line.rstrip('\n').split(',', 1)[0].replace('-', ':')] = s_line.rstrip('\n').split(',', 1)[1]
    return macvendors

#ポート番号とプロトコルが紐付くCSVファイルを読み込む
#https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
#引数
#なし
#戻り値
#portNumberList :dict TCP/UDPポート番号とプロトコル種別が紐づいている
def ReadPortNumberCSV():
    filepath="service-names-port-numbers.csv"
    portNumberList = {}
    port_pattern =r"[0-9A-Fa-f]+-[0-9A-Fa-f]+"
    
    with open(filepath) as f:
        reader = csv.reader(f)
        for row in reader:
            #３列目がtcp or udpで２列が数字or「数字-数字」あれば１列目を格納する
            protocolName = row[0]
            num = row[1]
            protocolType = row[2]

            if(protocolType=="tcp" or protocolType=="udp"):
                if(num.isdigit()):
                    portNumberList[str(num) + protocolType]=protocolName
                elif(re.fullmatch(port_pattern, num)):
                    startnum = int(num[0:num.find("-")])
                    endnum = int(num[num.find("-")+1:len(num)])
                    for i in range(startnum,endnum+1):
                        portNumberList[str(i) + protocolType]=protocolName

    return portNumberList

#EtherTypeとプロトコルが紐付くCSVファイルを読み込む
#https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
#引数
#なし
#戻り値
#ethTypeList :dict EtherTypeとプロトコル種別が紐づいている
def ReadEtherTypeCSV():
    filepath="ieee-802-numbers-1.csv"
    ethTypeList = {}
    #xxxx or xxxx-xxxx
    ethtype_pattern1 =r"[0-9A-Fa-f]+"
    ethtype_pattern2 =r"[0-9A-Fa-f]+-[0-9A-Fa-f]+"

    with open(filepath) as f:
        reader = csv.reader(f)
        for row in reader:
            hexnum = row[1]
            protocolName = row[4]
            if(re.fullmatch(ethtype_pattern1, hexnum)):
                ethTypeList[int(hexnum,16)]=protocolName
            elif(re.fullmatch(ethtype_pattern2, hexnum)):
                startnum = int(hexnum[0:hexnum.find("-")],16)
                endnum = int(hexnum[hexnum.find("-")+1:len(hexnum)],16)
                for i in range(startnum,endnum+1):
                    ethTypeList[i]=protocolName

    return ethTypeList

#プロトコル番号とプロトコルが紐付くCSVファイルを読み込む
#https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#引数
#なし
#戻り値
#protocolNumberList :dict IPヘッダー内のプロトコル番号とプロトコル種別が紐づいている
def ReadProtocolNumberCSV():
    filepath="protocol-numbers-1.csv"
    protocolNumberList = {}
    
    with open(filepath) as f:
        reader = csv.reader(f)
        for row in reader:
            num = str(row[0])
            protocolName = row[1]
            if(num.isdigit()):
                protocolNumberList[num]=protocolName

    return protocolNumberList