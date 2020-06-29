import coe_assetmanagement_class as COE_CLASS
import coe_assetmanagement_common as COE_COMMON

##csvファイルとスキャン結果の比較を行う
#考え方：
#　csvAssetListとscanAssetListのip,macが完全一致するかチェック
#　以下パターンが考えられる
#    1.以下の条件の場合                 ：右列に1 OK
#       MACとIPが一致している場合
#       または　スキャン結果のIPがなく、台帳のIPがあり、MACが一致した場合　
#       または　スキャン結果のIPがあり、台帳のIPがなく、MACが一致した場合　は更新する
#    2.ipもmacもヒットしなかった場合      ：右列に2  NoDiscovery
#    3.ipのみ一致した場合               ：右列に3   IPOnlyMatch
#    4.macのみ一致した場合              ：右列に4   MACOnlyMatch
#    5.全く新規の端末を発見した場合        ：行追加して右列に5  DicoveryNewDevice
# 
#引数
#csvAssetList   :class CoeAssetのlist   資産台帳一覧
#scanAssetList  :class CoeAssetのlist   スキャン結果一覧
#戻り値
#resultList     :class CoeAssetのlist   最新の資産台帳一覧
def MatchAsset(csvAssetList=[],scanAssetList=[]):
    resultList = []
    #まず台帳情報からスキャン結果に対してチェック
    for cal in csvAssetList:
        #MAC、IP両方とも一致しないを初期値とする
        match_flg = 2
        for sal in scanAssetList:                        
            #以下の条件のいずれかに一致した場合、台帳を更新する
            # MACとIPが一致している場合
            # または　スキャン結果のIPがなく、台帳のIPがあり、MACが一致した場合　
            # または　スキャン結果のIPがあり、台帳のIPがなく、MACが一致した場合
            # または　スキャン結果のIPがなく、台帳のIPがなく、MACが一致した場合
            if(cal.ip_src == sal.ip_src and cal.mac_src.lower() == sal.mac_src.lower() or \
                (COE_COMMON.HasElementValue(sal.ip_src)==False and COE_COMMON.HasElementValue(cal.ip_src)==True and cal.mac_src.lower() == sal.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(sal.ip_src)==True and COE_COMMON.HasElementValue(cal.ip_src)==False and cal.mac_src.lower() == sal.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(sal.ip_src)==False and COE_COMMON.HasElementValue(cal.ip_src)==False and cal.mac_src.lower() == sal.mac_src.lower())):
                match_flg = 1

                #ホスト名
                if(COE_COMMON.HasElementValue(sal.hostname) == False):
                    pass
                elif(COE_COMMON.HasElementValue(cal.hostname) == False):
                    cal.hostname = sal.hostname
                elif(cal.hostname != sal.hostname):
                    print("MAdAddress:",sal.mac_src," のホスト名を更新しました。",\
                        "以前：",cal.hostname,\
                        "今回：",sal.hostname)
                    cal.hostname = sal.hostname
                
                #OS情報
                if(COE_COMMON.HasElementValue(sal.osname) == False):
                    pass
                elif(COE_COMMON.HasElementValue(cal.osname) == False):
                    cal.osname = sal.osname
                elif(cal.hostname != sal.hostname):
                    print("MAdAddress:",sal.mac_src," のOS情報を更新しました。",\
                        "以前：",cal.osname,\
                        "今回：",sal.osname)
                    cal.osname = sal.osname

                #通信先(MAC)の比較
                if(COE_COMMON.HasElementValue(cal.mac_dst) == True and \
                   COE_COMMON.HasElementValue(sal.mac_dst) == True):
                    #両方とも通信先が入っている場合、比較を行う
                    sal_dst_list = sal.mac_dst.split(",")
                    cal_dst_list = cal.mac_dst.split(",")
                    for sal_dst in sal_dst_list:
                        if(sal_dst in cal_dst_list):
                            pass
                        else:
                            #新しい通信先が入っていた
                            print("MAdAddress:",sal.mac_src," の新規の通信先を発見しました。",\
                                    sal_dst)
                            cal.mac_dst = cal.mac_dst + "," + sal_dst
                elif(COE_COMMON.HasElementValue(cal.mac_dst) == False and \
                     COE_COMMON.HasElementValue(sal.mac_dst) == True):
                    cal.mac_dst = sal.mac_dst

                #通信先(IP)の比較
                if(COE_COMMON.HasElementValue(cal.ip_dst) == True and \
                   COE_COMMON.HasElementValue(sal.ip_dst) == True):
                    #両方とも通信先が入っている場合、比較を行う
                    sal_dst_list = sal.ip_dst.split(",")
                    cal_dst_list = cal.ip_dst.split(",")
                    for sal_dst in sal_dst_list:
                        if(sal_dst in cal_dst_list):
                            pass
                        else:
                            #新しい通信先が入っていた
                            print("MAdAddress:",sal.mac_src," の新規の通信先を発見しました。",\
                                    sal_dst)
                            cal.ip_dst = cal.ip_dst + "," + sal_dst
                elif(COE_COMMON.HasElementValue(cal.ip_dst) == False and \
                     COE_COMMON.HasElementValue(sal.ip_dst) == True):
                    cal.ip_dst = sal.ip_dst

                #通信プロトコルの比較
                if(COE_COMMON.HasElementValue(cal.protocol) == True and \
                   COE_COMMON.HasElementValue(sal.protocol) == True):
                    #両方とも通信プロトコルが入っている場合、比較を行う
                    sal_protocol_list = sal.protocol.split(",")
                    cal_protocol_list = cal.protocol.split(",")
                    
                    for sal_protocol in sal_protocol_list:
                        if(sal_protocol in cal_protocol_list):
                            pass
                        else:
                            #新しい通信プロトコルが入っていた
                            print("MAdAddress:",sal.mac_src," の新規の通信プロトコルを発見しました。",\
                                    sal_protocol)
                            cal.protocol = cal.protocol + "," + sal_protocol
                elif(COE_COMMON.HasElementValue(cal.protocol) == False and \
                     COE_COMMON.HasElementValue(sal.protocol) == True):
                    cal.protocol = sal.protocol
                

                #通信元ポートの比較
                if(COE_COMMON.HasElementValue(cal.port_src) == True and \
                   COE_COMMON.HasElementValue(sal.port_src) == True):
                    #両方とも通信先ポートが入っている場合、比較を行う
                    sal_port_src_list = sal.port_src.split(",")
                    cal_port_src_list = cal.port_src.split(",")
                    
                    for sal_port_src in sal_port_src_list:
                        if(sal_port_src in cal_port_src_list):
                            pass
                        else:
                            #通信元ポートが増えた場合は特に出力しない
                            cal.port_src = cal.port_src + "," + sal_port_src
                elif(COE_COMMON.HasElementValue(cal.port_src) == False and \
                     COE_COMMON.HasElementValue(sal.port_src) == True):
                    cal.port_src = sal.port_src

                #通信先ポートの比較
                if(COE_COMMON.HasElementValue(cal.port_dst) == True and \
                   COE_COMMON.HasElementValue(sal.port_dst) == True):
                    #両方とも通信先ポートが入っている場合、比較を行う
                    sal_port_dst_list = sal.port_dst.split(",")
                    cal_port_dst_list = cal.port_dst.split(",")
                    
                    for sal_port_dst in sal_port_dst_list:
                        if(sal_port_dst in cal_port_dst_list):
                            pass
                        else:
                            #新しい通信先ポートが入っていた
                            print("MAdAddress:",sal.mac_src," の新規の通信先ポートを発見しました。",\
                                    sal_port_dst)
                            cal.port_dst = cal.port_dst + "," + sal_port_dst
                elif(COE_COMMON.HasElementValue(cal.port_dst) == False and \
                     COE_COMMON.HasElementValue(sal.port_dst) == True):
                     cal.port_dst = sal.port_dst
                
                #通信
                if(COE_COMMON.HasElementValue(cal.communication) == True and \
                   COE_COMMON.HasElementValue(sal.communication) == True):
                    #両方とも通信先ポートが入っている場合、比較を行う
                    sal_communication_list = sal.communication.split(",")
                    cal_communication_list = cal.communication.split(",")
                    
                    for sal_communication in sal_communication_list:
                        if(sal_communication in cal_communication_list):
                            pass
                        else:
                            #新しい通信が入っていた(送信元：送信元ポート→プロトコル→送信先：送信先ポート)
                            print("MAdAddress:",sal.mac_src," の新規の通信を発見しました。",\
                                    sal_communication,)
                            cal.communication = cal.communication + "," + sal_communication
                elif(COE_COMMON.HasElementValue(cal.communication) == False and \
                     COE_COMMON.HasElementValue(sal.communication) == True):
                    cal.communication = sal.communication

        resultList.append(COE_CLASS.CoeAsset(\
            hostname=cal.hostname,\
            ip_src=cal.ip_src,\
            mac_src=cal.mac_src,\
            osname= cal.osname,\
            vendercode=cal.vendercode,\
            mac_dst= cal.mac_dst,\
            ip_dst= cal.ip_dst,\
            protocol= cal.protocol,\
            port_src= cal.port_src,\
            port_dst= cal.port_dst,\
            communication= cal.communication,\
            matchstatus=match_flg))

    #次にスキャン結果から台帳情報に対してチェック
    for sal in scanAssetList:
        #初期値を新規端末検出とする
        match_flg = 5
        for cal in csvAssetList:
            #以下の条件のいずれかに一致した場合、台帳更新
            # MACとIPが一致している場合
            # または　スキャン結果のIPがなく、台帳のIPがあり、MACが一致した場合　
            # または　スキャン結果のIPがあり、台帳のIPがなく、MACが一致した場合
            # または　スキャン結果のIPがなく、台帳のIPがなく、MACが一致した場合
            if(cal.ip_src == sal.ip_src and cal.mac_src.lower() == sal.mac_src.lower() or \
                (COE_COMMON.HasElementValue(sal.ip_src)==False and COE_COMMON.HasElementValue(cal.ip_src)==True and cal.mac_src.lower() == sal.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(sal.ip_src)==True and COE_COMMON.HasElementValue(cal.ip_src)==False and cal.mac_src.lower() == sal.mac_src.lower()) or \
                (COE_COMMON.HasElementValue(sal.ip_src)==False and COE_COMMON.HasElementValue(cal.ip_src)==False and cal.mac_src.lower() == sal.mac_src.lower())):
                match_flg = 1
                break
            #IPのみが一致した場合は新規登録（例：NIC交換など）
            elif(COE_COMMON.HasElementValue(sal.ip_src)==True and COE_COMMON.HasElementValue(cal.ip_src)==True and cal.ip_src == sal.ip_src and cal.mac_src.lower() != sal.mac_src.lower()):
                match_flg = 3
            #MACのみ一致した場合は新規登録（例：IPアドレス変更、ルータ経由の通信）
            elif(COE_COMMON.HasElementValue(sal.ip_src)==True and COE_COMMON.HasElementValue(cal.ip_src)==True and cal.ip_src != sal.ip_src and cal.mac_src.lower() == sal.mac_src.lower()):
                match_flg = 4
        #全く一致しなかった場合、IPのみ一致した場合、IPがあるがMACのみ一致した場合は、新規登録する
        if(match_flg == 3 or match_flg == 4 or match_flg == 5):
            print("新しい機器を検知しました　MAC:",sal.mac_src," IP:",sal.ip_src)
            resultList.append(COE_CLASS.CoeAsset(\
                hostname=sal.hostname,\
                ip_src=sal.ip_src,\
                mac_src=sal.mac_src,\
                osname= sal.osname,\
                vendercode=sal.vendercode,\
                mac_dst= sal.mac_dst,\
                ip_dst= sal.ip_dst,\
                protocol= sal.protocol,\
                port_src= sal.port_src,\
                port_dst= sal.port_dst,\
                communication= sal.communication,\
                matchstatus=match_flg))
    return resultList

