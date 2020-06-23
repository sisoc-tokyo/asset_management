import coe_assetmanagement_class as COE_CLASS
import coe_assetmanagement_common as COE_COMMON
import coe_assetmanagement_activescan as COE_ACTIVE
import coe_assetmanagement_passivescan as COE_PASSIVE
import coe_assetmanagement_match as COE_MATCH
import coe_assetmanagement_bacnet as COE_BACNET     #bacnet
import time

#アクティブスキャン時に警告表示を行う
#引数　：なし
#戻り値：アクティブスキャン に同意した場合はTrue、違う場合はFalse
def Warningdisplay():
    print("")
    print("###警告###")
    print("")
    print("##アクティブスキャンは制御システムに影響を与える可能性がございます##")
    print("##利用者の自己責任のもと利用いただくことに同意いただける場合は実行ください##")
    print("##「yes」と入力後、Enterを押下すると##")
    print("##アクティブスキャンを実行します##")
    print("##同意いただけない場合はこのままEnterを押下してください##")
    print("")
    
    checkwarning = input()

    if(checkwarning == "yes"):
        return True
    else:
        return False

#ヘルプ表示を行う
#引数　：なし
#戻り値：なし
def Helpdisplay():
    print("ヘルプ")
    print("")
    print("")
    print("1.簡易アクティブスキャン台帳なし")
    print("ass  インターフェース IPアドレス（セグメント） 【オプション　-o 台帳CSVファイル出力先】【オプション -q 警告非表示】")
    print("例）ass  en0 192.168.1.0/24 -o output.csv")
    print("")
    print("2.簡易アクティブスキャン台帳有り")
    print("assl  インターフェース IPアドレス（セグメント） 台帳CSVファイル入力先 【オプション　-o 台帳CSVファイル出力先】【オプション -q 警告非表示】")
    print("例）assl  en0 192.168.1.0/24 input.csv -o output.csv")
    print("")
    print("3.詳細アクティブスキャン台帳なし")
    print("asd  インターフェース IPアドレス（セグメント） 【オプション　-o 台帳CSVファイル出力先】【オプション -q 警告非表示】")
    print("例）asd  en0 192.168.1.0/24 -o output.csv")
    print("")
    print("4.詳細アクティブスキャン台帳有り")
    print("asdl  インターフェース IPアドレス（セグメント） 台帳CSVファイル入力先 【オプション　-o 台帳CSVファイル出力先】【オプション -q 警告非表示】")
    print("例）asdl  en0 192.168.1.0/24 input.csv -o output.csv")
    print("")
    print("5.パッシブスキャン台帳なし")
    print("ps  インターフェース スキャン時間（秒） 【オプション　-o 台帳CSVファイル出力先】")
    print("例）ps  en0 10 -o output.csv")
    print("")
    print("6.パッシブスキャン台帳有り")
    print("psl  インターフェース スキャン時間（秒） 台帳CSVファイル入力先 【オプション　-o 台帳CSVファイル出力先】")
    print("例）psl  en0 10 input.csv -o output.csv")
    print("")
    print("7.PCAPファイルスキャン台帳なし")
    print("pcaps  pcapファイルパス 【オプション　-o 台帳CSVファイル出力先】")
    print("例）pcaps  input.pcap -o output.csv")
    print("")
    print("8.PCAPファイルスキャン台帳有り")
    print("pcapsl  pcapファイルパス 台帳CSVファイル入力先【オプション　-o 台帳CSVファイル出力先】")
    print("例）pcapsl  input.pcap input.csv -o output.csv")
    print("")
    print("50.BACnetスキャン")
    print("bacnet  インターフェース IPアドレス（セグメント）【オプション -q 警告非表示】")
    print("例）bacnet en0 192.168.1.0/24")
    print("")

import sys
args = sys.argv
#コマンドチェック
#1.アクティブスキャン簡易台帳なし　
#  ass   I/F IP -o output.csv
#2.アクティブスキャン簡易台帳あり
#  assl  I/F IP input.csv -o output.csv
#3.アクティブスキャン詳細台帳なし
#  asd   I/F IP -o output.csv
#4.アクティブスキャン詳細台帳あり
#  asdl   I/F IP input.csv -o output.csv
#5.パッシブスキャン台帳なし
#  ps     I/F time(s) -o output.csv
#6.パッシブスキャン台帳あり
#  psl    I/F time(s) input.csv -o output.csv
#7.PCAPスキャン台帳なし
#  pcaps  input.pcap -o output.csv
#8.PCAPスキャン台帳あり
#  pcapsl inputo.pcap input.csv  -o output.csv
#50.BACNetモード
#  bacnet
#
#98.ヘルプ
#   help
#99.終了
#   exit
#引数
#command    :string 入力コマンド
#戻り値
#1.実行コマンド番号
#2.資産台帳CSV書き込みパス
def CheckCommand(command=""):
    try:
        s_command =[]
        s_command = command.split()
        s_command_len = len(s_command)
        warning_flg = 0 # 警告表示チェック用
        if(s_command[0]=="ass"):
            if(COE_COMMON.CheckIP(s_command[2])):
                #警告表示有無を確認
                if(s_command[s_command_len-1]!="-q"):
                    if(Warningdisplay()== False):
                        return -1,""
                else:
                    warning_flg = 1
                    
                if(s_command_len == 3+warning_flg or \
                    s_command_len == 5+warning_flg and \
                    s_command[3] == "-o"):
                    
                    print("アクティブスキャン簡易モード（台帳なし）実行")
                    if(s_command_len == 5+warning_flg and s_command[3] == "-o"):
                        return 1,s_command[4]
                    else:
                        return 1,""
        elif(s_command[0]=="assl"):
            if(COE_COMMON.CheckIP(s_command[2])):
                #警告表示有無を確認
                if(s_command[s_command_len-1]!="-q"):
                    if(Warningdisplay()== False):
                        return -1,""
                else:
                    warning_flg = 1

                if(s_command_len == 4+warning_flg or \
                    s_command_len == 6+warning_flg and \
                    s_command[4] == "-o"):
                    print("アクティブスキャン簡易モード（台帳あり）実行")
                    if(s_command_len+warning_flg == 6 and s_command[4] == "-o"):
                        return 2,s_command[5]
                    else:
                        return 2,""
        elif(s_command[0]=="asd"):
            if(COE_COMMON.CheckIP(s_command[2])):
                #警告表示有無を確認
                if(s_command[s_command_len-1]!="-q"):
                    if(Warningdisplay()== False):
                        return -1,""
                else:
                    warning_flg = 1

                if(s_command_len == 3+warning_flg or \
                    s_command_len == 5+warning_flg and \
                    s_command[3] == "-o"):
                    print("アクティブスキャン詳細モード（台帳なし）実行")
                    if(s_command_len == 5+warning_flg and s_command[3] == "-o"):
                        return 3,s_command[4]
                    else:
                        return 3,""
        elif(s_command[0]=="asdl"):
            if(COE_COMMON.CheckIP(s_command[2])):
                #警告表示有無を確認
                if(s_command[s_command_len-1]!="-q"):
                    if(Warningdisplay()== False):
                        return -1,""
                else:
                    warning_flg = 1

                if(s_command_len == 4+warning_flg or \
                    s_command_len == 6+warning_flg and \
                    s_command[4] == "-o"):
                    print("アクティブスキャン詳細モード（台帳あり）実行")
                    if(s_command_len == 6+warning_flg and s_command[4] == "-o"):
                        return 4,s_command[5]
                    else:
                        return 4,""
        elif(s_command[0]=="ps"):
            if(s_command_len == 3 or \
                s_command_len == 5 and \
                s_command[3] == "-o"):
                print("パッシブスキャンモード（台帳なし）実行")
                if(s_command_len == 5 and s_command[3] == "-o"):
                    return 5,s_command[4]
                else:
                    return 5,""
        elif(s_command[0]=="psl"):
            if(s_command_len == 4 or \
                s_command_len == 6 and \
                s_command[4] == "-o"):
                print("パッシブスキャンモード（台帳あり）実行")
                if(s_command_len == 6 and s_command[4] == "-o"):
                    return 6,s_command[5]
                else:
                    return 6,""
        elif(s_command[0]=="pcaps"):
            if(s_command_len == 2 or \
                s_command_len == 4 and \
                s_command[2] == "-o"):
                print("PCAPスキャンモード（台帳なし）実行")
                if(s_command_len == 4 and s_command[2] == "-o"):
                    return 7,s_command[3]
                else:
                    return 7,""
        elif(s_command[0]=="pcapsl"):
            if(s_command_len == 3 or \
                s_command_len == 5 and \
                s_command[3] == "-o"):
                print("PCAPスキャンモード（台帳あり）実行")
                if(s_command_len == 5 and s_command[3] == "-o"):
                    return 8,s_command[4]
                else:
                    return 8,""
        elif(s_command[0]=="bacnet"):
            if(COE_COMMON.CheckIP(s_command[2])):
                #警告表示有無を確認
                if(s_command[s_command_len-1]!="-q"):
                    if(Warningdisplay()== False):
                        return -1,""
                else:
                    warning_flg = 1
                if(s_command_len == 3+warning_flg or \
                    s_command_len == 5+warning_flg and \
                    s_command[3] == "-o"):
                    print("BACnetスキャンモード実行")
                    if(s_command_len == 5+warning_flg and s_command[3] == "-o"):
                        return 50,s_command[4]
                    else:
                        return 50,""
        elif(s_command[0]=="help"):
            Helpdisplay()
            return 98,""
        elif(s_command[0]=="exit"):
            print("終了します")
            return 99,""
    except Exception as e:
        print(e)
    
    print("コマンドエラーです")
    return -1,""

#メイン関数
#引数
#なし　現在はテスト簡易化のためcommandを自動入力している
#戻り値
#なし
def main(command=""):
#def main():

    command = ""
    #ターミナルから直接実行可能
    if len(args) >= 2 :
        command =  args[1]
        for x in range(2,len(args)):
            command += " " + args[x]
        print("実行コマンド:",command)
    else:
        print("コマンドを入力してエンターを押してください")
        command = input()

    
    start = time.time()

    result,outputfilepath = CheckCommand(command)
    commands = command.split()

    #アクティブスキャン簡易モード（台帳なし）
    if(result == 1):
        arpAssetList = []
        print("Arp実行開始")
        arpAssetList = COE_ACTIVE.CoeArp_Scapy(cmd=command)
        print("[ArpAsset]")
        for arpAsset in arpAssetList:
            arpAsset.AssetView()
        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,arpAssetList)
    #アクティブスキャン簡易モード（台帳あり）
    elif(result==2):
        csvAssetList = []
        csvAssetList = COE_COMMON.ReadAssetCSV(commands[3])
        print("[CsvAsset]")
        for csvAsset in csvAssetList:
            csvAsset.AssetView()
        arpAssetList = []
        print("Arp実行開始")
        arpAssetList = COE_ACTIVE.CoeArp_Scapy(cmd=command)
        print("[ArpAsset]")
        for arpAsset in arpAssetList:
            arpAsset.AssetView()
        resultList = []
        resultList = COE_MATCH.MatchAsset(csvAssetList,arpAssetList)
        print("[ResultAsset]")
        for resultAsset in resultList:
            resultAsset.AssetView()
        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,resultList)

    #アクティブスキャン詳細モード（台帳なし）
    elif(result == 3):
        activeAssetList = []
        print("Arp実行開始")
        activeAssetList = COE_ACTIVE.CoeArp_Scapy(cmd=command)
        print("NBNS,PING実行開始")
        activeAssetList = COE_ACTIVE.CoeActiveScan_Scapy(activeAssetList=activeAssetList)
        
        print("[ActiveAsset]")
        for activeAsset in activeAssetList:
            activeAsset.AssetView()
        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,activeAssetList)

    #アクティブスキャン詳細モード（台帳あり）
    elif(result == 4):
        csvAssetList = []
        csvAssetList = COE_COMMON.ReadAssetCSV(commands[3])
        print("[CsvAsset]")
        for csvAsset in csvAssetList:
            csvAsset.AssetView()

        activeAssetList = []
        print("Arp実行開始")
        activeAssetList = COE_ACTIVE.CoeArp_Scapy(cmd=command)
        print("NBNS,PING実行開始")
        activeAssetList = COE_ACTIVE.CoeActiveScan_Scapy(activeAssetList=activeAssetList)
        print("[ActiveAsset]")
        for activeAsset in activeAssetList:
            activeAsset.AssetView()
        
        resultList = []
        resultList = COE_MATCH.MatchAsset(csvAssetList,activeAssetList)
        print("[ResultAsset]")
        for resultAsset in resultList:
            resultAsset.AssetView()
        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,resultList)

    #パッシブスキャンモード（台帳なし）
    elif(result==5):
        passiveAssetList = []
        passiveAssetList = COE_PASSIVE.CoePassiveScan(commands[1],commands[2])
        print("[PassiveAsset]")
        for passiveAsset in passiveAssetList:
            passiveAsset.AssetView()
        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,passiveAssetList)

    #パッシブスキャンモード（台帳あり）
    elif(result==6):
        csvAssetList = []
        csvAssetList = COE_COMMON.ReadAssetCSV(commands[3])
        print("[CsvAsset]")
        for csvAsset in csvAssetList:
            csvAsset.AssetView()

        passiveAssetList = []
        passiveAssetList = COE_PASSIVE.CoePassiveScan(commands[1],commands[2])
        print("[PassiveAsset]")
        for passiveAsset in passiveAssetList:
            passiveAsset.AssetView()

        resultList = []
        resultList = COE_MATCH.MatchAsset(csvAssetList,passiveAssetList)
        print("[ResultAsset]")
        for resultAsset in resultList:
            resultAsset.AssetView()
        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,resultList)

    #PCAPスキャンモード（台帳なし）
    elif(result==7):
        pcapAssetList = []

        pcapAssetList = COE_PASSIVE.CoePcapScan(commands[1])
        print("[pcapAssetList]")
        for pcapAsset in pcapAssetList:
            pcapAsset.AssetView()


        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,pcapAssetList)

    #PCAPスキャンモード（台帳あり）
    elif(result==8):
        csvAssetList = []
        csvAssetList = COE_COMMON.ReadAssetCSV(commands[2])
        print("[CsvAsset]")
        for csvAsset in csvAssetList:
            csvAsset.AssetView()
        pcapAssetList = []
        pcapAssetList = COE_PASSIVE.CoePcapScan(commands[1])
        print("[pcapAssetList]")
        for pcapAsset in pcapAssetList:
            pcapAsset.AssetView()
        resultList = COE_MATCH.MatchAsset(csvAssetList,pcapAssetList)
        print("[ResultAsset]")
        for resultAsset in resultList:
            resultAsset.AssetView()
        if(len(outputfilepath) != 0):
            COE_COMMON.WriteAssetCSV(outputfilepath,resultList)
    #BACnetスキャンモード（台帳なし）
    elif(result==50):
        print("BACnetを実行")
        COE_BACNET.MakeAssetCSV(command)

    elapsed_time = time.time() - start
    print ("実行時間:{0}".format(elapsed_time) + "[sec]")

    print("実行完了しました")

if __name__ == '__main__':
    main()
