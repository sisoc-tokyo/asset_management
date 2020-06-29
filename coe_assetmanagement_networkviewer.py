import networkx as nx
import matplotlib.pyplot as plt
import coe_assetmanagement_class as COE_CLASS
import coe_assetmanagement_common as COE_COMMON
import sys
import os
import time
args = sys.argv

##################################################################
#192.168.1.10:1000-192.168.1.100:http(80)を以下４種類に分割する
# 192.168.1.10
# 1000
# 192.168.1.100
# http(80)
#引数　
# com       :string
#戻り値
# ip_src    :string
# port_src  :string
# ip_dst    :string
# protocol  :string
def SplitCommunication(com=""):
    ip_src_endpos = com.find(":")
    ip_src = com[0:ip_src_endpos]

    port_src_endpos = com.find("-")
    port_src = com[ip_src_endpos+1:port_src_endpos]

    ip_dst_endpos = com.find(":",port_src_endpos)
    ip_dst = com[port_src_endpos+1:ip_dst_endpos]

    protocol = com[ip_dst_endpos+1:len(com)]
    return ip_src,port_src,ip_dst,protocol
##################################################################


#実行方法
#３種類の通常モード
#   MAC  :MACアドレスのみ
#   IP   :IPアドレスのみ
#   COMM :通信元：通信元ポート→通信先：プロトコル
#　例）python3 coe_assetmanagement_networkviewer.py COMM hoge.csv
#旧ファイルとの比較モード
#   MAC2
#   IP2
#   COMM2
#   比較の場合、new.csvにしかない、もしくはある値を強調(通常blue、newだけは赤、oldだけは緑)する
#  例）python3 coe_assetmanagement_networkviewer.py MAC2 old.csv new.csv
#
#結果をXMLで出力する
# ファイル名はhoge_現在時刻.xml or new_現在時刻.xmlとなる
#
#事前準備
#　以下をインストール
#　・networkx
#　・matplotlib
#　coe-assetmanagement_xxx.pyと同一フォルダに格納する
def main():
    csvNewAssetList = []
    csvOldAssetList = []
    csvnewfilepath = ""
    csvoldfilepath = ""
    
    mode = args[1]
    if(mode=="MAC" or mode=="IP" or mode=="COMM"):
        csvnewfilepath = args[2]
    elif(mode=="MAC2" or mode=="IP2" or mode=="COMM2"):
        csvoldfilepath = args[2]
        csvnewfilepath = args[3]
    else:
        print("コマンドエラーです。終了します")
        exit
    

    #CSVファイルの読み込み
    csvNewAssetList = COE_COMMON.ReadAssetCSV(csvnewfilepath)
    if(csvoldfilepath != ""):
        csvOldAssetList = COE_COMMON.ReadAssetCSV(csvoldfilepath)

    #拡張子なしのファイル名取得
    basename_without_ext = os.path.splitext(os.path.basename(csvnewfilepath))[0]
    
    G = nx.MultiDiGraph()
    #図の作成。figsizeは図の大きさ
    plt.figure(figsize=(10, 8))
    plt.suptitle(basename_without_ext+"\n"+"Network")



    protocol_labels = {}    #COMMの場合、通信先へのプロトコル情報を記録しておく（最後のラベル描画のため）
    protocol_colors = {}    #途中計算用（エッジの線が赤から青・緑へ、緑から青へ上書きされないようにする）
    src_flg_list = {}   #送信元の有無を記憶しておく（ノード色決定のため）
    nodes_colors = []   #ノードの色を記憶しておく（最後のノード描画のため）
    
    OK_COLOR = "blue"
    OK_LABEL = "OK"
    NEW_COLOR = "red"
    NEW_LABEL = "New"
    NONE_COLOR = "green"
    NONE_LABEL = "None"
    DSTONLY_COLOR = "black"
    DSTONLY_LABEL = "DstOnly"
    
    ############################################################################################
    if(mode=="MAC"):
        for asset in csvNewAssetList:
            src_flg_list[asset.mac_src] = True
            for mac_dst in asset.mac_dst.split(","):
                #エッジの追加
                G.add_edges_from([(asset.mac_src,mac_dst,{'color': OK_COLOR})])
        #ノードの色を設定する
        nodes = G.nodes()
        for node in nodes:
            if(node in src_flg_list):
                G.add_nodes_from([(node,{"color":OK_COLOR})])
                nodes_colors.append(OK_COLOR)
            else:
                G.add_nodes_from([(node,{"color":DSTONLY_COLOR})])
                nodes_colors.append(DSTONLY_COLOR)
    ############################################################################################
    elif(mode=="IP"):
        for asset in csvNewAssetList:
            src_flg_list[asset.ip_src] = True
            for ip_dst in asset.ip_dst.split(","):
                #エッジの追加
                G.add_edges_from([(asset.ip_src,ip_dst,{'color': OK_COLOR})])
        #ノードの色を設定する
        nodes = G.nodes()
        for node in nodes:
            if(node in src_flg_list):
                G.add_nodes_from([(node,{"color":OK_COLOR})])
                nodes_colors.append(OK_COLOR)
            else:
                G.add_nodes_from([(node,{"color":DSTONLY_COLOR})])
                nodes_colors.append(DSTONLY_COLOR)
    ############################################################################################
    elif(mode=="COMM"):
        for asset in csvNewAssetList:
            src_flg_list[asset.ip_src] = True
            for com in asset.communication.split(","):
                #192.168.1.10:1000-192.168.1.100:http(80)を以下４種類に分割する
                #192.168.1.10
                #1000
                #192.168.1.100
                #http(80)
                ip_src_endpos = com.find(":")
                ip_src = com[0:ip_src_endpos]

                port_src_endpos = com.find("-")
                port_src = com[ip_src_endpos+1:port_src_endpos]

                ip_dst_endpos = com.find(":",port_src_endpos)
                ip_dst = com[port_src_endpos+1:ip_dst_endpos]

                protocol = com[ip_dst_endpos+1:len(com)]
                #protocolが不明は描画しない
                if(protocol == "unknown"):
                    continue

                #ラベルを追加
                if(protocol_labels.get((ip_src,ip_dst)) == None):
                    protocol_labels[(ip_src,ip_dst)]=protocol
                    #エッジの追加
                    G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': OK_COLOR})])
                else:
                    protocol_labels[(ip_src,ip_dst)]=protocol_labels[(ip_src,ip_dst)]+"\n"+protocol
                    #エッジの削除、追加
                    G.remove_edge(ip_src,ip_dst) 
                    G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': OK_COLOR})])
        #ノードの色を設定する
        nodes = G.nodes()
        for node in nodes:
            if(node in src_flg_list):
                G.add_nodes_from([(node,{"color":OK_COLOR})])
                nodes_colors.append(OK_COLOR)
            else:
                G.add_nodes_from([(node,{"color":DSTONLY_COLOR})])
                nodes_colors.append(DSTONLY_COLOR)
    ############################################################################################
    elif(mode=="MAC2"):
        for asset in csvNewAssetList:
            #oldに送信元、送信先があるか確認
            src_flg_list[(asset.mac_src,"new")]= False
            for oldasset in csvOldAssetList:
                #過去の台帳に送信元があった場合
                if(asset.mac_src==oldasset.mac_src):
                    src_flg_list[(asset.mac_src,"new")]= True
                    #送信先が過去にもあるか確認
                    for mac_dst in asset.mac_dst.split(","):
                        #ある場合は青線
                        if(mac_dst in oldasset.mac_dst.split(",")):
                            G.add_edges_from([(asset.mac_src,mac_dst,{"color":OK_COLOR,'interaction':OK_LABEL})])
                        #ない場合は赤線をひく。
                        else:
                            G.add_edges_from([(asset.mac_src,mac_dst,{"color":NEW_COLOR,'interaction':NEW_LABEL})])
                    #送信先が古い台帳にしかない場合、緑線をひく
                    for mac_dst in oldasset.mac_dst.split(","):
                        if(mac_dst in asset.mac_dst.split(",")):
                            pass
                        else:
                            G.add_edges_from([(oldasset.mac_src,mac_dst,{"color":NONE_COLOR,'interaction':NONE_LABEL})])

            #送信元が過去の台帳にない場合、全ての通信先へ赤線をひく
            if(src_flg_list[(asset.mac_src,"new")] == False):
                for mac_dst in asset.mac_dst.split(","):
                    G.add_edges_from([(asset.mac_src,mac_dst,{"color":NEW_COLOR,'interaction':NEW_LABEL})])

        #送信元が過去の台帳にだけある場合、全ての通信先へ緑線をひく
        for oldasset in csvOldAssetList:
            src_flg_list[(oldasset.mac_src,"old")]= False
            for newasset in csvNewAssetList:
                if(newasset.mac_src == oldasset.mac_src):
                    src_flg_list[(oldasset.mac_src,"old")]= True
            if(src_flg_list[(oldasset.mac_src,"old")] == False):
                for mac_dst in oldasset.mac_dst.split(","):
                    G.add_edges_from([(oldasset.mac_src,mac_dst,{"color":NONE_COLOR,'interaction':NONE_LABEL})])

        #送信元が過去の台帳にだけある場合はノードを緑色、新規の台帳にだけある場合はノードを赤色にする
        nodes = G.nodes()
        for node in nodes:
            if((node,"new") in src_flg_list):
                if(src_flg_list[(node,"new")]==True):
                    #過去、新規の両方の台帳にあるノード
                    G.add_nodes_from([(node,{"color":OK_COLOR,'interaction':OK_LABEL})])
                    nodes_colors.append(OK_COLOR)
                else:
                    #新規の台帳にだけあるノード
                    G.add_nodes_from([(node,{"color":NEW_COLOR,'interaction':NEW_LABEL})])
                    nodes_colors.append(NEW_COLOR)
            elif((node,"old") in src_flg_list):
                if(src_flg_list[(node,"old")]==True):
                    pass
                else:
                    #過去の台帳にだけあるノード
                    G.add_nodes_from([(node,{"color":NONE_COLOR,'interaction':NONE_LABEL})])
                    nodes_colors.append(NONE_COLOR)
            else:
                #通信先としてだけ存在しているノード
                G.add_nodes_from([(node,{"color":DSTONLY_COLOR,'interaction':DSTONLY_LABEL})])
                nodes_colors.append(DSTONLY_COLOR)

    ############################################################################################                     
    elif(mode=="IP2"):
        for asset in csvNewAssetList:
            #oldに送信元、送信先があるか確認
            src_flg_list[(asset.ip_src,"new")]= False
            for oldasset in csvOldAssetList:
                #過去の台帳に送信元があった場合
                if(asset.ip_src==oldasset.ip_src):
                    src_flg_list[(asset.ip_src,"new")]= True
                    #送信先が過去にもあるか確認
                    for ip_dst in asset.ip_dst.split(","):
                        #ある場合は青線
                        if(ip_dst in oldasset.ip_dst.split(",")):
                            G.add_edges_from([(asset.ip_src,ip_dst,{"color":OK_COLOR,'interaction':OK_LABEL})])
                        #ない場合は赤線をひく。
                        else:
                            G.add_edges_from([(asset.ip_src,ip_dst,{"color":NEW_COLOR,'interaction':NEW_LABEL})])
                    #送信先が古い台帳にしかない場合、緑線をひく
                    for ip_dst in oldasset.ip_dst.split(","):
                        if(ip_dst in asset.ip_dst.split(",")):
                            pass
                        else:
                            G.add_edges_from([(oldasset.ip_src,ip_dst,{"color":NONE_COLOR,'interaction':NONE_LABEL})])

            #送信元が過去の台帳にない場合、全ての通信先へ赤線をひく
            if(src_flg_list[(asset.ip_src,"new")] == False):
                for ip_dst in asset.ip_dst.split(","):
                    G.add_edges_from([(asset.ip_src,ip_dst,{"color":NEW_COLOR,'interaction':NEW_LABEL})])

        #送信元が過去の台帳にだけある場合、全ての通信先へ緑線をひく
        for oldasset in csvOldAssetList:
            src_flg_list[(oldasset.ip_src,"old")]= False
            for newasset in csvNewAssetList:
                if(newasset.ip_src == oldasset.ip_src):
                    src_flg_list[(oldasset.ip_src,"old")]= True
            if(src_flg_list[(oldasset.ip_src,"old")] == False):
                for ip_dst in oldasset.ip_dst.split(","):
                    G.add_edges_from([(oldasset.ip_src,ip_dst,{"color":NONE_COLOR,'interaction':NONE_LABEL})])

        #送信元が過去の台帳にだけある場合はノードを緑色、新規の台帳にだけある場合はノードを赤色にする
        nodes = G.nodes()
        for node in nodes:
            if((node,"new") in src_flg_list):
                if(src_flg_list[(node,"new")]==True):
                    #過去、新規の両方の台帳にあるノード
                    G.add_nodes_from([(node,{"color":OK_COLOR,'interaction':OK_LABEL})])
                    nodes_colors.append(OK_COLOR)
                else:
                    #新規の台帳にだけあるノード
                    G.add_nodes_from([(node,{"color":NEW_COLOR,'interaction':NEW_LABEL})])
                    nodes_colors.append(NEW_COLOR)
            elif((node,"old") in src_flg_list):
                if(src_flg_list[(node,"old")]==True):
                    pass
                else:
                    #過去の台帳にだけあるノード
                    G.add_nodes_from([(node,{"color":NONE_COLOR,'interaction':NONE_LABEL})])
                    nodes_colors.append(NONE_COLOR)
            else:
                #通信先としてだけ存在しているノード
                G.add_nodes_from([(node,{"color":DSTONLY_COLOR,'interaction':DSTONLY_LABEL})])
                nodes_colors.append(DSTONLY_COLOR)

    ############################################################################################
    elif(mode=="COMM2"):
        for asset in csvNewAssetList:
            #oldに送信元、送信先があるか確認
            src_flg_list[(asset.ip_src,"new")]= False
            for oldasset in csvOldAssetList:
                #過去の台帳に送信元があった場合
                if(asset.ip_src==oldasset.ip_src):
                    src_flg_list[(asset.ip_src,"new")]= True
                    #通信情報が過去にもあるか確認
                    for com in asset.communication.split(","):
                        ip_src,port_src,ip_dst,protocol=SplitCommunication(com=com)
                        #protocolが不明は描画しない
                        if(protocol == "unknown"):
                            continue

                        #通信情報が一致する場合はprotocolの前にOK、一致しない場合はNEWをつける
                        if(com in oldasset.communication.split(",")):
                            if(protocol_labels.get((ip_src,ip_dst)) == None):
                                protocol_colors[(ip_src,ip_dst)]=OK_COLOR
                                protocol_labels[(ip_src,ip_dst)]=OK_LABEL+":"+protocol
                                #エッジの追加
                                G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': protocol_colors[(ip_src,ip_dst)]})])
                            else:
                                protocol_labels[(ip_src,ip_dst)]=protocol_labels[(ip_src,ip_dst)]+"\n"+OK_LABEL+":"+protocol
                                #エッジの削除、追加
                                G.remove_edge(ip_src,ip_dst) 
                                G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': protocol_colors[(ip_src,ip_dst)]})])
                        else:
                            if(protocol_labels.get((ip_src,ip_dst)) == None):
                                protocol_colors[(ip_src,ip_dst)]=NEW_COLOR
                                protocol_labels[(ip_src,ip_dst)]=NEW_LABEL+":"+protocol
                                #エッジの追加
                                G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': protocol_colors[(ip_src,ip_dst)]})])
                            else:
                                #無条件で赤色にする
                                protocol_colors[(ip_src,ip_dst)]=NEW_COLOR
                                protocol_labels[(ip_src,ip_dst)]=protocol_labels[(ip_src,ip_dst)]+"\n"+NEW_LABEL+":"+protocol
                                #エッジの削除、追加
                                G.remove_edge(ip_src,ip_dst) 
                                G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': protocol_colors[(ip_src,ip_dst)]})])


                    #送信先が古い台帳にしかない場合、緑線をひく
                    for com in oldasset.communication.split(","):
                        ip_src,port_src,ip_dst,protocol=SplitCommunication(com=com)
                        if(com in asset.communication.split(",")):
                            pass
                        else:
                            if(protocol_labels.get((ip_src,ip_dst)) == None):
                                protocol_colors[(ip_src,ip_dst)]=NONE_COLOR
                                protocol_labels[(ip_src,ip_dst)]=NONE_LABEL+":"+protocol
                                #エッジの追加
                                G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': protocol_colors[(ip_src,ip_dst)]})])
                            else:
                                #青色だったら緑色にする
                                if(protocol_colors.get((ip_src,ip_dst)) == OK_COLOR):
                                    protocol_colors[(ip_src,ip_dst)]=NONE_COLOR
                                protocol_labels[(ip_src,ip_dst)]=protocol_labels[(ip_src,ip_dst)]+"\n"+NONE_LABEL+":"+protocol
                                #エッジの削除、追加
                                G.remove_edge(ip_src,ip_dst) 
                                G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': protocol_colors[(ip_src,ip_dst)]})])
  
            #送信元が過去の台帳にない場合、全ての通信先へ赤線をひく
            if(src_flg_list[(asset.ip_src,"new")] == False):
                for com in asset.communication.split(","):
                    ip_src,port_src,ip_dst,protocol=SplitCommunication(com=com)
                    if(protocol_labels.get((ip_src,ip_dst)) == None):
                        protocol_labels[(ip_src,ip_dst)]=NEW_LABEL+":"+protocol
                        #エッジの追加
                        G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': NEW_COLOR})])
                    else:
                        protocol_labels[(ip_src,ip_dst)]=protocol_labels[(ip_src,ip_dst)]+"\n"+NEW_LABEL+":"+protocol
                        #エッジの削除、追加
                        G.remove_edge(ip_src,ip_dst) 
                        G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': NEW_COLOR})])
    

        #送信元が過去の台帳にだけある場合、全ての通信先へ緑線をひく
        for oldasset in csvOldAssetList:
            src_flg_list[(oldasset.ip_src,"old")]= False
            for newasset in csvNewAssetList:
                if(newasset.ip_src == oldasset.ip_src):
                    src_flg_list[(oldasset.ip_src,"old")]= True
            if(src_flg_list[(oldasset.ip_src,"old")] == False):
                for com in oldasset.communication.split(","):
                    ip_src,port_src,ip_dst,protocol=SplitCommunication(com=com)
                    if(protocol_labels.get((ip_src,ip_dst)) == None):
                        protocol_labels[(ip_src,ip_dst)]=NONE_LABEL+":"+protocol
                        #エッジの追加
                        G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': NONE_COLOR})])
                    else:
                        protocol_labels[(ip_src,ip_dst)]=protocol_labels[(ip_src,ip_dst)]+"\n"+NONE_LABEL+":"+protocol
                        #エッジの削除、追加
                        G.remove_edge(ip_src,ip_dst) 
                        G.add_edges_from([(ip_src,ip_dst,{'interaction':protocol_labels[(ip_src,ip_dst)], 'color': NONE_COLOR})])
    

        #送信元が過去の台帳にだけある場合はノードを緑色、新規の台帳にだけある場合はノードを赤色にする
        nodes = G.nodes()
        for node in nodes:
            if((node,"new") in src_flg_list):
                if(src_flg_list[(node,"new")]==True):
                    #過去、新規の両方の台帳にあるノード
                    G.add_nodes_from([(node,{"color":OK_COLOR,'interaction':OK_LABEL})])
                    nodes_colors.append(OK_COLOR)
                else:
                    #新規の台帳にだけあるノード
                    G.add_nodes_from([(node,{"color":NEW_COLOR,'interaction':NEW_LABEL})])
                    nodes_colors.append(NEW_COLOR)
            elif((node,"old") in src_flg_list):
                if(src_flg_list[(node,"old")]==True):
                    pass
                else:
                    #過去の台帳にだけあるノード
                    G.add_nodes_from([(node,{"color":NONE_COLOR,'interaction':NONE_LABEL})])
                    nodes_colors.append(NONE_COLOR)
            else:
                #通信先としてだけ存在しているノード
                G.add_nodes_from([(node,{"color":DSTONLY_COLOR,'interaction':DSTONLY_LABEL})])
                nodes_colors.append(DSTONLY_COLOR)

    ############################################################################################
        


    #kの値が大きいほどノード間が広くなる（最大値は不明）
    pos=nx.spring_layout(G,k=2.0)

    #ノードの描画
    nodes = G.nodes()
    #nodes_colors = [G[u]['color'] for u in nodes]
    nx.draw_networkx_nodes(G, pos, alpha=0.4, nodes=nodes, node_color=nodes_colors)

    #エッジの色を設定
    edges = G.edges()
    edges_colors = [G[u][v][0]['color'] for u,v in edges]

    nx.draw_networkx(G,pos,font_size=6,font_weight="bold",\
        edges=edges, edge_color=edges_colors,\
        connectionstyle='arc3,rad=0.03', alpha=0.3)
    #ラベルを描画
    nx.draw_networkx_edge_labels(G,pos,\
        edge_labels=protocol_labels,label_pos=0.8,font_size=4)


    #nx.write_gml(G, 'network.gml')
    #XMLファイルの出力
    nx.write_graphml(G,basename_without_ext+"_"+str(time.time())+'.xml')

    #Linuxだと描画できないので代わりに画像ファイルを保存
    plt.savefig(basename_without_ext+"_"+str(time.time())+'.png')
    plt.show()

if __name__ == '__main__':
    main()
