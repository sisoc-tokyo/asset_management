#資産情報クラス
class CoeAsset():
    def __init__(self,hostname="unknown",ip_src="unknown",ip_dst="unknown",\
                mac_src="unknown",mac_dst="unknown",\
                vendercode="unknown",osname="unknown",protocol="unknown",\
                port_src="unknown",port_dst="unknown",\
                communication="unknown",matchstatus=""):
        self.hostname = hostname
        self.ip_src = ip_src
        self.ip_dst = ip_dst 
        self.mac_src = mac_src
        self.mac_dst = mac_dst 
        self.vendercode = vendercode
        self.osname = osname
        self.protocol =  protocol
        self.port_src = port_src
        self.port_dst = port_dst
        self.communication = communication
        self.matchstatus = matchstatus
    
    def AssetView(self):
        print("host=",self.hostname,\
            ":ip_src=",self.ip_src,\
            ":mac=",self.mac_src,\
            ":os=",self.osname,\
            ":vendercode=",self.vendercode,\
            ":mac_dst=",self.mac_dst,\
            ":ip_dst=",self.ip_dst,\
            ":protcol=",self.protocol,\
            ":port_src=",self.port_src,\
            ":port_dst=",self.port_dst,\
            ":communication=",self.communication,\
            ":matchstatus=",self.matchstatus)

