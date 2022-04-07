/*
 * ===========================================================================
 *
 *       Filename:  SSDPServer.cpp
 *    Description:  服务端设备发现 xml协议
 *        Version:  1.0
 *        Created:  20220406-12:07
 *       Revision:  none
 *       Compiler:  g++
 *         Author:   (zhouyongku),
 *        Company:  
 *
 * ===========================================================================
 */


#include"SSDPServer.h"
#include"uuid/uuid.h"
#include"configuserv.h"
#include"sysinfo/sysinfo.h"
#include"codec/md5.h"
#include"version/version.h"

#define MAXEVENTS 10
#define MAX_EP_TIMEOUT  5000
#define MAX_UDP_MSG_LEN 10*1024

CSSDPServer *CSSDPServer::g_in=NULL;
//全局变量


//解析IP地址
CSSDPServer::CSSDPServer( bool bBox )
{
    m_bBox = bBox;
    m_mt=PTHREAD_MUTEX_INITIALIZER;
    m_cd=PTHREAD_COND_INITIALIZER;
    RTM("CSSDPServer::CSSDPServer bBox=%d",bBox);
    std::thread t([&]
    {
        RTM("CSSDPServer::CSSDPServer create thread");
        InitSendSocket();
        InitRecvSocket();
        char szMsg[MAXSSDPSIZE]={0};
        socklen_t len = sizeof(m_sddr);
        while( true )
        {
            if((recvfrom(m_ssdps, szMsg, MAXSSDPSIZE, 0, (sockaddr*)&m_sddr, &len)) >= 0)
            {
                //printf("recvfrom success ip=%s,msg=%s",inet_ntoa(m_sddr.sin_addr),szMsg);

                ProcesMsg( szMsg );
                memset(szMsg,0,sizeof(szMsg));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    t.detach();
}
void CSSDPServer::ProcesMsg( const char *strMsg )
{
//    <?xml version="1.0" encoding="utf-8"?>
//    <Probe>
//    <Uuid>B1D9AE01-1117-477F-98AB-F2FFEFA7B5F3</Uuid>
//    <Types>inquiry</Types>
//    <DeviceType>CDZSFACEPAD,CDZSFACEAIBOX</DeviceType>
//    </Probe>

//    SendMsg( MakeResponseSearchMsg() );
//    return;
    //printf("CSSDPServer::ProcesMsg msg=%s",strMsg);
    const char *pXmlstr=strstr( strMsg,"<?xml");
    if( !pXmlstr)
    {
        //printf("CSSDPServer::ProcesMsg failed of not found <?xml");
        return;
    }


    TiXmlDocument doc;
    doc.Parse( pXmlstr );
    const TiXmlElement* pEle = doc.FirstChildElement("Probe");
    if( !pEle )
    {
        //printf("CSSDPServer::ProcesMsg failed of not found Probe");
        return;
    }


    const TiXmlElement *pUuid = pEle->FirstChildElement("Uuid");
    const TiXmlElement *pTypes = pEle->FirstChildElement("Types");
    const TiXmlElement *pDeviceType = pEle->FirstChildElement("DeviceType");

    if( !pUuid||!pTypes||!pDeviceType )
    {
        //printf("CSSDPServer::ProcesMsg failed of not found uuid types devicetype");
        return;
    }

    if( 0!=strcmp("inquiry",pTypes->GetText() ) ) return;

    string strUuid = pUuid->GetText();


    SendMsg( MakeResponseSearchMsg( strUuid ) );


}


CSSDPServer::~CSSDPServer()
{

}

CSSDPServer *CSSDPServer::Ins( bool bBox )
{
    if( CSSDPServer::g_in == nullptr )
    {
        CSSDPServer::g_in = new CSSDPServer( bBox );
    }

    return CSSDPServer::g_in;
}


void CSSDPServer::InitSendSocket()
{
    struct timeval TimeOut;
    TimeOut.tv_sec = 1;
    TimeOut.tv_usec = 0;


    m_ssdpc=socket(AF_INET,SOCK_DGRAM,0);
    if( m_ssdpc < 0)
    {
        ERR("CSSDPClient::InitSocket failed of create socket 239.255.255.250:1900");
        return;
    }

    bzero(&m_cddr, sizeof(m_cddr));
    m_cddr.sin_family = AF_INET;
    m_cddr.sin_addr.s_addr = inet_addr("239.255.255.250");
    m_cddr.sin_port = htons(1900);
    setsockopt(m_ssdpc, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut, sizeof(TimeOut));
    ip_mreq mreq;
    bzero(&mreq,sizeof(mreq));
    mreq.imr_multiaddr.s_addr =inet_addr("239.255.255.250");
    mreq.imr_interface.s_addr =htonl(INADDR_ANY);
    if( setsockopt(m_ssdpc, IPPROTO_IP,IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) <0 )
    {
        ERR("CSSDPServer::InitSocket failed of setsockopt IP_ADD_MEMBERSHIP");
        return;
    }
}

void CSSDPServer::InitRecvSocket()
{
    RTM("CSSDPServer::InitRecvSocket");
    struct timeval TimeOut;
    TimeOut.tv_sec = 1;
    TimeOut.tv_usec = 0;

    m_ssdps=socket(AF_INET,SOCK_DGRAM,0);
    if( m_ssdps < 0)
    {
        ERR("CSSDPServer::InitSocket failed of create socket 239.255.255.250:1900");
        return;
    }

    bzero(&m_sddr, sizeof(m_sddr));
    m_sddr.sin_family = AF_INET;
    m_sddr.sin_addr.s_addr = INADDR_ANY;
    m_sddr.sin_port = htons(1900);

    if( bind(m_ssdps, (struct sockaddr *)&m_sddr, sizeof(m_sddr)) < 0 )
    {
        ERR("CSSDPServer::InitSocket failed of bind socket 0.0.0.0:1900");
        return ;
    }
    ip_mreq mreq;
    bzero(&mreq,sizeof(mreq));
    mreq.imr_multiaddr.s_addr =inet_addr("239.255.255.250");
    mreq.imr_interface.s_addr =htonl(INADDR_ANY);
    if( setsockopt(m_ssdps, IPPROTO_IP,IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) <0 )
    {
        ERR("CSSDPServer::InitSocket failed of setsockopt IP_ADD_MEMBERSHIP");
        return;
    }
    RTM("CSSDPServer::InitRecvSocket success");

}

void CSSDPServer::Init( bool bBox )
{
    CSSDPServer::Ins( bBox );
}


string CSSDPServer::MakeSSDHeader()
{
    string strMsg="NOTIFY * HTTP/1.1\n"
            "HOST: 239.255.255.250:1900\n"
            "CACHE-CONTROL: max-age=66\n"
            "LOCATION:xml\n"
            "OPT:ns=01\n"
            "01-NLS:0\n"
            "NT: urn:schemas-upnp-org:service:AVTransport:1\n"
            "NTS: ssdp:alive\n"
            "SERVER: Ubuntu/16.04\n"
            "X-User-Agent: redsonic\n"
            "USN:1\n";
    return strMsg;
}


string CSSDPServer::MakeResponseSearchMsg( const string & strUuid)
{

    string strMsg=MakeSSDHeader();

    char szMsg[MAXSSDPSIZE]={0};
    if( m_bBox )
    {
        snprintf( szMsg,MAXSSDPSIZE,
                  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                  "<ProbeMatch>\n"
                  "<mount>%d</mount>\n"
                  "<enable>%d</enable>\n"
                  "<platformip>%s</platformip>\n"
                  "<Uuid>%s</Uuid>\n"
                  "<Types>inquiry</Types>\n"
                  "<DeviceType>CDZSFACEBOX</DeviceType>\n"
                  "<DeviceSN>%s</DeviceSN>\n"
                  "<DeviceName>%s</DeviceName>\n"
                  "<MAC>%s</MAC>\n"
                  "<IPv4Address>%s</IPv4Address>\n"
                  "<IPv4SubnetMask>%s</IPv4SubnetMask>\n"
                  "<IPv4Gateway>%s</IPv4Gateway>\n"
                  "<IPv6Address>::</IPv6Address>\n"
                  "<IPv6Gateway>::</IPv6Gateway>\n"
                  "<IPv6MaskLen>64</IPv6MaskLen>\n"
                  "<DHCP>::</DHCP>\n"
                  "<SoftwareVersion>%s</SoftwareVersion>\n"
                  "<BootTime>%s</BootTime>\n"
                  "<Diskrate>%s</Diskrate >\n"
                  "<Cpurate>%s</Cpurate >\n"
                  "<Memoryrate>%s</Memoryrate >\n"
                  "</ProbeMatch>",
                  CConfiguserv::GetBMount(),
                  CConfiguserv::GetBEnable(),
                  CConfiguserv::GetPlatformIp().c_str(),
                  strUuid.c_str(),
                  CConfiguserv::GetDeviceId().c_str(),
                  CConfiguserv::GetDeviceName().c_str(),
                  CSysInfo::GetdMac().c_str(),
                  CSysInfo::GetIp().c_str(),
                  CSysInfo::GetSubMask().c_str(),
                  CSysInfo::GetGateWay().c_str(),
                  CVersion::GetVersion(),
                  CSysInfo::GetLastRebootTime().c_str(),
                  CSysInfo::GetDiskRate().c_str(),
                  CSysInfo::GetCpuRate().c_str(),
                  CSysInfo::GetMemoryRate().c_str());
    }
    else
    {
        snprintf( szMsg,MAXSSDPSIZE,
                  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                  "<ProbeMatch>\n"
                  "<mount>%d</mount>\n"
                  "<enable>%d</enable>\n"
                  "<platformip>%s</platformip>\n"
                  "<boxip>%s</boxip>\n"
                  "<Uuid>%s</Uuid>\n"
                  "<Types>inquiry</Types>\n"
                  "<DeviceType>CDZSFACEPAD</DeviceType>\n"
                  "<DeviceSN>%s</DeviceSN>\n"
                  "<DeviceName>%s</DeviceName>\n"
                  "<MAC>%s</MAC>\n"
                  "<IPv4Address>%s</IPv4Address>\n"
                  "<IPv4SubnetMask>%s</IPv4SubnetMask>\n"
                  "<IPv4Gateway>%s</IPv4Gateway>\n"
                  "<IPv6Address>::</IPv6Address>\n"
                  "<IPv6Gateway>::</IPv6Gateway>\n"
                  "<IPv6MaskLen>64</IPv6MaskLen>\n"
                  "<DHCP>::</DHCP>\n"
                  "<SoftwareVersion>%s</SoftwareVersion>\n"
                  "<BootTime>%s</BootTime>\n"
                  "<Diskrate>%s</Diskrate >\n"
                  "<Cpurate>%s</Cpurate >\n"
                  "<Memoryrate>%s</Memoryrate >\n"
                  "</ProbeMatch>\n",
                  CConfiguserv::GetBMount(),
                  CConfiguserv::GetBEnable(),
                  CConfiguserv::GetPlatformIp().c_str(),
                  CConfiguserv::GetBoxIp().c_str(),
                  strUuid.c_str(),
                  CConfiguserv::GetDeviceId().c_str(),
                  CConfiguserv::GetDeviceName().c_str(),
                  CSysInfo::GetdMac().c_str(),
                  CSysInfo::GetIp().c_str(),
                  CSysInfo::GetSubMask().c_str(),
                  CSysInfo::GetGateWay().c_str(),
                  CVersion::GetVersion(),
                  CSysInfo::GetLastRebootTime().c_str(),
                  CSysInfo::GetDiskRate().c_str(),
                  CSysInfo::GetCpuRate().c_str(),
                  CSysInfo::GetMemoryRate().c_str());
    }


    strMsg += szMsg;
    return strMsg;
}


//发送ssdp:discover消息
void CSSDPServer::SendMsg(const string&str)
{
    RTM("CSSDPServer::SendMsg msg=%s",str.c_str());

    socklen_t len = sizeof(m_cddr);
    int nLen = sendto(m_ssdps,str.c_str(),str.length(),0,(sockaddr*)&m_cddr,len);
    if( nLen >0 )
    {
        RTM("CSSDPServer::SendMsg success to send to %s msg len=%d",inet_ntoa(m_cddr.sin_addr),nLen);
    }
    else
    {
        RTM("CSSDPServer::SendMsg failed to send msg");
    }
}

void CSSDPServer::RecvMsg()
{
    socklen_t len = sizeof(m_sddr);
    char szMsg[MAXSSDPSIZE]={0};
    int num = recvfrom(m_ssdps,szMsg,MAXSSDPSIZE,0,(sockaddr*)&m_sddr,&len);
    if( num >0 )
    {
        string str;
        //ParseMsg(buf);
    }
}





