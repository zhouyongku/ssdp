/*
 * ===========================================================================
 *
 *       Filename:  SSDPClient.cpp
 *    Description:  客户端设备发现 xml协议
 *        Version:  1.0
 *        Created:  20220406-12:07
 *       Revision:  none
 *       Compiler:  g++
 *         Author:   (zhouyongku),
 *        Company:  
 *
 * ===========================================================================
 */

#include"SSDPClient.h"
#include"uuid/uuid.h"
#include"configuserv.h"
#include"sysinfo/sysinfo.h"
#include"codec/md5.h"




CSSDPClient *CSSDPClient::g_in=NULL;
//全局变量


//解析IP地址
CSSDPClient::CSSDPClient()
{
    m_mt=PTHREAD_MUTEX_INITIALIZER;
    m_cd=PTHREAD_COND_INITIALIZER;

    std::thread t([&]
    {
        InitSocket();
        while(true)
        {

            pthread_mutex_lock(&m_mt); // 拿到互斥锁，进入临界区
            if( m_que.size()<=0 )pthread_cond_wait(&m_cd,&m_mt); // 令线程等待在条件变量上
            pthread_mutex_unlock(&m_mt); // 释放互斥锁

            InerDiscover(m_que.front());

            m_que.pop();

        }


    });
    t.detach();
}

CSSDPClient::~CSSDPClient()
{

}

CSSDPClient *CSSDPClient::Ins()
{
    if( CSSDPClient::g_in == nullptr )
    {
        CSSDPClient::g_in = new CSSDPClient();
    }

    return CSSDPClient::g_in;
}

void CSSDPClient::InerDiscover(const string&str)
{
    SendMsg( str );
    RecvMsg( );
}

void CSSDPClient::InitSocket()
{
    struct timeval TimeOut;
    TimeOut.tv_sec = 1;
    TimeOut.tv_usec = 0;


    m_ssdps=socket(AF_INET,SOCK_DGRAM,0);
    if( m_ssdps < 0)
    {
        ERR("CSSDPClient::InitSocket failed of create socket 239.255.255.250:1900");
        return;
    }

    bzero(&m_sddr, sizeof(m_sddr));
    m_sddr.sin_family = AF_INET;
    m_sddr.sin_addr.s_addr = inet_addr("239.255.255.250");
    m_sddr.sin_port = htons(1900);
    setsockopt(m_ssdps, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut, sizeof(TimeOut));
    ip_mreq mreq;
    bzero(&mreq,sizeof(mreq));
    mreq.imr_multiaddr.s_addr =inet_addr("239.255.255.250");
    mreq.imr_interface.s_addr =htonl(INADDR_ANY);
    if( setsockopt(m_ssdps, IPPROTO_IP,IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) <0 )
    {
        ERR("CSSDPServer::InitSocket failed of setsockopt IP_ADD_MEMBERSHIP");
        return;
    }

//    if( bind(m_ssdps, (struct sockaddr *)&m_sddr, sizeof(m_sddr)) < 0 )
//    {
//        ERR("CSSDPClient::InitSocket failed of bind socket %s:%d",SSDP_MCAST_ADDR,SSDP_PORT);
//    }
}

void CSSDPClient::Discover()
{
    string str=CSSDPClient::Ins()->MakeSearchMsg();
    CSSDPClient::Ins()->NotifyOne(str);

}

void CSSDPClient::ModifyNet(string &strUuid, string &strUid, string &strPwd, string &strMask, string &strGateway, string &strDns)
{
    string str=CSSDPClient::Ins()->MakeModifyNetMsg();
    CSSDPClient::Ins()->NotifyOne(str);
}

void CSSDPClient::ModifyUser(string &strUuid, string &strUid, string &strPwd)
{
    string str=CSSDPClient::Ins()->MakeModifyUserMsg();
    CSSDPClient::Ins()->NotifyOne(str);
}

void CSSDPClient::NotifyOne(const string&str)
{
    RTM("CSSDPClient::NotifyOne quesize=%d",m_que.size());
    pthread_mutex_lock(&m_mt); // 拿到互斥锁，进入临界区
    m_que.push( str );
    pthread_cond_signal(&m_cd); // 通知等待在条件变量上的消费者
    pthread_mutex_unlock(&m_mt); // 释放互斥锁
}

string CSSDPClient::MakeSSDHeader()
{
    string strMsg="M-SEARCH * HTTP/1.1\n";
    strMsg +="HOST: 239.255.255.250:1900\n";
    strMsg +="MAN: \"ssdp:discover\"\n";
    strMsg +="MX: 1\n";
    strMsg +="ST: urn:dial-multiscreen-org:service:dial:1\n";
    strMsg +="USER-AGENT:arm\n";
    return strMsg;
}

string CSSDPClient::MakeSearchMsg()
{

    string strMsg=MakeSSDHeader();
    strMsg +="<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    strMsg +="<Probe>\n";
        strMsg +="  <Uuid>";
        strMsg += CUuid::Genuuid();
        strMsg +="</Uuid>\n";
        strMsg +="  <Types>inquiry</Types>\n";
        strMsg +="  <DeviceType>";
        strMsg += CConfiguserv::GetDeviceMode();
        strMsg +="</DeviceType>\n";
    strMsg +="</Probe>";
    return strMsg;
}

string CSSDPClient::MakeModifyNetMsg()
{
    string strMsg=MakeSSDHeader();
    char szMsg[MAXSSDPSIZE]={0};
    sprintf( szMsg,
    "%s\n"
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<Probe>\n"
    "<Uuid>%s</Uuid>\n"
    "<Types>update</Types>\n"
    "<DeviceSN>%s</DeviceSN>\n"
    "<method>modifyipdns</method>\n"
    "<MAC>%s</MAC>\n"
    "<IPv4Address>%s</IPv4Address>\n"
    "<IPv4SubnetMask>%s</IPv4SubnetMask>\n"
    "<IPv4Gateway>%s</IPv4Gateway>\n"
    "<IPv6Address>::</IPv6Address>\n"
    "<IPv6Gateway>::</IPv6Gateway>\n"
    "<IPv6MaskLen>64</IPv6MaskLen>\n"
    "<DHCP>false</DHCP>\n"
    "<Password>kFnsMaQrzmGi89g+6txepC1RNnZMSi/fA16x+UdjFOmqBmoVCc/zeZ8X6oZmLBdWaXnvwTxjLIQBsLsDP0xjHw==</Password>\n"
    "</Probe>\n",
    strMsg.c_str(),
    CUuid::Genuuid().c_str(),
    CConfiguserv::GetDeviceId().c_str(),
    CSysInfo::GetdMac().c_str(),
    CSysInfo::GetIp().c_str(),
    CSysInfo::GetNetMask().c_str(),
    CSysInfo::GetGateWay().c_str());
    return string(szMsg);

}

string CSSDPClient::MakeModifyUserMsg()
{
    string strMsg=MakeSSDHeader();

    string strPwd=CConfiguserv::GetPwd();
    MD5 m( strPwd.c_str(),strPwd.size());
    string strPwdMd5 = m.toString();

    char szMsg[MAXSSDPSIZE]={0};
    sprintf( szMsg,
    "%s\n"
     "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
     "<Probe>\n"
     "<Uuid>%s>\n"
     "<Types>update</Types>\n"
     "<DeviceSN>%s</DeviceSN>\n"
     "<method>modifypassword</method>\n"
     "<newpassword>%s</newpassword>\n"
     "<Password>%s</Password>\n"
     "</Probe>\n",
    strMsg.c_str(),
    CUuid::Genuuid().c_str(),
    CConfiguserv::GetDeviceId().c_str(),
    strPwdMd5.c_str(),
    strPwdMd5.c_str());
    return string(szMsg);
}


//发送ssdp:discover消息
void CSSDPClient::SendMsg(const string&str)
{
    RTM("CSSDPClient::SendMsg msg=%s",str.c_str());

    socklen_t len = sizeof(m_sddr);
    int nRet=sendto(m_ssdps,str.c_str(),str.length(),0,(sockaddr*)&m_sddr,len);
    if( nRet >0 )
    {
        RTM("CSSDPClient::SendMsg leng=%d",nRet);

    }

    char szMsg[MAXSSDPSIZE]={0};
    nRet = recvfrom( m_ssdps,szMsg,MAXSSDPSIZE,0,(sockaddr*)&m_sddr,&len);
    if( nRet >0 )
    {
        RTM("CSSDPClient::SendMsg RECV MSG=%s",szMsg);
    }
}

void CSSDPClient::RecvMsg()
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





