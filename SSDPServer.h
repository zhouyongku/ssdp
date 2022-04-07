#ifndef CSSDPSERVER_H
#define CSSDPSERVER_H
/*
Author:zhuoyong
Date:2022-04-07
Mark:设备发现服务端代码
*/
#include"common.h"
#include"ssdpparam.h"
#include<sys/epoll.h>

class CSSDPServer
{
public:
    static  void    Init( bool bBox );

protected:
    CSSDPServer( bool bBox );
    ~CSSDPServer();
    void    SendMsg(const string&str);
    void    RecvMsg();
    string  MakeSSDHeader();
    string  MakeResponseSearchMsg( const string & strUuid);
    static  CSSDPServer *Ins( bool bBox );
    void    InitSendSocket();
    void    InitRecvSocket();
    void    ProcesMsg( const char *strMsg );
private:
    static CSSDPServer *    g_in;
    sockaddr_in             m_sddr ;
    sockaddr_in             m_cddr ;
    int                     m_ssdps;
    int                     m_ssdpc;
    bool                    m_bBox;
    queue<string>           m_que;
    pthread_cond_t          m_cd;
    pthread_mutex_t         m_mt;
};

#endif // CSSDPSERVER_H
