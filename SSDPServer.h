#ifndef CSSDPSERVER_H
#define CSSDPSERVER_H
/*
Author:zhuoyong
Date:2022-04-07
Mark:设备发现服务端代码
*/
#include<string>
#include<string.h>
#include<queue>
#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<thread>
#include<chrono>
#include<unistd.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<net/if.h>
#include<pthread.h>
#include<fcntl.h>
#include<mutex>
#define ERR printf
#define RTM printf
#define MAXSSDPSIZE 1024

using namespace std;


class CSSDPServer
{
public:
    static  void    Init(  );

protected:
    CSSDPServer(  );
    ~CSSDPServer();
    void    SendMsg(const string&str);
    void    RecvMsg();
    string  MakeSSDHeader();
    string  MakeResponseSearchMsg( );
    static  CSSDPServer *Ins();
    void    InitSendSocket();
    void    InitRecvSocket();
    void    ProcesMsg( const char *strMsg );
private:
    static CSSDPServer *    g_in;
    sockaddr_in             m_sddr ;
    sockaddr_in             m_cddr ;
    int                     m_ssdps;
    int                     m_ssdpc;
    queue<string>           m_que;
    pthread_cond_t          m_cd;
    pthread_mutex_t         m_mt;
};

#endif // CSSDPSERVER_H
