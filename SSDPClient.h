/*
Author:zhuoyong
Date:2022-04-07
Mark:人脸识别客户端代码
*/

#ifndef CSSDPCLIENT_H
#define CSSDPCLIENT_H
#include"common.h"


class CSSDPClient
{
public:
    static  void    Discover();
    //最终加密后的pssword=：md5(<uuid>:<uid>:<pwd>)
    static  void    ModifyNet(string &strUuid,string&strUid,string&strPwd,string &strMask,string&strGateway,string &strDns);
    //strCryptPwd=base64(AES(pwd))
    static  void    ModifyUser(string &strUuid,string&strUid,string&strPwd);
protected:
    CSSDPClient();
    ~CSSDPClient();
    void    SendMsg(const string&str);
    void    RecvMsg();
    void    NotifyOne(const string&str);
    string  MakeSSDHeader();
    string  MakeSearchMsg();
    string  MakeModifyNetMsg();
    string  MakeModifyUserMsg();
    static  CSSDPClient *Ins();
    void    InerDiscover(const string&str);
    void    InitSocket();
private:
    static CSSDPClient *    g_in;
    sockaddr_in             m_sddr ;
    int                     m_ssdps;
    queue<string>           m_que;
    pthread_cond_t          m_cd;
    pthread_mutex_t         m_mt;
};

#endif // CSSDPCLIENT_H
