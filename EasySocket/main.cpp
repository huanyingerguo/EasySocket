//
//  main.cpp
//  EasySocket
//
//  Created by baidu on 5/16/16.
//  Copyright © 2016 isee15. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#include <string>

#include <zlib.h>
#include <map>
#include <iostream>
#include <sstream>
#include <sys/timeb.h>

#include "HandShake.h"
#include "pugixml.hpp"
#include "md5.hpp"

#define BUFSIZE 1024*1024    /* size of buffer sent */

long long seq = 0;

const char *account = "chatfriend71";
const char *passowrd = "chatfriend";
long long fromUid = 1227623668;
long long toUid = 491269311;

class HiPackage
{
public:
    std::string protocol;
    std::string method;
    std::string req_Ack;
    std::string version;
    long long seq;

    std::string body;

    /*s
     msg R 1.0 1243
     method:msg_requst
     imid:12312312
     
     <body>
       <msg>"hellow word!"</msg>
     </body>
    */
    void parse(std::string &s) {
        char a[20];
        char b[20];
        char c[20];
        long long d;
        sscanf(s.c_str(), "%s %s %s %lld", a, b, c, &d);
        protocol = std::string(a);
        req_Ack = std::string(b);
        version = std::string(c);
        seq = d;

        std::map<std::string, std::string> headers;
        std::istringstream f(s);
        std::string line;
        while (std::getline(f, line)) {
            //std::cout << line << std::endl;
            if (line.empty() || line == "\r\n\r\n")
                break;
            auto key_value_sep = line.find(":"); // do not split by space

            auto key = line.substr(0, key_value_sep);

            auto value = line.substr(key_value_sep + 1, // skip ":"
                    line.size() - key.size() - 2); // size less key,

            // set header
            headers[key] += value;
        }
        method = headers["method"];
        auto bodyLoc = s.find("\r\n\r\n");
        body = s.substr(bodyLoc + 4, s.length() - bodyLoc - 4);
    }
};

const std::string sendProtocolData(const unsigned char *outgoingData, unsigned int datalength, IMRSA &imrsa) {
    OnePacket header;
    memset(&header, 0, sizeof(header));
    header.nVer = BIN_PRO_VER_1_0;
    header.nTag = CT_TAG;
    header.ctFlag.bCompress = datalength > MIN_CT_COMPRESS_SIZE ? 1 : 0;
    header.ctFlag.bEncrypt = 1;
    header.ctFlag.nConFlag = CT_FLAG_CON_OK;
    header.ctFlag.nReserved26 = 0;
    header.nSrcDataLen = datalength;
    header.nZipDataLen = datalength;
    header.nDestDataLen = datalength;

    //int desttype = 0;
    unsigned char pBufSendZip[MAX_CT_BUFF_SIZE];
    unsigned char *compressData = (unsigned char *) outgoingData;
    if (datalength > MIN_CT_COMPRESS_SIZE) {

        //need compression
        unsigned long iZiped = header.nZipDataLen;

        memset(pBufSendZip, 0, MAX_CT_BUFF_SIZE);
        compress(pBufSendZip, &iZiped, outgoingData, datalength);
        header.nZipDataLen = (unsigned int) iZiped;

        if (header.nZipDataLen > MAX_CT_PACKET_SIZE) {
            //data too long
            printf("\nsend data: data too long, srclen: %d, nZipDataLen: %d", header.nSrcDataLen, header.nZipDataLen);
        }

        compressData = pBufSendZip;
    }

    //encrypt
    unsigned char pBufSendEncrypt[MAX_CT_BUFF_SIZE];
    memset(pBufSendEncrypt, 0, MAX_CT_BUFF_SIZE);

    imrsa.aesEncrptData(compressData, header.nZipDataLen, pBufSendEncrypt, &header.nDestDataLen);


    //send
    size_t len = sizeof(header) + header.nDestDataLen;
    char *data = (char *) malloc(len);
    memcpy(data, &header, sizeof(header));
    memcpy(data + sizeof(header), pBufSendEncrypt, header.nDestDataLen);

    std::string ret = std::string(data, len);
    free(data);
    return ret;

}

void toPacket(const unsigned char *rawData, HiPackage *outPackage, IMRSA &imrsa) {
    OnePacket *pPkt = (OnePacket *) (rawData);
    //int packetLength = sizeof(OnePacket) + pPkt->nDestDataLen;
    unsigned char *pData = NULL;
    unsigned int iLen = 0;

    unsigned char pBufRecvDecrypt[MAX_TC_BUFF_SIZE];
    memset(pBufRecvDecrypt, 0, MAX_TC_BUFF_SIZE);

    imrsa.aesDecrptData(rawData + sizeof(OnePacket), pPkt->nDestDataLen,
            pBufRecvDecrypt, &iLen);

    pData = pBufRecvDecrypt;

    if (((pPkt->nZipDataLen + 15) & 0xfffffff0) == iLen) {
        iLen = pPkt->nZipDataLen;

    }
    if (pPkt->ctFlag.bCompress) {

        unsigned char pBufRecvZip[MAX_TC_BUFF_SIZE];
        memset(pBufRecvZip, 0, MAX_TC_BUFF_SIZE);

        uLongf nUnzipLen = pPkt->nSrcDataLen;
        uncompress(pBufRecvZip, &nUnzipLen, pData, iLen);
        pData = pBufRecvZip;
        iLen = (unsigned int) nUnzipLen;
    }
    std::cout << std::endl << "recv begin-------------------" << std::endl;
    std::cout << std::string((char *) pData, iLen);
    std::cout << std::endl << "recv end---------------------" << std::endl;

    std::string recv((char *) pData, iLen);
    outPackage->parse(recv);
}

const std::string sendMessage(long long fromUid, long long toUid, std::string &msg, IMRSA &imrsa) {
    struct timeb t1;
    ftime(&t1);

    long long ms = t1.time * 1000 + t1.millitm;//毫秒数

    long long basemsgid = ms & 0x00000000FFFFFFFF;

    const char *msgFormat = "msg 1.1 R %d\r\nmethod:msg_request\r\ntype:1\r\nuid:%lld\r\nfrom:%lld\r\nto:%lld\r\ntime:%lld\r\nbasemsgid:%lld\r\nmsgid:0\r\nsubid:0\r\nnextsubid:0\r\nContent-Length:%d\r\nContent-Type:text\r\n\r\n%s";
    const char *msgBodyFormat = "<msg><font n=\"宋体\" s=\"10\" b=\"0\" i=\"0\" ul=\"0\" c=\"0\" cs=\"134\"/><text c=\"%s\"/></msg>";
    char msgBody[2048] = {0};
    sprintf(msgBody, msgBodyFormat, msg.c_str());

    char msgData[2048] = {0};
    sprintf(msgData, msgFormat, seq++, fromUid, fromUid, toUid, ms, basemsgid, strlen(msgBody), msgBody);

//    const std::string msgPacket = sendProtocolData((const unsigned char *) msgData, (unsigned int) strlen(msgData),imrsa);
//    return msgPacket;
    return std::string(msgData);
}


int main(int argc, char *argv[]) {
    //"gbp4.im.baidu.com", "1863"

    IMRSA imrsa;

    struct addrinfo hints;
    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *server;
    int retCode = getaddrinfo("gbp4.im.baidu.com", "1863", &hints, &server);
    if (retCode < 0) {
        printf("getaddrinfo ret: %d", retCode);
        exit(-1);
    }

    int sockfd = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
    if (sockfd < 0) {
        printf("socket ret: %d", sockfd);
        exit(-1);
    }

    retCode = connect(sockfd, server->ai_addr, server->ai_addrlen);
    if (retCode < 0) {
        printf("connect ret: %d", retCode);
        exit(-1);
    }

    const std::string &s1 = dataForS1();

    std::cout << "send s1:---------------------" << std::endl;
    std::cout.write(s1.c_str(), s1.length());
    std::cout << std::endl;

    ssize_t rc = write(sockfd, s1.c_str(), s1.length());
    if (rc < 0) {
        printf("write s1 ret: %d", retCode);
        exit(-1);
    }

    char recvBuf[BUFSIZE];
    rc = read(sockfd, recvBuf, BUFSIZE);
    if (rc < 0) {
        printf("read s2 ret: %d", retCode);
        exit(-1);
    }

    std::cout << "recv s2:---------------------" << std::endl;
    std::cout.write(recvBuf, rc);
    std::cout << std::endl;

    const std::string &s3 = dataForS3((const unsigned char *) recvBuf, &imrsa);

    std::cout << "send s3:---------------------" << std::endl;
    std::cout.write(s3.c_str(), s3.length());
    std::cout << std::endl;

    rc = write(sockfd, s3.c_str(), s3.length());
    if (rc < 0) {
        printf("write s3 ret: %d", retCode);
        exit(-1);
    }

    memset(recvBuf, 0, BUFSIZE);
    rc = read(sockfd, recvBuf, BUFSIZE);
    if (rc < 0) {
        printf("read s4 ret: %d", retCode);
        exit(-1);
    }

    std::cout << "recv s4:---------------------" << std::endl;
    std::cout.write(recvBuf, rc);
    std::cout << std::endl;

    {
        OnePacket *pPkt = (OnePacket *) recvBuf;
        S4Data *pData = (S4Data *) (pPkt + 1);
        //保存seed,用于加密登录密码
        //memcpy(key_seed, pData->seed, RANDOKEY_SEED_LEN);

        if (-1 == imrsa.saveS4Data((const unsigned char *) (pData + 1), pData->nDataLen)) {
            std::cout << "error" << std::endl;
        }

        //unsigned int keepAliveInterval = pData->nKeepAliveSpace;
        unsigned char *pEndPkt = (unsigned char *) (pPkt + 1) + pPkt->nDestDataLen;
        unsigned char *pEndKey = (unsigned char *) (pData + 1) + pData->nDataLen;

        unsigned int iLen = (unsigned int) (pEndPkt - pEndKey);
        std::string tsConfig((char *) pEndKey, iLen);
        std::cout << std::endl << "ts config: " << tsConfig << std::endl;

        const char *dataFormat = "security 2.0 R %lld\nmethod:verify\nlid:%s\nlid_type:1\ntype:1\n\r\n";
        char data[2048] = {0};
        sprintf(data, dataFormat, seq++, account);

        const std::string &security = sendProtocolData((unsigned const char *) data, (int) strlen(data), imrsa);
        std::cout << "send security:---------------------" << std::endl;
        std::cout << data;
        std::cout << std::endl;

        rc = write(sockfd, security.c_str(), security.length());
        if (rc < 0) {
            printf("write security ret: %d", retCode);
            exit(-1);
        }

        memset(recvBuf, 0, BUFSIZE);
        rc = read(sockfd, recvBuf, BUFSIZE);
        if (rc < 0) {
            printf("read security ret: %d", retCode);
            exit(-1);
        }

    }

    {

        HiPackage pack;
        toPacket((unsigned char *) recvBuf, &pack, imrsa);


        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_string(pack.body.c_str());
        if (result.status == pugi::status_ok) {
            pugi::xml_node root = doc.child("verify");
            auto vurl = root.attribute("v_url").value();
            auto vtime = root.attribute("v_time").value();
            auto vperiod = root.attribute("v_period").value();
            auto vcode = root.attribute("v_code").value();
            std::cout << vurl << std::endl;


            const char *loginFormat = "login 4.9 R %lld\r\nmethod:login\r\ncontent-length:%d\r\ncontent-type:text\r\nlid_type:1\r\npriority:20\r\nv_code:%s\r\nv_period:%s\r\nv_time:%s\r\nv_url:%s\r\n\r\n%s";

            const char *loginBodyFormat = "<login>"\
            "<user account=\"%s\" password=\"%s\" imversion=\"1,7,1,0\" client_type=\"1\" kickout=\"true\" redirect_times=\"0\" platform=\"mac\" device=\"10.11.2|sunke02的MacBook Pro\" get_cookie=\"1\" />"\
            "</login>";

            char loginBody[2048] = {0};
            sprintf(loginBody, loginBodyFormat, account, md5(md5(passowrd)).c_str());

            char loginData[2048] = {0};
            sprintf(loginData, loginFormat, seq++, strlen(loginBody), vcode, vperiod, vtime, vurl, loginBody);

            const std::string &loginSend = sendProtocolData((unsigned const char *) loginData, (int) strlen(loginData), imrsa);

            std::cout << "send login:--------------" << std::endl;
            std::cout << loginData;
            std::cout << std::endl;

            rc = write(sockfd, loginSend.c_str(), loginSend.length());
            if (rc < 0) {
                printf("write login ret: %d", retCode);
                exit(-1);
            }

            memset(recvBuf, 0, BUFSIZE);
            rc = read(sockfd, recvBuf, BUFSIZE);
            if (rc < 0) {
                printf("read login ret: %d", retCode);
                exit(-1);
            }

            toPacket((unsigned char *) recvBuf, &pack, imrsa);
        }
    }
    std::string msg;
    while (1) {
        std::cout << "Enter msg(q as quit): "; // no flush needed
        std::getline(std::cin, msg);
        if (msg == "q") {
            break;
        }
        const std::string &msgPacket = sendMessage(fromUid, toUid, msg, imrsa);
        const std::string &msgSend = sendProtocolData((unsigned const char *) msgPacket.c_str(), (int) msgPacket.length(), imrsa);

        std::cout << "send message:--------------" << std::endl;
        std::cout << msgPacket;
        std::cout << std::endl;

        rc = write(sockfd, msgSend.c_str(), msgSend.length());
        if (rc < 0) {
            printf("write message ret: %d", retCode);
            exit(-1);
        }

        memset(recvBuf, 0, BUFSIZE);
        rc = read(sockfd, recvBuf, BUFSIZE);
        if (rc < 0) {
            printf("read message ret: %d", retCode);
            exit(-1);
        }

        HiPackage pack;
        toPacket((unsigned char *) recvBuf, &pack, imrsa);
    }


    close(sockfd);

    freeaddrinfo(server);

    return 0;
}
