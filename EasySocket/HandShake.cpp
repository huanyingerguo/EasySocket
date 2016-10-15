//
// Created by baidu on 16/2/1.
// Copyright (c) 2016 isee15. All rights reserved.
//

#include "HandShake.h"

const std::string dataForS3(const unsigned char *data, IMRSA *m_MyRSA) {
    OnePacket *pPkt = (OnePacket *) (data);
    //int packetLength = sizeof(OnePacket) + pPkt->nDestDataLen;
    S2Data *pData = (S2Data *) (pPkt + 1);

    m_MyRSA->saveS2Data(pData->nRootKeyNO, pData->nRootKeyLen, (const unsigned char *) (pData + 1), pData->nDataLen);

    unsigned char *pKey3Data = NULL;
    int pKey3DataLen = 0;
    m_MyRSA->getS3Data(&pKey3Data, &pKey3DataLen);


    struct TPacket
    {
        OnePacket m_header;
        S3Data m_data;
    } pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.m_header.nVer = BIN_PRO_VER_1_0;
    pkt.m_header.nTag = CT_TAG;
    pkt.m_header.ctFlag.nConFlag = CT_FLAG_CON_S3;
    pkt.m_header.nSrcDataLen = sizeof(S3Data) + pKey3DataLen;
    pkt.m_header.nZipDataLen = sizeof(S3Data) + pKey3DataLen;
    pkt.m_header.nDestDataLen = sizeof(S3Data) + pKey3DataLen;
    pkt.m_data.nDataLen = pKey3DataLen;


    int len = sizeof(pkt);
    char *packetData = (char *) malloc(len + pKey3DataLen + 1); //need free
    memcpy(packetData, &pkt, len);
    memcpy(packetData + len, pKey3Data, pKey3DataLen);

    if (pKey3Data) {
        free(pKey3Data);
    }

    std::string ret = std::string(packetData, len + pKey3DataLen);
    free(packetData);
    return ret;
}

const std::string dataForS1() {
    struct TPacketS1
    {
        OnePacket m_header;
        S1Data m_data;
    } pkt;

    memset(&pkt, 0, sizeof pkt);

    //support session
    int sessionlen = 0;

    //int enablefastlogin = 0;

    //session_restore_body session;
    //char * session_device_string[100]; //100 is enough large now


    pkt.m_header.nVer = BIN_PRO_VER_1_0;
    pkt.m_header.nTag = CT_TAG;
    pkt.m_header.ctFlag.nConFlag = CT_FLAG_CON_S1;
    pkt.m_header.nSrcDataLen = sizeof pkt.m_data + sessionlen;
    pkt.m_header.nZipDataLen = sizeof pkt.m_data + sessionlen;
    pkt.m_header.nDestDataLen = sizeof pkt.m_data + sessionlen;

    pkt.m_data.nEPVer = 1; //support fast login

    pkt.m_data.nConMethod[0] = CON_METHOD_A;


    int len = sizeof(pkt) + sessionlen; //sessionlen = session body len + devicestring len
    char *packetData = (char *) malloc(len + 1);
    memcpy(packetData, &pkt, sizeof(pkt)); //add OnePacket and S1
    std::string ret = std::string(packetData, len);
    free(packetData);
    return ret;
}