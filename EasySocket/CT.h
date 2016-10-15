#ifndef __CT_H__
#define __CT_H__


//#define INVALID_USERID		0			//无效的用户ID	no use


#define MAX_METHOD            4

#define SYM_METHOD_NONE        0            //无加密
#define SYM_METHOD_AES        1            //AES加密策略
#define SYM_METHOD_DES        2            //Des加密策略

#define UNSYM_METHOD_NONE    0            //无加密
#define UNSYM_METHOD_RSA    1            //RSA加密策略

#define ZIP_METHOD_NONE            0
#define ZIP_METHOD_COMPRESS        1            //zlib compress方法

#define CON_METHOD_NULL            0        //非法数据
#define CON_METHOD_NONE            1        //无压缩、无加密
#define CON_METHOD_A            2        //RSA交换秘钥 AES加密 ZIP(compress)压缩
//#define CON_METHOD_B			2		//RSA交换秘钥 DES加密 ZIP(compress)压缩


//self sizeof
#define PACK16_SIZEOF(x)        ((x | 0xf) + 1)
#define PACK16_SIZEOF_EX(x)        ((x | 0xf) + 17)

#define MAX_CT_BUFF_SIZE        (128 * 1024)
#define MAX_CT_PACKET_SIZE        (64 * 1024)        //客户端发送过来的最大包尺寸
#define MAX_TC_BUFF_SIZE        (1048 * 1024)
#define MAX_TC_PACKET_SIZE        (1024 * 1024)        //服务器发向客户端的最大包尺寸

#define MIN_CT_COMPRESS_SIZE    (1024)            //启动压缩临界尺寸
#define MIN_TC_COMPRESS_SIZE    (1024)

#define RANDOM_KEY_SEED_LEN        (16)

/// 会话建立阶段
enum ECtFlagConnectStates
{
    /// 会话第一步(握手)
            CT_FLAG_CON_S1 = 0x0,
    /// 会话第二步(握手)
            CT_FLAG_CON_S2 = 0x1,
    /// 会话第三步(握手)
            CT_FLAG_CON_S3 = 0x2,
    /// 会话第四步(握手)
            CT_FLAG_CON_S4 = 0x3,
    /// 心跳包
            CT_FLAG_KEEPALIVE = 0x5,
    /// 会话进入正常流程
            CT_FLAG_CON_OK = 0x7
};

///	值为'IMV1'
#define CT_TAG                        (0x494d5631)
/// ver 1.0
#define BIN_PRO_VER_1_0                0x00010000

#define BIN_PRO_VER_2_0                0x00020000

/// 发送标记
enum ECtSendFlags
{
    /// 标记登录，目前没有使用这个值，而是固定握手之后的两个包属于登录阶段
            CT_SEND_FLAG_LOGIN = 0x00000001,
    /// 标记登出
            CT_SEND_FLAG_LOGOUT = 0x00000002,

    CT_SEND_FLAG_LOGIN_REQ = 17,  //for public account
    CT_SEND_FLAG_LOGIN_RESP = 18,  //for public account
    CT_SEND_FLAG_OK = 19   //for public account

};

#pragma pack(push, 1)

/// 传输标记
typedef struct _CT_FLAG
{
    /// 会话状态标示，参考 #ECtFlagConnectStates
    unsigned int nConFlag:3;
    /// 是否加密,0--不加密;1--加密
    unsigned int bEncrypt:1;
    /// 是否压缩算法,0--不压缩;1--压缩
    unsigned int bCompress:1;
    /// 客户端告诉服务器是否应该发送心跳，服务器表示一个心跳包
    unsigned int bHeartBeat:1;

    /// 保留使用
    //with public account release,  use this field for mark the public account pack
    unsigned int nReserved26:26;
} CT_Flag, *PCT_Flag;

// 原始数据 -> 压缩 -> 压缩数据 -> 加密 ->加密数据
// 加密数据 -> 解密 -> 压缩数据 -> 解压 ->原始数据
/// 客户端-TS 传输包格式
typedef struct _ONEPACKET_
{
    /// 协议版本，当前版本为 #BIN_PRO_VER_1_0
    unsigned int nVer;
    /// 标记，参考 #CT_TAG
    unsigned int nTag;
    /// 传输标记
    CT_Flag ctFlag;
    /// 原始数据长度
    unsigned int nSrcDataLen;
    /// 压缩后数据长度
    unsigned int nZipDataLen;
    /// 加密后数据长度
    unsigned int nDestDataLen;
    /// 发送标志, 参考 #ECtSendFlags
    unsigned int nSendFlag;
    /// 协议种类，暂为0
    unsigned int nCategory;

    /// 保留字段
    unsigned int nReserved1;
    /// 保留字段
    unsigned int nReserved2;

//	unsigned char			Data[];			//包体数据
} OnePacket, *POnePacket;

//临时秘钥数据

#define TEMP_KEY_SIGN1        "BaiduIM Key Begin"
#define TEMP_KEY_SIGN2        "BaiduIM Key End"

#define MAX_KEY_LEN            1024

//support session
#define VERSION_LENGTH 16
#define PLATFORM_LENGTH 10
#define SESSIONID_LENGTH 37   // 36 + '\0'
typedef struct session_restore_body_t
{
    unsigned char version[VERSION_LENGTH];
    unsigned char clientType;
    unsigned char platform[PLATFORM_LENGTH];
    unsigned char sessionid[SESSIONID_LENGTH];  //d5550dad-82e9-4a72-9bb1-4537d1a3ec0c

    unsigned char devicedatalen;
    unsigned int reserved1;
    unsigned int reserved2;
    unsigned int reserved3;

    //device string
    //
} session_restore_body;  //size = 16+1+10+37 +1+4+4+4 + n


//会话协商第一步数据
typedef struct _S1_DATA
{
    unsigned char nEPVer;                        //交换秘钥协议版本			当前版本为1
    unsigned char nConMethod[MAX_METHOD];        //压缩加密方法

    unsigned int nReserved1;                  //这个字段被 gateway 使用，用来上报客户端ip 给hiserver
    unsigned int nConnectType;              //以前是保留字段，为0， 如果这次登录是快速登录，那么为 1

    unsigned int nDataLen;                    //后续数据长度
//	unsigned char			szData[];					//具体数据
} S1Data, *PS1Data;

//会话协商第二步数据
typedef struct _S2_DATA
{
    unsigned char nConMethod;            //会话策略

    unsigned char nRootKeyNO;            //RootKey编号
    unsigned int nRootKeyLen;        //RootKey长度

    unsigned int nReserved1;            //保留字段，目前为0
    unsigned int nReserved2;            //保留字段，目前为0

    unsigned int nDataLen;            //后续数据长度
//	unsigned char			szData[];			//具体数据
} S2Data, *PS2Data;

//会话协商第三步数据
typedef struct _S3_DATA
{
    unsigned int nReserved1;            //保留字段，目前为0
    unsigned int nReserved2;            //保留字段，目前为0

    unsigned int nDataLen;            //后续数据长度
//	unsigned char			szData[];
} S3Data, *PS3Data;

//会话协商第四步数据
typedef struct _S4_DATA
{
    /// 随机key，本次连接期间用来对密码做hash
    unsigned char seed[RANDOM_KEY_SEED_LEN];
    /// Keep-Alive间隔时间
    unsigned int nKeepAliveSpace;
    /// 保留字段
    unsigned int nReserved1;
    /// 保留字段
    unsigned int nReserved2;
    /// 后续数据长度，S4后面会有一个可选的xml，表示一些数据属性
    unsigned int nDataLen;
//	unsigned char			szData[];			//具体数据
/*
<ts_config><heartbeat sign_interval="40" echo_timeout="80"/></ts_config>
*/
} S4Data, *PS4Data;

#pragma pack(pop)


#endif //__CT_H__
