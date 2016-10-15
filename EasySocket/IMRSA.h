#ifndef hicore_IMRSA_h
#define hicore_IMRSA_h


#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>


#define MAX_RSA_ROOT_KEY        8

#define RSA_KEY_LEN                1024
#define RSA_KEY_DATA_LEN        4096
#define RSA_ENCRYPT_BUFF_LEN    4096
#define MAX_SYM_KEY_LEN            1024

#include <stdio.h>
#include <string>

class IMRSA
{
public:
    IMRSA();

    ~IMRSA();

    int saveS2Data(int nRootKey, int nRootKeyLen, const unsigned char *p, int nlen);

    int saveS4Data(const unsigned char *p, int nlen);

    int getS3Data(unsigned char **p, int *nlen);


    int aesDecrptData(const unsigned char *pSrc, unsigned lenSrc, unsigned char *pDest, unsigned *lenDest);

    int aesEncrptData(const unsigned char *pSrc, unsigned lenSrc, unsigned char *pDest, unsigned *lenDest);

protected:


public:
    RSA *m_pS2Key;
    RSA *m_pS3Key;
    RSA *m_pRootKey[MAX_RSA_ROOT_KEY];

    RSA *m_paKey;


    AES_KEY m_EKey;
    AES_KEY m_DKey;

    int m_nS3KeyPubDataLen;
    int m_nS3KeyPrvDataLen;
    unsigned char m_szS3KeyPubData[RSA_KEY_DATA_LEN];
    unsigned char m_szS3KeyPrvData[RSA_KEY_DATA_LEN];

    unsigned char m_szSynKey[MAX_SYM_KEY_LEN];

private:
    int InitRK();

    int LeaveRK();
};

#endif



