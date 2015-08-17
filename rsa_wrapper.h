//
//  rsa_wrapper.h
//  opensslrsatest
//
//  Created by guolihui on 15/8/17.
//  Copyright (c) 2015年 shengdoushi. All rights reserved.
//

#ifndef __opensslrsatest__rsa_wrapper__
#define __opensslrsatest__rsa_wrapper__

typedef void GhRSA;

enum enGhRSAKeyType {
    GhRSAKeyType_PublicKey,
    GhRSAKeyType_PrivateKey
};

enum enGhPaddinType {
    GhPadding_None,
    GhPadding_PKCS1,
    GhPadding_SSLV23
};

void GhRSA_free(GhRSA* rsa);

/**
 *  读取pem的key
 *
 *  @param filename 文件路径
 *
 *  @return RSA key
 *
 *  @note 返回的 key 记得用 GhRSA_free() 释放掉
 */
GhRSA* gh_rsa_read_public_key(const char* filename);
GhRSA* gh_rsa_read_private_key(const char* filename);
GhRSA* gh_rsa_read_key(enum enGhRSAKeyType keyType, const char* filename);

/**
 *  自动生成一个key
 *
 *  @param bit_size 位数
 *
 *  @return RSA key
 *
 *  @note 返回的 key 记得用 GhRSA_free() 释放掉。
 *        返回一个 RSA_F4 的key
 */
GhRSA* gh_rsa_generate_key(int bit_size);

/**
 *  加密
 *
 *  @param rsa          RSA 的 key
 *  @param from         源buffer
 *  @param from_len     源buffer长度
 *  @param to           写出bufffer
 *  @param padding_type padding
 *
 *  @return 加密后长度， -1 为出错
 */
int gh_rsa_encrypt_public_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type);
int gh_rsa_encrypt_private_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type);
int gh_rsa_encrypt(enum enGhRSAKeyType keyType, GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type);

/**
 *  解密
 *
 *  @param rsa          RSA 的 key
 *  @param from         源buffer
 *  @param from_len     源buffer长度
 *  @param to           写出bufffer
 *  @param padding_type padding
 *
 *  @return 解密后长度， -1 为出错
 */
int gh_rsa_decrypt_public_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type);
int gh_rsa_decrypt_private_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type);
int gh_rsa_decrypt(enum enGhRSAKeyType keyType, GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type);

#endif /* defined(__opensslrsatest__rsa_wrapper__) */
