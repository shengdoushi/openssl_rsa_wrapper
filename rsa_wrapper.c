//
//  rsa_wrapper.c
//  opensslrsatest
//
//  Created by guolihui on 15/8/17.
//  Copyright (c) 2015年 shengdoushi. All rights reserved.
//

#include "rsa_wrapper.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>

int gh_private_rsa_padding_type_from(enum enGhPaddinType paddingType){
    switch (paddingType) {
        case GhPadding_PKCS1:
            return RSA_PKCS1_PADDING;
            break;
        case GhPadding_SSLV23:
            return RSA_SSLV23_PADDING;
            break;
            
        case GhPadding_None:
        default:
            return RSA_NO_PADDING;
            break;
    }
}

RSA* GhRSA_real(GhRSA* rsa){
    return (RSA*)rsa;
}

void GhRSA_free(GhRSA* rsa){
    RSA_free((RSA*)rsa);
}

// 读取pem
GhRSA* gh_rsa_read_key(enum enGhRSAKeyType keyType, const char* filename){
    RSA* rsa = NULL;
    if (GhRSAKeyType_PublicKey == keyType){
        BIO* key = BIO_new(BIO_s_file());
        if (BIO_read_filename(key, filename) <= 0){
            BIO_free_all(key);
            return NULL;
        }
        rsa = PEM_read_bio_RSAPublicKey(key, NULL, NULL, NULL);
        BIO_free_all(key);
    }else if (GhRSAKeyType_PrivateKey == keyType){
        FILE* file = fopen(filename, "rb");
        if (!file) return NULL;
        
        if (GhRSAKeyType_PrivateKey == keyType)
            rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
        fclose(file);
    }
    return rsa;
}
GhRSA* gh_rsa_read_public_key(const char* filename){
    return gh_rsa_read_key(GhRSAKeyType_PublicKey, filename);
}

GhRSA* gh_rsa_read_private_key(const char* filename){
    return gh_rsa_read_key(GhRSAKeyType_PrivateKey, filename);
}

// 自动生成
GhRSA* gh_rsa_generate_key(int bit_size) {
    // 另外有 RSA_3 参数
    RSA* rsa =  RSA_generate_key(bit_size,RSA_F4,NULL,NULL);
    return rsa;
}

// 加解密
int gh_rsa_decrypt(enum enGhRSAKeyType keyType, GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type) {
    if (from == NULL && to == NULL) return -1;
    int status = RSA_check_key(GhRSA_real(rsa));
    if (!status) {
        return -1;
    }
    int rsaPadding = gh_private_rsa_padding_type_from(padding_type);
    if (GhRSAKeyType_PublicKey == keyType)
        status =  RSA_public_decrypt(from_len,from,to, GhRSA_real(rsa),  rsaPadding);
    else if (GhRSAKeyType_PrivateKey == keyType)
        status = RSA_private_decrypt(from_len, from, to, GhRSA_real(rsa), rsaPadding);
    else
        status = -1;
    return status;
}
int gh_rsa_decrypt_public_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type) {
    return gh_rsa_decrypt(GhRSAKeyType_PublicKey, rsa, from, from_len, to, padding_type);
}
int gh_rsa_decrypt_private_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type) {
    return gh_rsa_decrypt(GhRSAKeyType_PublicKey, rsa, from, from_len, to, padding_type);
}

//
int gh_rsa_encrypt(enum enGhRSAKeyType keyType, GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type) {
    if (from == NULL && to == NULL) return -1;
    int status = RSA_check_key(GhRSA_real(rsa));
    if (!status) {
        return -1;
    }
    int rsaPadding = gh_private_rsa_padding_type_from(padding_type);
    if (GhRSAKeyType_PublicKey == keyType)
        status =  RSA_public_encrypt(from_len,from,to, GhRSA_real(rsa),  rsaPadding);
    else if (GhRSAKeyType_PrivateKey == keyType)
        status = RSA_private_encrypt(from_len, from, to, GhRSA_real(rsa), rsaPadding);
    else
        status = -1;
    return status;
}
int gh_rsa_encrypt_public_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type) {
    return gh_rsa_encrypt(GhRSAKeyType_PublicKey, rsa, from, from_len, to, padding_type);
}
int gh_rsa_encrypt_private_key(GhRSA* rsa, const unsigned char* from, int from_len, unsigned char* to, enum enGhPaddinType padding_type) {
    return gh_rsa_encrypt(GhRSAKeyType_PrivateKey, rsa, from, from_len, to, padding_type);
}
