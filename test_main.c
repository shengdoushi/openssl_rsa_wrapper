//
//  test_main.c
//  opensslrsatest
//
//  Created by guolihui on 15/8/17.
//  Copyright (c) 2015年 shengdoushi. All rights reserved.
//

#include "test_main.h"
#include "rsa_wrapper.h"

void test(){
    unsigned char to[1280];
    const char* from = "thisis a simple text";
    int from_len = (int)strlen(from);
    
    // key 读取
    GhRSA* private_rsa = gh_rsa_read_private_key("privateKey.pem");
    GhRSA* public_rsa = gh_rsa_read_public_key("publicKey.pem");
    
    // 加密
    int toSize = gh_rsa_encrypt_private_key(private_rsa, from, from_len, to, GhPadding_PKCS1);
    // to 中写入了 toSize
    
    
    // 解密
    char* mingwen[128] = {0};
    int mingwenSize = gh_rsa_decrypt_public_key(public_rsa, to, toSize, mingwen, GhPadding_PKCS1);
}
