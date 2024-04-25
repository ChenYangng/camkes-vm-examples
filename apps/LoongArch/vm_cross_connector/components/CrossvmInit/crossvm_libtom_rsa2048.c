#include <tomcrypt.h>
#include <stdio.h>

// #define NUM_TESTS 1000  // 定义测试次数

int run(void) {
    int err, hash_idx, prng_idx;
    rsa_key key;
    unsigned long len, rsa_len, outlen;
    unsigned char out[256], decrypted[256]; // 对于2048位RSA，加密输出将是256字节
    unsigned char plaintext[] = "Hello, World!"; // 测试的明文

    // 初始化多精度数学库
    ltc_mp = ltm_desc;

    // 注册算法
    register_all_ciphers();
    register_all_hashes();
    register_all_prngs();

    // 获取PRNG索引
    prng_idx = find_prng("sprng");
    if (prng_idx == -1) {
        printf("sprng PRNG not found.\n");
        return -1;
    }

    // 生成RSA密钥
    if ((err = rsa_make_key(NULL, prng_idx, 256, 65537, &key)) != CRYPT_OK) {
        printf("rsa_make_key error: %s\n", error_to_string(err));
        return -1;
    }

    len = sizeof(plaintext) - 1;
    rsa_len = sizeof(out);  // 密文长度

    // 先进行一次加密以生成密文
    if ((err = rsa_encrypt_key_ex(plaintext, len, out, &rsa_len, NULL, 0,
                                  NULL, prng_idx, hash_idx, LTC_PKCS_1_V1_5, &key)) != CRYPT_OK) {
        printf("rsa_encrypt_key_ex error: %s\n", error_to_string(err));
        rsa_free(&key);
        return -1;
    }

    int stat;


    while(1) {
        ready_wait();
        outlen = sizeof(decrypted);  // 设置解密输出的最大长度
        if ((err = rsa_decrypt_key_ex(out, rsa_len, decrypted, &outlen, NULL, 0,
                                      hash_idx, LTC_PKCS_1_V1_5, &stat, &key)) != CRYPT_OK) {
            printf("rsa_decrypt_key_ex error: %s\n", error_to_string(err));
            rsa_free(&key);
            return -1;
        }
        done_emit_underlying();
    }


    // // 打印测试结果
    // double total_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    // printf("Total time for %d RSA-2048 private key decryptions: %f seconds\n", NUM_TESTS, total_time);
    // printf("Average time per decryption: %f milliseconds\n", (total_time / NUM_TESTS) * 1000);

    // 清理
    rsa_free(&key);

    return 0;
}

