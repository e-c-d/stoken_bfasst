
#include "stoken_bfasst.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static int
encrypt_aes_128_ecb(EVP_CIPHER_CTX * ctx, unsigned char *plaintext,
                    int plaintext_len, unsigned char *key,
                    unsigned char *ciphertext)
{
    /* Inspired from https://stackoverflow.com/questions/38342326/aes-256-encryption-with-openssl-library-using-ecb-mode-of-operation */
    int len;
    int ciphertext_len;

    /* Init cipher with cryptographic key. */

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        ciphertext_len = -2;
        goto error1;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* Encrypt message */
    if (1 !=
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        ciphertext_len = -3;
        goto error1;
    }

    ciphertext_len = len;

    /* Finalize */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ciphertext_len = -4;
        goto error1;
    }
    ciphertext_len += len;

error1:
    return ciphertext_len;
}


int
stoken_bfasst_generate_passcode(
    struct StokenBruteForceAssist *A
) {
    EVP_CIPHER_CTX *ctx;
    char key[16], key2[16];
    int i, j;
    int pin_len = strlen(A->pin);
    int result;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        result = -1;
        goto error0;
    }

    result = -2;
    char *bl = A->time_blocks;
    if (encrypt_aes_128_ecb(ctx, bl + 16*0, 16, A->seed, key) != 16) goto error1;
    if (encrypt_aes_128_ecb(ctx, bl + 16*1, 16, key, key2) != 16) goto error1;
    if (encrypt_aes_128_ecb(ctx, bl + 16*2, 16, key2, key) != 16) goto error1;
    if (encrypt_aes_128_ecb(ctx, bl + 16*3, 16, key, key2) != 16) goto error1;
    if (encrypt_aes_128_ecb(ctx, bl + 16*4, 16, key2, key) != 16) goto error1;

    uint32_t tokencode =
        (key[A->key_time_offset + 0] << 24) |
        (key[A->key_time_offset + 1] << 16) |
        (key[A->key_time_offset + 2] << 8) |
        (key[A->key_time_offset + 3] << 0);

    /* populate code_out backwards, adding PIN digits if available */
    j = A->digits;
    A->code_out[j--] = 0;
    for (i = 0; j >= 0; j--, i++) {
        uint8_t c = tokencode % 10;
        tokencode /= 10;

        if (i < pin_len)
            c += A->pin[pin_len - i - 1] - '0';
        A->code_out[j] = c % 10 + '0';
    }

    result = 0;

error1:
    EVP_CIPHER_CTX_free(ctx);

error0:
    return result;
}

