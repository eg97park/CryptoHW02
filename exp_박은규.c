/**
 * @file exp_박은규.c
 * @author 박은규 (ekpark97.dev@gmail.com)
 * @brief L2R Modular Exponentiation
 * @version 0.1
 * @date 2022-08-12
 * @build gcc -o exp "exp_박은규.c" -L.. -lcrypto -I../include/crypto -g
 * @exec ./exp [a] [e] [m]
 */

#include <stdio.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * @brief Calculate r = a**e mod m using L2R modular exponentiation.
 * 
 * @param[out] r reuslt.
 * @param[in] a base.
 * @param[in] e exponent value.
 * @param[in] m modular value.
 * @return int 0 if there were no errors.
 */
int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m){
        const int k = BN_num_bits(e);
        const int kb = BN_num_bytes(e);
        uint8_t gap = kb * 8 - k;

        unsigned char* eCharArray = (unsigned char*)malloc(sizeof(unsigned char) * kb);
        if (eCharArray == NULL){
                return 1;
        }

        BN_bn2bin(e, eCharArray);

        // Write n = (bk−1 bk−2 ··· b0)
        uint8_t eArray[k];
        for(int i = 0; i < k + gap; i++){
                if (i < gap){
                        continue;
                }
                eArray[i - gap] = (eCharArray[i / 8] >> (7 - (i % 8))) & 0x01;
        }

        BN_CTX* ctx = BN_CTX_new();
        if (ctx == NULL){
                if(eCharArray != NULL) free(eCharArray);
                eCharArray = NULL;
                return 1;
        }

        // A <- a
        BIGNUM* _a = BN_dup(a);

        // For i = k - 2 to 0 do:
        for (int i = k - 2; 0 <= i; i--){
                // A <- A**2 mod m
                BN_mod_mul(_a, _a, _a, m, ctx);

                // if bi = 1 then A <- A * a mod m
                if(eArray[(0 - i) + k - 1] == 1){
                        BN_mod_mul(_a, _a, a, m, ctx);        
                }
        }

        /** mapping my array index to lecture note 26p.
         * lecture note         my array
         * i = k - 2            i = 1
         * i = k - 3            i = 2
         * ...                  ...
         * i = k - n            i = n - 1
         * ...                  ...
         * i = k - (k - 1)      i = k - 2
         * i = k - (k - 0)      i = k - 1
         */

        BN_copy(r, _a);

        if(eCharArray != NULL) free(eCharArray);
        if(ctx != NULL) BN_CTX_free(ctx);
        if(_a != NULL) BN_free(_a);
        return 0;
}

void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        ExpMod(res,a,e,m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}
