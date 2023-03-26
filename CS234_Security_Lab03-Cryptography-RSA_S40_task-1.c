/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a, BIGNUM * b)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str_a = BN_bn2hex(a);
char * number_str_b = BN_bn2hex(b);
printf("%s (%s,%s)\n", msg, number_str_a, number_str_b);
OPENSSL_free(number_str_a);
OPENSSL_free(number_str_b);
}

int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *p = BN_new();
BIGNUM *q = BN_new();
BIGNUM *e = BN_new();
BIGNUM *phi = BN_new();
BIGNUM *n = BN_new();
BIGNUM *d = BN_new();
BIGNUM *pm1 = BN_new();
BIGNUM *qm1 =BN_new();

// assign values
BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
BN_hex2bn(&e, "0D88C3");

// Solution: n = p*q for compute Public Key
BN_mul(n, p, q, ctx);
printBN("Public Key:", e, n);

// Solution: phi(n) = (p-1)*(q-1)
BN_sub(pm1, p, BN_value_one());
BN_sub(qm1, q, BN_value_one());
BN_mul(phi,pm1, qm1, ctx);
// Solution: e * d mod phi(n) = 1 for compute Private Key
BN_mod_inverse(d, e, phi, ctx);
printBN("Private Key:", d, n);

//free memory
BN_clear_free(p);
BN_clear_free(q);
BN_clear_free(e);
BN_clear_free(d);
BN_clear_free(phi);
BN_clear_free(pm1);
BN_clear_free(qm1);
BN_clear_free(n);

return 0;
}
