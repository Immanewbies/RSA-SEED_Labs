/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}

int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *e = BN_new();
BIGNUM *n = BN_new();
BIGNUM *M = BN_new();
BIGNUM *d = BN_new();
BIGNUM *C = BN_new();

/*// Task 2 Encrypting a message
// assign values
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&e, "010001");
BN_hex2bn(&M, "4120746f702073656372657421"); //hex encode for " A top secret!"
// Solution: C = M^e mod n
BN_mod_exp(C, M, e, n, ctx);
printBN("Encrypting a Message", C);*/

/*// Task 3 Decrypting a Message
// assign values
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
// Solution: M = C^d mod n
BN_mod_exp(M, C, d, n ,ctx);
printBN("Decrypting a Message", M); */

/*// Task 4 Signing a Message
//new variable
BIGNUM *M1 = BN_new();
BIGNUM *M2 = BN_new();
BIGNUM *S1 = BN_new();
BIGNUM *S2 = BN_new();
// assign values
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
BN_hex2bn(&M1, "49206f776520796f75202432303030");
BN_hex2bn(&M2, "49206f776520796f75202433303030");
// Solution: C = M^d mod n
BN_mod_exp(S1, M1, d, n, ctx);
BN_mod_exp(S2, M2, d, n, ctx);
printBN("Signature of M1", S1);
printBN("Signature of M2", S2);
//free memory
BN_clear_free(M1);
BN_clear_free(M2);
BN_clear_free(S1);
BN_clear_free(S2);*/

/*// Task 5 Verifying a Signature
//new variable
BIGNUM *S = BN_new();
// assign values
BN_hex2bn(&M, "4c61756e63682061206d697373696c652e"); //hex encode for "Launch a missile." 
BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
BN_hex2bn(&e, "010001");
BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
// Solution: C = S^e mod n for get Message to check C=M
BN_mod_exp(C, S, e, n ,ctx);
// verifying the signature
if (BN_cmp(C,M) == 0)
{
	printf("Valid Signature \n");	
}else{
	printf("Verification fails \n");	
}
// free memory
BN_clear_free(S);*/

// free memory
BN_clear_free(M);
BN_clear_free(e);
BN_clear_free(d);
BN_clear_free(C);
BN_clear_free(n);

return 0;
}
