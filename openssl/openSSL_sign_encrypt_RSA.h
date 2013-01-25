/*
 * =====================================================================================
 *
 *       Filename:  openSSL_sign_encrypt_RSA.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2012 9:44:09 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */

#ifndef  OPENSSL_SIGN_ENCRYPT_RSA_H_INC
#define  OPENSSL_SIGN_ENCRYPT_RSA_H_INC



#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/rand.h>


#include <glog/logging.h>

#define SSL_MIN(x,y) ((x) > (y) ? (y) : (x))

// #define RSA_PKCS_PADDING_MODE RSA_PKCS1_OAEP_PADDING
#define SHA1_LEN 	20
#define KEY_SIZE  	1024
#define PUB_KEY_DER_LEN 140
#define PRI_KEY_DER_LEN 608
#define KEY_FILE_NAME "verify_uk_server_key.key"

// Generally speaking the bytes which will be encrypted is less than RSA_size(key)
/* How many bytes we can encrypt each time, limited by the modulus size
 * and the padding requirements. */
/* padding length for input padding mode
==encrypt with private key：
===RSA_PKCS1_PADDING RSA_size-11
===RSA_NO_PADDING RSA_size-0
===RSA_X931_PADDING RSA_size-2
==encrypt with public key:
===RSA_PKCS1_PADDING RSA_size-11
===RSA_SSLV23_PADDING RSA_size-11
===RSA_X931_PADDING RSA_size-2
===RSA_NO_PADDING RSA_size-0
===RSA_PKCS1_OAEP_PADDING RSA_size-2 * SHA_DIGEST_LENGTH-2
*/

#define PRIFIX_PUB_KEY_LEN 7
#define SUBFIX_PUB_KEY_LEN 5
#define PUB_KEY_DER_FORMAT_LEN 140
#define PUB_KEY_BARE_LEN 128

#define PUB_KEY_BARE_BIN_FILE_NAME "./openssl/terminal_pub_key.dat"

#define RSA_PKCS_PADDING_MODE RSA_NO_PADDING
#define FIXED_BYTES_TO_BE_ENCRYPTED_PER_TIME 100
//#define BYTES_TO_BE_ENCRYPTED_PER_TIME(x) {RSA_size(x) - (20*2 +2)}

char *base64(const unsigned char *input, int length);
char *unbase64(unsigned char *input, int length);
unsigned char *Convert_rsa_to_der_for_pub_key(RSA *rsa, int *len);
RSA *Convert_der_to_rsa_for_pub_key(unsigned char *buf, long len);


int Save_private_key_to_file(RSA *rsa, char* key_file);
int Get_private_key_from_file(RSA **rsa, char* key_file);



int Generate_pub_key_from_files(char* file_name, RSA** rsa);
void Remove_private_key(RSA *r);


int Sign_and_encrypt_plain_text(RSA *receiver_pub_key_for_encrypt, RSA *signers_private_key_for_signature,
                                unsigned char *plain_text, unsigned int  plain_text_len,
                                unsigned char **cipher_text, unsigned int *cipher_text_len);
int decrypt_and_validate_sign(RSA *receiver_pub_private_key_for_decrypt, RSA *signers_pub_key_for_signature,
                              unsigned char *cipher_text, unsigned int cipher_text_len,
                              unsigned char **plain_text, unsigned int *plain_text_len);

#endif
/* ----- #ifndef OPENSSL_SIGN_ENCRYPT_RSA_H_INC  ----- */
