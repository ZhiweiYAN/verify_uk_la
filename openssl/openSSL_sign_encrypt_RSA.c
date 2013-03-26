/*
 * =====================================================================================
 *
 *       Filename:  openSSL_sign_encrypt_RSA.c
 *
 *    Description:  the codes does both sign and encrypt data using RSA
 *
 *        Version:  1.0
 *        Created:  12/21/2012 9:43:10 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */
#include "openssl_sign_encrypt_rsa.h"

int Generate_pub_key_from_file(RSA** rsa, char* file_name)
{
    char prefix_pub_key[PRIFIX_PUB_KEY_LEN]= {0x30,0x81,0x89,0x02,0x81,0x81,0x00};
    char subfix_pub_key[SUBFIX_PUB_KEY_LEN]= {0x02,0x03,0x01,0x00,0x01 };

    char *buf = NULL;
    buf = (char*)malloc(PUB_KEY_DER_FORMAT_LEN+1);
    bzero(buf, PUB_KEY_DER_FORMAT_LEN+1);

    FILE *fp = NULL;
    fp = fopen(file_name,"rb");
    if(NULL==fp) {
        return -1;
    }

    char *p = NULL;
    p = buf;
    memcpy(buf, prefix_pub_key, PRIFIX_PUB_KEY_LEN);
    memcpy(buf + PRIFIX_PUB_KEY_LEN + PUB_KEY_BARE_LEN, subfix_pub_key, SUBFIX_PUB_KEY_LEN);
    fread(buf + PRIFIX_PUB_KEY_LEN, PUB_KEY_BARE_LEN, 1, fp);

    fclose(fp);
    fp = NULL;
    buf = p;

    RSA *rsa_pub_key = NULL;

    const unsigned char *p_buf = (const unsigned char *)buf;
    rsa_pub_key = d2i_RSAPublicKey (NULL, &p_buf, PUB_KEY_DER_FORMAT_LEN);

    DLOG(INFO)<<hex2str((unsigned char *)buf, PUB_KEY_DER_FORMAT_LEN)<< "terminal pub_key with DER format.";

    if(NULL==rsa_pub_key) {
        //ERR_print_errors_fp(stdout);
        *rsa = NULL;
        return -1;
    } else {
        *rsa = rsa_pub_key;
        return 1;
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  base64
 *  Description:
 * =====================================================================================
 */
char *base64(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    char *buff = NULL;


    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    buff = (char *)malloc(bptr->length);
    if(NULL==buff) {
        return NULL;
    }

    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    BIO_free_all(b64);

    return buff;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  unbase64
 *  Description:
 * =====================================================================================
 */
char *unbase64(unsigned char *input, int length)
{
    BIO *b64, *bmem;

    char *buffer = (char *)malloc(length);
    if(NULL==buffer) {
        return NULL;
    }
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

char* str2binary( char* str, int str_len)
{
    int i = 0;

    char* hex = NULL;

    int hex_len;

    int hex_sum = str_len/2;

    unsigned int * hex_value = NULL;
    hex_value = (unsigned int *)malloc( hex_sum * sizeof(unsigned int) );

    char one_value_chars[3];

    for(i=0; i<hex_sum; i++) {
        memset(one_value_chars, 0, 3);
        memcpy(one_value_chars, str+2*i, 2);
        *(hex_value + i) = strtol(one_value_chars, (char**) NULL, 16);
    }

    hex = (char*)malloc(hex_sum);

    for (i=0; i<hex_sum; i++) {
        memset((char*)hex+i, *(hex_value+i), 1);
    }

    hex_len =hex_sum;

    if(NULL!=hex_value) {
        free(hex_value);
        hex_value = NULL;
    }

    return hex;
}

/* Returns the malloc buffer, and puts the size of the buffer into the integer
 * pointed to by the second argument.
 */
unsigned char *Convert_rsa_to_der_for_pub_key(RSA *rsa, int *len)
{
    unsigned char *buf=NULL, *p=NULL;

    *len = i2d_RSAPublicKey(rsa, NULL);
    buf = (unsigned char*)OPENSSL_malloc(*len);
    if(NULL==buf) {
        return 0;
    }

    p = buf;
    i2d_RSAPublicKey(rsa, &p); /* If we use buf here, return buf; becomes wrong */
    return buf;
}

unsigned char *Convert_rsa_to_der_for_private_key(RSA *rsa, int *len)
{
    unsigned char *buf=NULL, *p=NULL;

    *len = i2d_RSAPrivateKey(rsa, NULL);
    buf = (unsigned char*)OPENSSL_malloc(*len);
    if(NULL==buf) {
        return 0;
    }

    p = buf;
    i2d_RSAPrivateKey(rsa, &p); /* If we use buf here, return buf; becomes wrong */
    return buf;
}


/* Note that the pointer to the buffer gets copied in.  Therefore, when
 * d2i_... changes its value, those changes aren't reflected in the caller's copy
 * of the pointer.
 */
RSA *Convert_der_to_rsa_for_pub_key(unsigned char *buf, long len)
{
    RSA *rsa = NULL;
    unsigned char *p = NULL;

    p = buf;

    rsa = d2i_RSAPublicKey(NULL, ( const unsigned char**)&p, len);

    if (NULL==rsa) {
        return NULL;
    } else {
        return rsa;
    }
}

RSA *Convert_der_to_rsa_for_private_key(unsigned char *buf, long len)
{
    RSA *rsa = NULL;
    unsigned char *p = NULL;

    p = buf;

    rsa = d2i_RSAPrivateKey(NULL, ( const unsigned char**)&p, len);

    if (NULL==rsa) {
        return NULL;
    } else {
        return rsa;
    }
}

void Remove_private_key(RSA *r)
{
    r->d = r->p = r->q = r->dmp1 = r->dmq1 = r->iqmp = 0;
}



int Save_private_key_to_file(RSA *rsa, char* key_file)
{
    FILE *file;
    if (NULL == rsa) {
        printf("RSA not initial.\n");
        return 0;
    }
    file = fopen(key_file,"wb");

    if (NULL == file ) {
        printf("create file 'prikey.key' failed!\n");
        return 0;
    }
    PEM_write_RSAPrivateKey(file, rsa, NULL, NULL, 512, NULL, NULL);
    fclose(file);
    return 1;
}


int Save_public_key_to_file(RSA *rsa, char* key_file)
{
    FILE *file;
    if (NULL == rsa) {
        printf("RSA not initial.\n");
        return 0;
    }
    file = fopen(key_file,"wb");

    if (NULL == file ) {
        printf("create file 'pubkey.key' failed!\n");
        return 0;
    }
    PEM_write_RSAPublicKey(file, rsa);
    fclose(file);
    return 1;
}


int Get_private_key_from_file(RSA **rsa, char* key_file)
{
    FILE *file;
    file = fopen(key_file, "rb");
    if (NULL == file) {
        printf("open file 'prikey.key' failed!\n");
        return -1;
    }

    RSA *key = NULL;
    PEM_read_RSAPrivateKey(file, &key, NULL, NULL);
    fclose(file);

    if(NULL==key) {
        *rsa = NULL;
        return -1;
    } else {
        *rsa = key;
        return 1;
    }
}

int Get_public_key_from_file(RSA **rsa, char* key_file)
{
    FILE *file;
    file = fopen(key_file, "rb");
    if (NULL == file) {
        printf("open file 'public.key' failed!\n");
        return -1;
    }

    RSA *key = NULL;
    PEM_read_RSAPublicKey(file, &key, NULL, NULL);
    fclose(file);

    if(NULL==key) {
        *rsa = NULL;
        return -1;
    } else {
        *rsa = key;
        return 1;
    }
}


char* Binary2str(unsigned char* hex, int hex_len)
{
    int i = 0;
//  assert(NULL!=hex);
//  assert(NULL!=str);
    char *str = NULL;
    int  str_len = 0;

    str_len = 2 * hex_len+1;
    str = (char*)malloc(str_len);
    memset(str, 0, str_len);

    for(i=0; i<hex_len; i++) {
        sprintf(str+2*i, "%02X ", ((unsigned char *) hex)[i] );
        // printf("0x%02X ", ( (unsigned char *) hex)[i] );
    }
    // printf("\n");
    if(NULL!=str) {
        return str;
    } else {
        return NULL;
    }


}


char hex2str(unsigned char* hex, int hex_len)
{
    int i = 0;
//  assert(NULL!=hex);
//  assert(NULL!=str);
    char *str = NULL;
    int  str_len = 0;

    str_len = 2 * hex_len+1;
    str = (char*)malloc(str_len);
    memset(str, 0, str_len);

    for(i=0; i<hex_len; i++) {
        sprintf(str+2*i, "%02X ", ((unsigned char *) hex)[i] );
        // printf("0x%02X ", ( (unsigned char *) hex)[i] );
    }
    // printf("\n");
    if(NULL!=str) {
        DLOG(INFO)<<"Memory Binary:|"<<str<<"|";
        free(str);
        str = NULL;
    }

    return ' ';
}

int str2hex( char* str, int str_len, void* hex, int *hex_len)
{
    int i = 0;

    int hex_sum = str_len/2;

    unsigned int * hex_value = NULL;
    hex_value = (unsigned int *)malloc( hex_sum * sizeof(unsigned int) );

    char one_value_chars[3];

    for(i=0; i<hex_sum; i++) {
        memset(one_value_chars, 0, 3);
        memcpy(one_value_chars, str+2*i, 2);
        *(hex_value + i) = strtol(one_value_chars, (char**) NULL, 16);
    }


    for (i=0; i<hex_sum; i++) {
        memset((char*)hex+i, *(hex_value+i), 1);
    }

    *hex_len =hex_sum;

    return 1;
}


/*    First, we calculate the SHA1( 20 bytes) of the plain text (PT).
 *    Second, we create the signature (S) of SHA1 with signers_private_key_for_signature.
 *    Third, after we attach (S) to the end of PT, we have (PT+S).
 *    Fourth, we create the cipher text (CT) of (PT+S) by means of receiver_pub_key_for_encrypt.
 *    */
int Sign_and_encrypt_plain_text(RSA *receiver_pub_key_for_encrypt,
                                RSA *signers_private_key_for_signature,
                                unsigned char *plain_text,
                                unsigned int  plain_text_len,
                                unsigned char **cipher_text,
                                unsigned int *cipher_text_len)
{
    int ret = 0;
    unsigned char *tmp = NULL, *to_encrypt = NULL;
    unsigned char *sig = NULL;
    unsigned char *p = NULL, *ptr = NULL;
    unsigned int  len = 0, ignored = 0, b_per_ct = 0;
    int sig_len = 0;
    int to_encrypt_len = 0;
    int bytes_remaining; /* MUST NOT BE UNSIGNED. */
    int padding_mode = 0;

    unsigned char hash[SHA1_LEN];
    memset(hash, 0, SHA1_LEN);

    DLOG(INFO)<<"input, plain_text_len: "<<plain_text_len;
    DLOG(INFO)<<"input, plain_text: |"<<plain_text<<"|";

    //we put the plain text into a temporary buffer.
    len = plain_text_len;
    tmp = (unsigned char *)malloc(len);
    if(NULL==tmp) {
        LOG(ERROR)<<"malloc tmp, failed";
        ret = -1;
        return -1;
    } else {
        memset(tmp, 0, len);
    }
    memcpy(tmp, plain_text, plain_text_len);

    //malloc space for the signature
    sig = (unsigned char *)malloc(BN_num_bytes(signers_private_key_for_signature->n));
    if(NULL == sig) {
        LOG(ERROR)<<"malloc tmp, failed";
        ret = -1;
        goto err;
    } else {
        memset(sig, 0, BN_num_bytes(signers_private_key_for_signature->n));
    }

    //Process SHA1
    if (!SHA1(tmp, len, hash)) {
        LOG(ERROR)<<"sha1, failed";
        ret = -1;
        goto err;
    }
    DLOG(INFO)<<"SHA1 LEN:" << SHA1_LEN <<hex2str(hash,SHA1_LEN) ;
    /* Now sign tmp (the hash of it).*/
    if (!RSA_sign(NID_sha1, hash, SHA1_LEN, sig, &ignored, signers_private_key_for_signature)) {
        ret = -1;
        goto err;
    }
    sig_len = RSA_size(signers_private_key_for_signature);
    DLOG(INFO)<<"signature_len:"<<sig_len<<hex2str(sig,sig_len);

    /*   Up to here, the signature is created successfully.
     */


    /* How many bytes we can encrypt each time, limited by the modulus size
     * and the padding requirements.
     */
    //b_per_ct = RSA_size(receiver_pub_key_for_encrypt) - (2 * 20 + 2);
    b_per_ct = FIXED_BYTES_TO_BE_ENCRYPTED_PER_TIME;


    to_encrypt_len = plain_text_len + sig_len;

    to_encrypt = (unsigned char *)malloc(to_encrypt_len);
    if(NULL == to_encrypt) {
        goto err;
    } else {
        memset(to_encrypt, 0, to_encrypt_len);
    }


    /* The calculation before the mul is the number of encryptions we're
     * going to make.  After the mul is the output length of each
     * encryption.
     */
    *cipher_text_len = ((to_encrypt_len + b_per_ct - 1) / b_per_ct) * RSA_size(receiver_pub_key_for_encrypt);

    *cipher_text = (unsigned char *) malloc(*cipher_text_len);
    if(NULL == cipher_text) {
        ret = -1;
        goto err;
    } else {
        memset(*cipher_text, 0, *cipher_text_len);
    }


    /* Copy the data to encrypt into a single buffer. */
    ptr = to_encrypt;
    bytes_remaining = to_encrypt_len;
    // memcpy(to_encrypt, plain_text, plain_text_len);
    // memcpy(to_encrypt + plain_text_len, sig, sig_len);

    memcpy(to_encrypt, sig, sig_len);
    memcpy(to_encrypt + sig_len, plain_text, plain_text_len);
    p = *cipher_text;

    /*
    if(RSA_PKCS1_OAEP_PADDING == RSA_PKCS_PADDING_MODE){
        padding_mode = RSA_PKCS1_OAEP_PADDING;
    }else{
        padding_mode = RSA_PKCS1_PADDING;
    }
    */
    padding_mode = RSA_PKCS_PADDING_MODE;

    while (bytes_remaining > 0) {
        /* encrypt b_per_ct bytes up until the last loop, where it may be fewer. */
        if (!RSA_public_encrypt(SSL_MIN(bytes_remaining,(int)b_per_ct), ptr, p,
                                receiver_pub_key_for_encrypt,
                                padding_mode)) {
            /* the operation of encrypt failed during the encrypt process. */
            if(NULL!=(*cipher_text)) {
                free(*cipher_text);
                *cipher_text = NULL;
                *cipher_text_len = 0;
            }
            ret = -1;
            goto err;
        }
        bytes_remaining -= b_per_ct;
        ptr += b_per_ct;
        /* Remember, output is larger than the input. */
        p += RSA_size(receiver_pub_key_for_encrypt);
    }
//    The operation of encrypt is successful and set the flag of success.
    ret = 1;
    DLOG(INFO)<<"cipher_text:"<< *cipher_text_len <<hex2str(*cipher_text, *cipher_text_len);

err:
    if(NULL!=tmp) {
        free(tmp);
        tmp = NULL;
    }

    if (NULL!=sig) {
        free(sig);
        sig = NULL;
    }

    if(NULL!=to_encrypt) {
        free(to_encrypt);
        to_encrypt = NULL;
    }

    if(1 == ret) {
        return 1;
    } else {
        return -1;
    }
}


/* recip_key must contain both the public and private key. */
int decrypt_and_validate_sign(RSA *receiver_pub_private_key_for_decrypt,
                              RSA *signers_pub_key_for_signature,
                              unsigned char *cipher_text,
                              unsigned int cipher_text_len,
                              unsigned char **plain_text,
                              unsigned int *plain_text_len)
{
    int           ret = 0;
    BN_CTX        *tctx = NULL;
    BN_CTX        *tctx_verify = NULL;
    unsigned int  ctlen =0, i=0, l=0;
    unsigned char *decrypt=NULL,  *p=NULL;

    unsigned char *sig = NULL;
    int sig_len = 0;
    int padding_mode = 0;

    unsigned char hash[SHA1_LEN +1];
    memset(hash, 0, SHA1_LEN+1);


    DLOG(INFO)<<"cipher_text_len:"<<cipher_text_len<<hex2str(cipher_text,cipher_text_len);

    // cipher_text_len must be the interger times than RSA_size
    if (0!=(cipher_text_len % RSA_size(receiver_pub_private_key_for_decrypt))) {
        LOG(ERROR)<< "cipher_text_len must be the interger times than RSA_size";
        ret = -1;
        goto err;
    }


    // malloc space for decrypt
    decrypt = (unsigned char *)malloc(cipher_text_len);
    if(NULL==decrypt) {
        LOG(ERROR)<<"malloc, failed";
        ret = -1;
        goto err;
    } else {
        memset(decrypt, 0 , cipher_text_len);
        p = decrypt;
    }

    if (!(tctx = BN_CTX_new(  ))) {
        free(decrypt);
        decrypt = NULL;
        p = NULL;
        ret = -1;
        goto err;
    }

    if(RSA_PKCS1_OAEP_PADDING == RSA_PKCS_PADDING_MODE) {
        padding_mode = RSA_PKCS1_OAEP_PADDING;
    } else {
        padding_mode = RSA_PKCS1_PADDING;
    }

    padding_mode = RSA_PKCS_PADDING_MODE;

    RSA_blinding_on(receiver_pub_private_key_for_decrypt, tctx);
    for (ctlen = i = 0;  i < cipher_text_len / RSA_size(receiver_pub_private_key_for_decrypt);  i++) {
        if (!(l = RSA_private_decrypt(RSA_size(receiver_pub_private_key_for_decrypt), cipher_text, p, receiver_pub_private_key_for_decrypt,
                                      padding_mode))) {
            print_rsa_error_string();
            ret = -1;
            goto err;
        }
        cipher_text += RSA_size(receiver_pub_private_key_for_decrypt);
        p += l;
        ctlen += l;
    }

    //LOG(INFO)<<"Decrypt txt: "<< hex2str(decrypt+sig_len, );
    //split the signature text and plain text
    sig_len = RSA_size(signers_pub_key_for_signature);
    sig = (unsigned char *)malloc(sig_len);
    if(NULL==sig) {
        LOG(ERROR)<<"malloc, failed";
        ret = -1;
        goto err;
    } else {
        // memcpy(sig, decrypt+ctlen-sig_len, sig_len);
        memcpy(sig, decrypt, sig_len);
        DLOG(INFO)<<"signature_len:"<<sig_len<<hex2str(sig,sig_len);
    }


    *plain_text_len = ctlen - sig_len;
    *plain_text = (unsigned char *)malloc(*plain_text_len);
    if(NULL==*plain_text) {
        LOG(ERROR)<<"malloc, failed";
        ret = -1;
        goto err;
    } else {
        memcpy(*plain_text, decrypt+sig_len,  *plain_text_len);
        DLOG(INFO)<<"output, plain_text_len: "<<*plain_text_len;
        DLOG(INFO)<<"output, plain_text: |"<<*plain_text <<"|";
    }

    if (!SHA1(*plain_text, *plain_text_len, hash)) {
        ret = -1;
        goto err;
    }


    if (!(tctx_verify = BN_CTX_new(  ))) {
        ret = -1;
        goto err;
    }
//    //verify the signature of signer.
//    RSA_blinding_on(signers_pub_key_for_signature, tctx_verify);
//	ret = RSA_verify(NID_sha1, hash, SHA1_LEN, sig, RSA_size(signers_pub_key_for_signature), signers_pub_key_for_signature);

//    if (1!=ret){
//        LOG(ERROR)<<"RSA verify, failed";
//		print_rsa_error_string();
//        ret = -1;
//       goto err;
//    }


    //decrypt signature with pubkey_terminal, comparing to sha1 of plain txt byte to byte.
    unsigned char sig_decrypt[SHA1_LEN];
    memset(sig_decrypt, 0, SHA1_LEN);

    ret = RSA_public_decrypt(RSA_size(signers_pub_key_for_signature),
                             sig, sig_decrypt, signers_pub_key_for_signature, padding_mode);

    if(-1==ret) {
        print_rsa_error_string();
        goto err;
    } else {
        DLOG(INFO)<<hex2str(sig_decrypt,SHA1_LEN)<<"signature txt:" ;
        DLOG(INFO)<<hex2str(hash, SHA1_LEN)<<"recv signature txt:";
    }

    ret = memcmp(hash,sig_decrypt, SHA1_LEN);

    if(0==ret) {
        ret = 1;
    } else {
        ret = -1;
    }


err:
    RSA_blinding_off(receiver_pub_private_key_for_decrypt);
    BN_CTX_free(tctx);
    RSA_blinding_off(signers_pub_key_for_signature);
    BN_CTX_free(tctx_verify);

    if(NULL!=decrypt) {
        free(decrypt);
        decrypt = NULL;
        p = NULL;
    }
    if(NULL!=sig) {
        free(sig);
        sig = NULL;
    }

    if(-1==ret ) {
        if(NULL!=(*plain_text)) {
            free( (*plain_text));
            *plain_text = NULL;
            *plain_text_len = 0;
        }
        return -1;
    } else {
        return 1;
    }
}

int print_rsa_error_string(void)
{
    char buf[2048];
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), buf);
    fprintf(stderr, "%s\n", buf);
    DLOG(INFO)<<"decrypt error info:"<<buf;
    return 1;
}

