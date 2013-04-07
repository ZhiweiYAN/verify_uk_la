#include <glog/logging.h>
#include "openssl_sign_encrypt_rsa.h"


static void callback(int p, int n, void *arg)
{
    char c='B';
    if (p == 0) c='.';
    if (p == 1) c='+';
    if (p == 2) c='*';
    if (p == 3) c='\n';
    fputc(c,stderr);
}

int main(void)
{

    int ret = 0;

    google::SetLogDestination(google::INFO,("./log.txt"));
    google::InitGoogleLogging("");

    /*
    char results_string[]="MIGMAgEAAoGBAJ+c9JmFU7ctJ4NKcv4AcUYnxzXZoy5X2/whN5DuxordXLndsFMd+37fT2xB5RdJIGP9aPLm9BLvPmj9BAjJEQxDDbX4jExQ/PD4O1+0a3iqJRt5zY3ryLlJAADET9bnhMNR2L36BXEcClGGDy+jVJMyhrFNkeR2bLxHmzyeaetfAgMBAAE=";
    char *pub_key_der_buffer = NULL;

    char prefix_pub_key[7]= {0x30,0x81,0x89,0x02,0x81,0x81,0x00};
    char subfix_pub_key[5]= {0x02,0x03,0x01,0x00,0x01 };


    char *buf2 = (char*)malloc(1024);
    bzero(buf2, 1024);

    long int len2 = 0;

    //read the 128 bytes of terminal pub key
    FILE *fp2 = NULL;
    fp2 = fopen("terminal_pub_key.dat","rb");

    fread(buf2+7, 128, 1, fp2);

    memcpy(buf2, prefix_pub_key, 7);
    memcpy(buf2 + 128 + 7, subfix_pub_key, 5);

    fclose(fp2);

    len2 = 140;

    RSA *rsa_pub_key2 = NULL;

    const unsigned char *p_buf2 = (const unsigned char *)buf2;
    rsa_pub_key2 = d2i_RSAPublicKey (NULL, &p_buf2, 140);

    printf ("stage 1\n");

    RSA *key = NULL;

    ret = Generate_pub_key_from_files("terminal_pub_key.dat", &key);

    return 1;
    */

    /*
    //Google Log
    google::SetLogDestination(google::INFO,("./log.txt"));
    google::InitGoogleLogging("");

    //Google Log testing
    //google::SendEmail("jerod.yan@gmail.com",  "subject",  "body");
    LOG(INFO)  <<  "BEGIN LOG.";
    DLOG(INFO) << "DLOG BEGIN.";
    FILE *fp = NULL;

    RSA *rsa = NULL, *pub_rsa=NULL, *priv_rsa=NULL;
    int len;
    unsigned char *buf, *p;

    //rsa = RSA_generate_key (1024, RSA_F4, NULL, (char *) stdout);
    rsa = RSA_new();
    rsa = Get_private_key_from_file(rsa, (char *)"pub_keyfile.txt");

    buf = (unsigned char *) malloc (2048);

    p = buf;

    len = i2d_RSAPublicKey (rsa, &p);

    fp = fopen("server_pub_key.bin2","wb");
    ret = fwrite(buf+7, 1, 128, fp);
    fclose(fp);

    fp = fopen("server_pub_key.bin","wb");
    ret = fwrite(buf, 1, len, fp);


    len += i2d_RSAPrivateKey (rsa, &p);


    RSA_free (rsa);


    p = buf;
    pub_rsa = d2i_RSAPublicKey (NULL, (const unsigned char **)&p, (long) len);
    len -= (p - buf);
    priv_rsa = d2i_RSAPrivateKey (NULL, (const unsigned char **)&p, (long) len);


    return 1;

    pub_key_der_buffer = unbase64((unsigned char*)results_string, strlen( results_string ));
    rsa = d2i_RSAPublicKey(NULL, (const unsigned char **)&pub_key_der_buffer, 140);
    //pub_key_der_buffer = (char*)Convert_rsa_to_der_for_pub_key(rsa,&len);

    return 1;

    */

    //Generate public key and private key, which are stored in an RSA object.
    RSA *rsa = NULL;
    unsigned long exp =  RSA_F4; //65537
//    rsa = RSA_generate_key(KEY_SIZE, exp, callback, NULL);
    ret = Generate_pub_key_from_file(&rsa, (char *)"GZ002312_1005_pubkey.bin");
//    ret = Get_private_key_from_file(&rsa, (char *)"terminal_pub_key.dat");
//    ret = Save_private_key_to_file(rsa, (char *)"pri_keyfile.txt");
    return 1;

    Remove_private_key(rsa);

    ret = Save_public_key_to_file(rsa, (char *)"GZ1616_1009_pubkey.pem");

    return 1;

    unsigned char msg[]="What is the expected output? What do you see instead?";
    // unsigned char re_msg[]="yznzw world, OpenSSL";

    unsigned char *cipher_text = NULL;
    unsigned int cipher_text_len = 0;

    unsigned char *plain_text = NULL;
    unsigned int plain_text_len = 0;



    ret = Sign_and_encrypt_plain_text(rsa, rsa,
                                      msg, sizeof(msg),
                                      &cipher_text, &cipher_text_len);
    ret = decrypt_and_validate_sign(rsa, rsa,
                                    cipher_text, cipher_text_len,
                                    &plain_text, &plain_text_len);

    //DLOG(INFO) <<"DLOG END.";
    //LOG(INFO)  <<  "END LOG.";
    google::ShutdownGoogleLogging();

    return ret;

}

