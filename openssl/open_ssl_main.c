#include <glog/logging.h>
#include "openSSL_sign_encrypt_RSA.h"


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
	
	//Google Log
    google::SetLogDestination(google::INFO,("./log.txt"));
    google::InitGoogleLogging("");
    
    //Google Log testing
    //google::SendEmail("jerod.yan@gmail.com",  "subject",  "body");
    LOG(INFO)  <<  "BEGIN LOG.";
    DLOG(INFO) << "DLOG BEGIN.";

    //Generate public key and private key, which are stored in an RSA object.
    RSA * rsa = NULL;
    unsigned long exp =  RSA_F4; //65537
    rsa = RSA_generate_key(KEY_SIZE, exp, callback, NULL);
	ret = Save_private_key_to_file(rsa, (char *)"pri_keyfile.txt");

	
	Remove_private_key(rsa);

	ret = Save_private_key_to_file(rsa, (char *)"pub_keyfile.txt");

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

    DLOG(INFO) <<"DLOG END.";
    LOG(INFO)  <<  "END LOG.";
    google::ShutdownGoogleLogging();

    return ret;

}

