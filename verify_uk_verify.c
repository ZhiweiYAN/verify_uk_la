/*
 * =====================================================================================
 *
 *       Filename:  Verify_procedures.c
 *
 *    Description:  record the payment packet into the database
 *
 *        Version:  1.0
 *        Created:  12/14/2012 10:17:07 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */
#include "verify_uk_verify.h"

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Do_verify_procedures
 *  Description:  Verify the incoming packet from terminals, transfer the unencrypted
 *                plain packet to proxy servers if the packet is verified successfully.
 * =====================================================================================
 */
int Do_verify_procedures(int connection_sd, char *packet, int packet_size)
{
    int ret = 0;

    char buf_send_terminal[MAXPACKETSIZE];
    int buf_send_terminal_len = 0;

    char *send_terminal_cipher_text = NULL;
    int send_terminal_cipher_text_len = 0;

    int pre_pkt_len =0 ;

    ssize_t count = 0;

    unsigned char *cipher_text = NULL;
    unsigned int   cipher_text_len = 0;

    unsigned char *to_proxy_plain_text = NULL;
    unsigned int   to_proxy_plain_text_len = 0;

    unsigned char *from_proxy_plain_text = NULL;
    unsigned int from_proxy_plain_text_len = 0;

    VerifyPacketHeader veri_pkt_hdr;
    RSA *terminal_pub_key = NULL;
    RSA *server_private_key = NULL;

    bzero(buf_send_terminal, MAXPACKETSIZE);

    //sleep to debug option for multi-process
    // sleep(45);

    //get verifying-packet header and parse the verifying-packet header
    bzero(&veri_pkt_hdr, sizeof(VerifyPacketHeader));
    ret = Parse_verify_pkt_header(packet, packet_size, &veri_pkt_hdr);
    if(-1 == ret) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to parse verify packet header: terminal_id=%s, worker_id=%s.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
        ret = Prepare_error_response_packet(buf_send_terminal, ERROR_INCOMPLETE_PKT);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    } else {
        DBG("Success to parse verify packet header: terminal_id=%s, worker_id=%s.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
    }


    //get the public key of terminal
//    ret = Get_terminal_pub_key_from_db(&terminal_pub_key, &veri_pkt_hdr);
    ret = Get_terminal_pub_key_from_file(&terminal_pub_key, &veri_pkt_hdr);
    if (-1==ret) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to get terminal %s:%s public rsa-key.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
        ret = Prepare_error_response_packet(buf_send_terminal, ERROR_NO_TERMINAL_RSA_PUBKEY);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    } else {
        DBG("Success to get terminal %s:%s public rsa-key.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);

    }

    //get the private key of verify server
    ret = Get_server_private_key_from_db(&server_private_key);
    //ret = Get_server_private_key_from_file(&server_private_key, (char *)SERVER_PRIVATE_KEY_PEM_FILE);
    if (-1==ret) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to get server rsa key pair.\n");
        ret = Prepare_error_response_packet(buf_send_terminal, ERROR_NO_SRV_RSA_PRIKEY);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    } else {
        DBG("Success to get server rsa key pair.\n");
    }

    cipher_text = (unsigned char *)packet + VERIFY_PKT_HEADER_LENGTH;
    cipher_text_len = (unsigned int) (veri_pkt_hdr.payload_len);
    to_proxy_plain_text = NULL;
    to_proxy_plain_text_len = 0;

    //De-encrypt and Validate signature
    pre_pkt_len = VERIFY_PKT_MSG_TYPE_LENGTH + VERIFY_PKT_TERMINAL_ID_LENGTH + VERIFY_PKT_WORKER_ID_LENGTH;
    memcpy(buf_send_terminal, packet, pre_pkt_len);

    //malloc? free?
    //The memory for the variable 'to_proxy_plain_text' will be allocated in the
    //function decrypt_and_validate_sign().
    ret = decrypt_and_validate_sign(server_private_key, terminal_pub_key,
                                    cipher_text, cipher_text_len,
                                    &to_proxy_plain_text, &to_proxy_plain_text_len);


    if(1!=ret) {
        if(ERROR_DECRYPT==ret) {
            OUTPUT_ERROR;
            LOG_ERROR("while decrypting cipher text from %s %s, error.\n",veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
            Prepare_error_response_packet(buf_send_terminal, ERROR_DECRYPT);
            buf_send_terminal_len = strlen(buf_send_terminal);
            goto Do_verify_procedures_END;
        }
        if(ERROR_VALIDATE_SIGN==ret) {
            OUTPUT_ERROR;
            LOG_ERROR("while validating the signatures from %s %s, error.\n",veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
            Prepare_error_response_packet(buf_send_terminal, ERROR_VALIDATE_SIGN);
            buf_send_terminal_len = strlen(buf_send_terminal);
            goto Do_verify_procedures_END;
        } else {
            OUTPUT_ERROR;
            LOG_ERROR("while decrypting cipher text and validating the signatures from %s %s, error.\n", veri_pkt_hdr.terminal_id, veri_pkt_hdr.worker_id);
            Prepare_error_response_packet(buf_send_terminal, ERROR_VALIDATE_SIGN);
            buf_send_terminal_len = strlen(buf_send_terminal);
            goto Do_verify_procedures_END;
        }
    }

    DBG("Send to proxy packet %d bytes: |%s|.\n", to_proxy_plain_text_len, to_proxy_plain_text);

    //Prepare the memory for the packet from the server proxy.
    from_proxy_plain_text = (unsigned char *)malloc(MAX_SIZE_BUFFER_RECV+1);
    if(NULL==from_proxy_plain_text) {
        OUTPUT_ERROR;
        LOG(ERROR)<<"memory malloc for the variable from_proxy_plain_text, failed.";
        Prepare_error_response_packet(buf_send_terminal, ERROR_MEMORY_LACK);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    }

    bzero(from_proxy_plain_text, MAX_SIZE_BUFFER_RECV+1);

    //connect to proxy server as random mode, send plain text pkt to proxy server
    //and wait for backward pkt from proxy server.
    from_proxy_plain_text_len = 0;
    ret = SendRecv_message_to_proxy((char *)to_proxy_plain_text, to_proxy_plain_text_len,
                                    (char *)from_proxy_plain_text, (int *)&from_proxy_plain_text_len);


    //add signature and en-crypt the backward pkt
    if(1==ret && 0< from_proxy_plain_text_len) {
        bzero(buf_send_terminal, MAXPACKETSIZE);
        send_terminal_cipher_text_len = 0;
        ret = Sign_and_encrypt_plain_text(terminal_pub_key, server_private_key,
                                          (unsigned char *) from_proxy_plain_text,
                                          (unsigned int) from_proxy_plain_text_len,
                                          (unsigned char * *) &send_terminal_cipher_text,
                                          (unsigned int *) &send_terminal_cipher_text_len);

        //if we can add signature and encrypt the backward packet successfully.
        if(1==ret && 0<send_terminal_cipher_text_len) {
            memset(buf_send_terminal, ' ', VERIFY_PKT_HEADER_LENGTH);
            memcpy(buf_send_terminal, packet, VERIFY_PKT_MSG_TYPE_LENGTH+VERIFY_PKT_TERMINAL_ID_LENGTH+VERIFY_PKT_WORKER_ID_LENGTH);
            strncpy(buf_send_terminal+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "0", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
            strncpy(buf_send_terminal+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                    "SUCCESS",VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
            memcpy(buf_send_terminal+VERIFY_PKT_PAYLOAD_LEN_POSITION,
                   &send_terminal_cipher_text_len,
                   VERIFY_PKT_PAYLOAD_LEN_LENGTH);
            memcpy(buf_send_terminal+VERIFY_PKT_HEADER_LENGTH,
                   send_terminal_cipher_text, send_terminal_cipher_text_len);
            buf_send_terminal_len = VERIFY_PKT_HEADER_LENGTH + send_terminal_cipher_text_len;
        }
    } else {
        OUTPUT_ERROR;
        LOG(ERROR)<<"The link with proxy server seems down.";
        Prepare_error_response_packet(buf_send_terminal, ERROR_LINK_PROXY);
        buf_send_terminal_len = strlen(buf_send_terminal);
        goto Do_verify_procedures_END;
    }

    RSA_free(terminal_pub_key);
    RSA_free(server_private_key);

    //label for return.
Do_verify_procedures_END:
    //send the packet to terminal
    count = send( connection_sd, buf_send_terminal, buf_send_terminal_len, 0 );
    DBG("\nSend to terminal with %d bytes: |%s|\n", count, buf_send_terminal);

    if (0>count) {
        OUTPUT_ERROR;
        LOG_ERROR("Failed to send backward to terminals\n");
    }

    if(NULL!=send_terminal_cipher_text) {
        free(send_terminal_cipher_text);
        send_terminal_cipher_text = NULL;
        send_terminal_cipher_text_len = 0;
    }

    if(NULL!=from_proxy_plain_text) {
        free(from_proxy_plain_text);
        from_proxy_plain_text = NULL;
        from_proxy_plain_text_len =0;
    }

    if(NULL!=to_proxy_plain_text) {
        free(to_proxy_plain_text);
        to_proxy_plain_text=NULL;
    }

    return 1;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Prepare_error_response_packet
 *  Description:  Generate backward packet according to the error codes.
 * =====================================================================================
 */
int Prepare_error_response_packet(char *pkt, int error_code)
{
    int ret = 0;

    // all default values for the following fields are spaces.
    memset(pkt, ' ', VERIFY_PKT_HEADER_LENGTH);


    //Attation plz: the length of msg memo must be less than 45 characters.
    switch (error_code) {
    case ERROR_DECRYPT:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "1", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "decrypt cipher with srv_private_key, error!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_VALIDATE_SIGN:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "2", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "validate term_pkt with ukey_pub_key, error!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_LINK_PROXY:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "3", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "connect to proxy srv, link down!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_INCOMPLETE_PKT:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "4", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "parse verify_pkt header, incomplete!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_NO_TERMINAL_RSA_PUBKEY:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "5", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "find terminal ukey_pub_key, nothing!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_NO_SRV_RSA_PRIKEY:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "6", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "while finding server ukey rsa_private_key, error!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;
    case ERROR_MEMORY_LACK:
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, "7", VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_LENGTH);
        strncpy(pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION,
                "server memory, not enough!",
                VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
        break;

    default:
        break;
    }

    memset(pkt+VERIFY_PKT_PAYLOAD_LEN_POSITION, 0, VERIFY_PKT_PAYLOAD_LEN_LENGTH);

    return ret;


}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Parse_verify_pkt_header
 *  Description:  Parse the incoming packet from terminals
 * =====================================================================================
 */
int Parse_verify_pkt_header(char* pkt, int pkt_len, VerifyPacketHeader *pkt_header)
{
    if(NULL==pkt) {
        LOG(ERROR)<<"NULL==pkt pointer";
        return -1;
    }

    if(NULL==pkt_header) {
        LOG(ERROR)<<"NULL==pkt_header pointer";
        return -1;
    }

    if(pkt_len<VERIFY_PKT_HEADER_LENGTH) {
        LOG_ERROR("Verify packet header length, too short, %d bytes, less than standard length %d", pkt_len, VERIFY_PKT_HEADER_LENGTH);
        return -1;
    }

    bzero(pkt_header, sizeof(VerifyPacketHeader));

    memcpy(pkt_header->msg_type, pkt+VERIFY_PKT_MSG_TYPE_POSITION, VERIFY_PKT_MSG_TYPE_LENGTH);
    memcpy(pkt_header->terminal_id, pkt+VERIFY_PKT_TERMINAL_ID_POSITION, VERIFY_PKT_TERMINAL_ID_LENGTH);
    memcpy(pkt_header->worker_id, pkt+VERIFY_PKT_WORKER_ID_POSITION, VERIFY_PKT_WORKER_ID_LENGTH);
    memcpy(pkt_header->rsp_memo_type, pkt+VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION, VERIFY_PKT_RESPONSE_MSG_TYPE_FROM_VERIFY_SERVER_POSITION);
    memcpy(pkt_header->rsp_memo_txt, pkt+VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_POSITION, VERIFY_PKT_RESPONSE_MSG_FROM_VERIFY_SERVER_LENGTH);
    memcpy(&(pkt_header->payload_len), pkt+VERIFY_PKT_PAYLOAD_LEN_POSITION, VERIFY_PKT_PAYLOAD_LEN_LENGTH);

    DBG("Payload bytes: %d, pkt_len: %d, VERIFY_PKT_HEADER_LENGTH: %d.\n", pkt_header->payload_len, pkt_len, VERIFY_PKT_HEADER_LENGTH);

    //Examine the packet length whether it is valid or not.
    if(pkt_header->payload_len==pkt_len-VERIFY_PKT_HEADER_LENGTH) {

        //Good
        return 1;
    } else {

        //Bad
        return -1;
    }

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_terminal_pub_key_from_file
 *  Description:  Get terminal public key from PEM file or Binary file
 * =====================================================================================
 */
int Get_terminal_pub_key_from_file(RSA **terminal_pub_key, VerifyPacketHeader *pkt_hdr)
{
    int ret = 0;

    RSA * pub_key = NULL;

    //Generate the file name with the format PEM or Binary.
    char pem_filename[COMMON_LENGTH];
    bzero(pem_filename, COMMON_LENGTH);

    snprintf(pem_filename, COMMON_LENGTH, "%s_%s_pubkey.bin", pkt_hdr->terminal_id, pkt_hdr->worker_id);

    ret =  Generate_pub_key_from_file( &pub_key, pem_filename);
    //ret = Get_public_key_from_file(&pub_key, pem_filename);
    if(-1==ret) {
        *terminal_pub_key = NULL;
        return -1;
    } else {
        *terminal_pub_key = pub_key;
        return 1;
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_terminal_pub_key_from_db
 *  Description:  Connect to PostgreSQL to query the pubic key of rsa.
 * =====================================================================================
 */
int Get_terminal_pub_key_from_db(RSA *key, VerifyPacketHeader *pkt_header)
{

    int ret = 0;

    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    char * results_string = NULL;
    int  results_string_len = 0;

    char *pub_key_bin_buffer = NULL;

    if(NULL==key) {
        LOG(ERROR)<<"NULL==key,input parameters, failed.";
        OUTPUT_ERROR;
        return -1;
    }
    if(NULL==pkt_header) {
        LOG(ERROR)<<"NULL==pkt_header, input parameters, failed.";
        OUTPUT_ERROR;
        return -1;
    }


    //SQL string is created
    char query_string[MAX_QUERY_LENGTH];
    //char private_key_verify_server[MAX_TEMP_SIZE];

    bzero(query_string,MAX_QUERY_LENGTH);

    conn_db = Connect_db_server(global_par.system_par.verify_database_user[0],
                                global_par.system_par.verify_database_password[0],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[0]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

    //generate query string
    sprintf(query_string, "SELECT pub_key from t_terminal_ukey_pubkey where terminal_id=\'%s\';",
            (char*)(pkt_header->terminal_id) );

//    sprintf(query_string, "SELECT pub_key from t_terminal_ukey_pubkey where terminal_id=\'%s\'";",
    //          (char*)(pkt_header->terminal_id), (char*)(pkt_header->worker_id ));
    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        DLOG(INFO)<<query_string;
        DLOG(INFO)<<PQerrorMessage(conn_db);

    }

    /* If there are more than one records, return the first one */
    if (PQntuples(res)>=1) {

        /* Only return first tuple*/
        results_string = PQgetvalue(res,0,0);
        results_string_len = PQgetlength(res, 0, 0);

        DBG("\n%s |%s|\n", "RSA Get_terminal_pub_key:", results_string);
        DLOG(INFO)<<"RSA Get_terminal_pub_key:"<<results_string;

        pub_key_bin_buffer = unbase64((unsigned char*)results_string, strlen( results_string ));

//		results_string = base64(pub_key_bin_buffer, const unsigned char * input,int length)

        if(NULL!=pub_key_bin_buffer) {
            key = Convert_der_to_rsa_for_pub_key((unsigned char*)pub_key_bin_buffer, PUB_KEY_DER_LEN);
            if(NULL==key) {
                DBG("DER TO RSA, Error");
                LOG(ERROR)<<"Terminal pubkey DER TO RSA, Error.";
                ret = -1;
            }
        }
    }

    if(NULL!=pub_key_bin_buffer) {
        free(pub_key_bin_buffer);
        pub_key_bin_buffer = NULL;
    }


    PQclear(res);
    res = NULL;


    /* Free the DB resource */
    PQfinish((PGconn*)(conn_db));
    conn_db = NULL;

    return ret;

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_server_private_key_from_db
 *  Description:
 * =====================================================================================
 */
int Get_server_private_key_from_db(RSA **key)
{

    int ret = 0;

    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    char * results_string = NULL;
    int  results_string_len = 0;

    char *private_key_bin_buffer = NULL;

    int i =0;
    time_t t = 0;
    int verify_srv_num = 0;


    //SQL string is created
    char query_string[MAX_QUERY_LENGTH];
    bzero(query_string,MAX_QUERY_LENGTH);

    //choose the index of a verify server at random
    t = time(NULL);
    srand((unsigned int) t);
    verify_srv_num = global_par.system_par.verify_number;

    if(1==verify_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * verify_srv_num * rand() / (RAND_MAX + 1.0));

    }

    conn_db = Connect_db_server(global_par.system_par.verify_database_user[i],
                                global_par.system_par.verify_database_password[i],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[i]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

    //generate query string
    sprintf(query_string, "SELECT rsa_key FROM verify_srv_rsa where enable=1;");

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(ERROR)<<query_string;
        LOG(ERROR)<<PQerrorMessage(conn_db);

    }

    /* If there are more than one records, return the first one */
    if (PQntuples(res)>=1) {

        /* Only return first tuple*/
        results_string = PQgetvalue(res,0,0);
        results_string_len = PQgetlength(res, 0, 0);

        DBG("\n%s |%s|\n", "RSA Get_server_pri_key:", results_string);
        DLOG(INFO)<<"RSA Get_server_pri_key:"<<results_string;

        private_key_bin_buffer = str2binary((char*)results_string, strlen( results_string ));

//		results_string = base64(pub_key_bin_buffer, const unsigned char * input,int length)

        if(NULL!=private_key_bin_buffer) {
            *key = Convert_der_to_rsa_for_private_key((unsigned char*)private_key_bin_buffer, strlen( results_string )*2);
            if(NULL==*key) {
                DBG("DER TO RSA, Error");
                LOG(ERROR)<<"Server_pri_key DER TO RSA, Error.";
                ret = -1;
            }
        }
    }

    if(NULL!=private_key_bin_buffer) {
        free(private_key_bin_buffer);
        private_key_bin_buffer = NULL;
    }


    PQclear(res);
    res = NULL;


    /* Free the DB resource */
    PQfinish((PGconn*)(conn_db));
    conn_db = NULL;

    return ret;

}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Get_server_private_key_from_file
 *  Description:
 * =====================================================================================
 */
int Get_server_private_key_from_file(RSA **server_private_key, char* file_name)
{
    int ret = 0;
    RSA *key = NULL;

//    ret = Get_private_key_from_file(&key, (char *)"./openssl/yao_lagate.pem");
    ret = Get_private_key_from_file(&key, file_name);
    if(1==ret) {
        *server_private_key = key;
        return 1;
    } else {
        *server_private_key = NULL;
        return -1;
    }

}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Record_pkt_regular_table
 *  Description:  record the payment packets
 * =====================================================================================
 */
int Record_pkt_regular_table( char *pkt, int pkt_size,
                              PGconn *conn_db,
                              char* backward_pkt)
{
    return 1;
}



/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Connect_db_server
 *  Description:
 * =====================================================================================
 */
PGconn *Connect_db_server(char *user_name, char *password,char *db_name,char *ip_addr)
{
    PGconn  *conn;
    char conn_string[COMM_LENGTH];

    /* Check input parameters */
    if (NULL==ip_addr||NULL==user_name||NULL==password||NULL==db_name) {
        OUTPUT_ERROR;
        return NULL;
    }

    bzero(conn_string,COMM_LENGTH);
    sprintf(conn_string,"user=%s password=%s dbname=%s hostaddr=%s",user_name,password,db_name,ip_addr);
    DBG("Connect to DB: |%s|\n",conn_string);
    DLOG(INFO)<<"Connect to DB:" << conn_string;

    /* Connect the database */
    conn = PQconnectdb(conn_string);

    if (PQstatus(conn) != CONNECTION_OK) {
        LOG(ERROR)<<"Connect to DB, failed." << "detail: " <<conn_string;
        OUTPUT_ERROR;
        return NULL;
    }

    return conn;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  Load_server_private_key_from_file_into_db (char* file_name)
 *  Description:
 * =====================================================================================
 */
int Transform_server_private_key_from_file_into_db(char* file_name)
{
    int ret = 0;


    PGconn* conn_db = NULL;
    PGresult *res = NULL;

    int i =0;
    time_t t = 0;
    int verify_srv_num = 0;


//SQL string is created
    char query_string[MAX_QUERY_LENGTH];
    bzero(query_string,MAX_QUERY_LENGTH);

    RSA *server_private_key = NULL;


    unsigned char* srv_rsa_private_key_binary = NULL;
    int srv_rsa_private_key_binary_len = 0;

    char *srv_rsa_private_key_binary_string = NULL;
    int srv_rsa_private_key_binary_string_len = 0;


    //Read rsa from file with base64 format.
    ret = Get_server_private_key_from_file(&server_private_key, file_name);

    if(NULL==server_private_key) {
        LOG(ERROR)<<"Read private key of verify server, failed." << file_name;
        ret = 0;
        goto load_s_p_k_return;
    } else {
        DLOG(INFO)<<"Read private key of verify server, success!";
    }

    //Convert rsa format into der format
    srv_rsa_private_key_binary = Convert_rsa_to_der_for_private_key(server_private_key, &srv_rsa_private_key_binary_len);

    if(NULL!=srv_rsa_private_key_binary && 0!=srv_rsa_private_key_binary_len) {
        DLOG(INFO)<<"Convert rsa to binary, Success!";

        //convert der binary format to ASIICA format.
        srv_rsa_private_key_binary_string = Binary2str(srv_rsa_private_key_binary, srv_rsa_private_key_binary_len);
        if(NULL!=srv_rsa_private_key_binary_string) {
            srv_rsa_private_key_binary_string_len = srv_rsa_private_key_binary_len *2;
            //One Byte -> 2 Numbers
            DLOG(INFO)<<"Private key string length:" << srv_rsa_private_key_binary_string_len
                      <<"ASIIC :" <<srv_rsa_private_key_binary_string;
        } else {
            ret = 0;
            LOG(ERROR)<<"Convert rsa binary to ASIIC string, failed.";
            goto load_s_p_k_return;
        }


    } else {
        LOG(ERROR)<<"Convert rsa to binary, Failed.";
        ret = 0;
        goto load_s_p_k_return;
    }



//choose the index of a verify server at random
    t = time(NULL);
    srand((unsigned int) t);
    verify_srv_num = global_par.system_par.verify_number;

    if(1==verify_srv_num) {
        i = 0;
    } else {
        i = 0 + (int) ( 1.0 * verify_srv_num * rand() / (RAND_MAX + 1.0));

    }

    conn_db = Connect_db_server(global_par.system_par.verify_database_user[i],
                                global_par.system_par.verify_database_password[i],
                                global_par.system_par.verify_database_name,
                                global_par.system_par.verify_ip_addr_array[i]);
    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

//generate query string
    sprintf(query_string, "INSERT INTO verify_srv_rsa(rsa_key) values (trim(\'%s\'));", srv_rsa_private_key_binary_string);

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Query: SQL string", query_string);
    DLOG(INFO)<<"Query: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(ERROR)<<query_string;
        LOG(ERROR)<<PQerrorMessage(conn_db);

    }

load_s_p_k_return:
    if(NULL!=server_private_key) {
        free(server_private_key);
        server_private_key = NULL;
    }

    if(NULL!=srv_rsa_private_key_binary) {
        free(srv_rsa_private_key_binary);
        srv_rsa_private_key_binary = NULL;
        srv_rsa_private_key_binary_len = 0;
    }

    if(NULL!=srv_rsa_private_key_binary_string) {
        free(srv_rsa_private_key_binary_string);
        srv_rsa_private_key_binary_string = NULL;
        srv_rsa_private_key_binary_string_len = 0;
    }

    return ret;
}

