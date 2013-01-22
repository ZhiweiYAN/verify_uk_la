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
int Do_verify_procedures(int connection_sd,char *packet,int packet_size)
{
    int success = 0;

    PGconn* conn_db = NULL;

    char send_terminal[MAXPACKETSIZE];
    ssize_t count = 0;
    int com_id = 0;

	//get verifing-packet header

	//parse the verifing-packet header

	//get the public key of clients and the private key of verify server.


    bzero(send_terminal, MAXPACKETSIZE);
    conn_db = Connect_db_server(global_par.system_par.database_user[0],
                                global_par.system_par.database_password[0],
                                global_par.system_par.database_name,
                                global_par.system_par.localhost_ip_address);


    if (NULL==conn_db) {
        OUTPUT_ERROR;
        return -1;
    }

    /* Free the DB resource */
    PQfinish((PGconn*)(conn_db));
    conn_db = NULL;

	//verify the packet of terminals.


	//connect to proxy server as random mode.


	//

	

    if (0!=success) {
        OUTPUT_ERROR;
    }

    count = send(connection_sd, send_terminal, strlen(send_terminal), 0 );
    DBG("\n%s |%s|\n","send to Teminal",send_terminal);

    if (0>count) {
        OUTPUT_ERROR;
    }



    return 1;
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
    char query_string[MAX_QUERY_LENGTH];
    int success = 0;
    PGresult *res = NULL;
    char *back_pkt = NULL;
    char *fwd_pkt = NULL;

    struct CompoundPacketInfo com_pkt_info;

    if (NULL==pkt) {
        OUTPUT_ERROR;
        return -1;
    }
    if (0>=pkt_size) {
        OUTPUT_ERROR;
        LOG(INFO)<<pkt;
        return -1;
    }

    if (NULL==conn_db) {
        OUTPUT_ERROR;
        LOG(INFO)<<pkt;
        return -1;
    }

    if (NULL==backward_pkt) {
        OUTPUT_ERROR;
        LOG(INFO)<<pkt;
        return -1;
    }

    bzero(&com_pkt_info,sizeof(struct CompoundPacketInfo));
    success = Get_compound_pkt_info(pkt, pkt_size,&com_pkt_info);

    /* allocate the backward packet memory and reconstruct the backward packet */
    back_pkt = (char *)malloc(pkt_size+1);
    if (NULL==back_pkt) {
        OUTPUT_ERROR;
        return -1;
    }
    bzero(back_pkt,pkt_size+1);

    memcpy(back_pkt, pkt, PACKET_HEADER_LENGTH);
    memcpy(back_pkt+PACKET_HEADER_LENGTH,
           pkt+PACKET_HEADER_LENGTH+com_pkt_info.forward_pkt_len,
           com_pkt_info.backward_pkt_len);
    memset(back_pkt+PACKET_HEADER_LENGTH-ERROR_MEMO_LENGTH,
           ' ',
           ERROR_MEMO_LENGTH);

    /* allocate the forward packet memory and reconstruct the forward packet */
    fwd_pkt = (char *)malloc(pkt_size+1);
    if (NULL==fwd_pkt) {
        OUTPUT_ERROR;
        return -1;
    }
    bzero(fwd_pkt,pkt_size+1);
    memcpy(fwd_pkt, pkt, PACKET_HEADER_LENGTH);
    memcpy(fwd_pkt+PACKET_HEADER_LENGTH,
           pkt+PACKET_HEADER_LENGTH,
           com_pkt_info.forward_pkt_len);
    memset(fwd_pkt+PACKET_HEADER_LENGTH-ERROR_MEMO_LENGTH,
           ' ',
           ERROR_MEMO_LENGTH);

    //SQL string is created
    bzero(query_string,MAX_QUERY_LENGTH);

    if (INVOICE_DB == Get_ownself_server_type()) {
        success = Generate_company_record_with_invoice_from_two_packet(fwd_pkt,
                  strlen(fwd_pkt),
                  back_pkt,strlen(back_pkt),
                  query_string,
                  MAX_QUERY_LENGTH);
    } else {
        success = Generate_company_record_from_two_packet(fwd_pkt,
                  strlen(fwd_pkt),
                  back_pkt,strlen(back_pkt),
                  query_string,
                  MAX_QUERY_LENGTH);

    }

    /* Send the query to primary database */
    res = PQexec(conn_db, query_string);
    DBG("\n%s |%s|\n","Record: SQL string", query_string);
	LOG(INFO)<<"Record: SQL string: "<<query_string;

    /* Did the record action fail in the primary database? */
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        OUTPUT_ERROR;
        perror(query_string);
        perror(PQerrorMessage(conn_db));

        LOG(INFO)<<query_string;
        LOG(INFO)<<PQerrorMessage(conn_db);

        success = Change_packet_response_code(back_pkt,strlen(back_pkt),DB_ERROR_RECORDSQL);
    }
    memcpy(backward_pkt, back_pkt, strlen(back_pkt));

    PQclear(res);
    res = NULL;

    free(back_pkt);
    back_pkt = NULL;
    free(fwd_pkt);
    fwd_pkt = NULL;

    return success;
}


int Get_back_pkt_for_business_srv(char *pkt,int pkt_size, char* backward_pkt)
{
    int success = 0;
    char *back_pkt = NULL;

    struct CompoundPacketInfo com_pkt_info;

    bzero(&com_pkt_info,sizeof(struct CompoundPacketInfo));
    success = Get_compound_pkt_info(pkt, pkt_size,&com_pkt_info);

    back_pkt = (char *)malloc(pkt_size+1);
    if (NULL==back_pkt) {
        OUTPUT_ERROR;
        return -1;
    }
    bzero(back_pkt,pkt_size+1);

    /* Reconstruct the backward packet */
    memcpy(back_pkt,pkt,PACKET_HEADER_LENGTH);
    memcpy(back_pkt+PACKET_HEADER_LENGTH,pkt+PACKET_HEADER_LENGTH+com_pkt_info.forward_pkt_len,com_pkt_info.backward_pkt_len);
    memset(back_pkt+PACKET_HEADER_LENGTH-ERROR_MEMO_LENGTH,' ',ERROR_MEMO_LENGTH);
    memcpy(backward_pkt, back_pkt,strlen(back_pkt));

    free(back_pkt);
    back_pkt = NULL;

    return 1;
}


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
	LOG(INFO)<<"Connect to DB:" << conn_string;
	
    /* Connect the database */
    conn = PQconnectdb(conn_string);

    if (PQstatus(conn) != CONNECTION_OK) {
		LOG(ERROR)<<"Connect to DB, failed." << "detail: " <<conn_string;
        OUTPUT_ERROR;
        return NULL;
    }

    return conn;
}


