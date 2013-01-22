
#ifndef  VERIFY_UK_VERIFY_H_INC
#define  VERIFY_UK_VERIFY_H_INC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "verify_uk_common.h"
#include "parse_pkt_common_header.h"
#include "verify_uk_monitor_process.h"
#include "libpq-fe.h"
#include "business_data_analysis.h"
#include "multi_recvsend.h"

int Do_verify_procedures(int connection_sd,char *packet,int packet_size);
int Record_pkt_regular_table( char *pkt, int pkt_size,PGconn *conn_db, char* backward_pkt);
int Get_back_pkt_for_business_srv(char *pkt,int pkt_size, char* backward_pkt);


#endif   /* ----- #ifndef VERIFY_UK_VERIFY_H_INC  ----- */
