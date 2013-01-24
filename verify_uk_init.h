/*
 * =====================================================================================
 *
 *       Filename:  verify_uk_init.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  1/22/2013 7:14:15 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */

#ifndef  VERIFY_UK_INIT_H_INC
#define  VERIFY_UK_INIT_H_INC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include "libpq-fe.h"
#include "shmsem.h"

#include "verify_uk_common.h"
#include "verify_uk_monitor_process.h"



int Init_process_manager_share_memory(int share_id);
int Setup_config_parameters(void);
int Init_verify_data_socket(int port,int *welcome_sd, struct sockaddr_in *sa);
int Start_network_service(int port,int *welcome_sd, struct sockaddr_in *sa, const char* s);

int Start_monitor_process(void);
int Start_life_time_counter_process(void);




#endif   /* ----- #ifndef VERIFY_UK_INIT_H_INC  ----- */
