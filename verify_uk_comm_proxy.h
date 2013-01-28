/*
 * =====================================================================================
 *
 *       Filename:  verify_uk_comm_proxy.h
 *
 *    Description:  functions with communication, such as socket programming.
 *
 *        Version:  1.0
 *        Created:  1/28/2013 1:28:16 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */

#ifndef  VERIFY_UK_COMM_PROXY_H_INC
#define  VERIFY_UK_COMM_PROXY_H_INC

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "verify_uk_common.h"

int SendRecv_message_to_proxy(char *msg_to_proxy, int msg_to_proxy_length, char*msg_from_proxy,	int *msg_from_proxy_len);
int Read_proxy_parameters(char *proxy_addr_array,int *proxy_data_port);

#endif   /* ----- #ifndef VERIFY_UK_COMM_PROXY_H_INC  ----- */
