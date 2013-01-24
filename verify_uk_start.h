/*
 * =====================================================================================
 *
 *       Filename:  verify_uk_init.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  1/19/2013 10:32:29 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Zhi-wei YAN (Jerod YAN), jerod.yan@gmail.com
 *        Company:  DrumTm
 *
 * =====================================================================================
 */

#ifndef  VERIFY_UK_START_H_INC
#define  VERIFY_UK_START_H_INC

#include "verify_uk_common.h"
#include "verify_uk_init.h"
#include "verify_uk_monitor_process.h"
#include "verify_uk_verify.h"


int Init_verify_uk_server(void);
int Daemon_db_verify_uk_server(int welcome_sd,struct sockaddr_in *sa);


#endif   /* ----- #ifndef VERIFY_UK_INIT_H_INC  ----- */
