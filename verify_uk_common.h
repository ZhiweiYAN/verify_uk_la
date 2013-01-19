
#ifndef  VERIFY_UK_COMMON_H_INC
#define  VERIFY_UK_COMMON_H_INC

#include <time.h>
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
#include <assert.h>

#include "libpq-fe.h"

#include <glog/logging.h>
#include "../config_h_c/config.h"



#ifdef DEBUG
# define DBG(format, args...) printf(format, ##args)
#else
# define DBG(format, args...)
#endif

#define OUTPUT_OK do{printf("[\033[32mOK\033[0m]\n");fflush(NULL);}while(0);
#define OUTPUT_ERROR do{ printf("[\033[31mERROR\033[0m] %s:%d,%s()\n",__FILE__, __LINE__, __FUNCTION__);LOG(ERROR)<<__FUNCTION__;fflush(NULL);}while(0);

#endif   /* ----- #ifndef VERIFY_UK_COMMON_H_INC  ----- */

