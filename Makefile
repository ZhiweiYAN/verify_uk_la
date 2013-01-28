# #####################################################
#This software is designed for LIAN Company.
#It begins in Nov 15, 2012
# ####################################################

PROJECT=LIAN_VERIFY_UK_SERVER

CC=g++
AR=ar

ifdef REL
CFLAGS= -O2 -s -DNDEBUG 
TARGET=run_gdlian_verify_uk_release_version
else
CFLAGS= -g -Wall -DDEBUG -O0 -gdwarf-2 -g3
TARGET=run_gdlian_db_verify_uk_debug_version
endif

ifdef LIAN
PG_INC=-I /usr/local/pgsql/include
PG_LIB=-L /usr/local/pgsql/lib
else
PG_INC=-I /usr/include/postgresql
PG_LIB=-L /usr/lib
endif

GLOG_INC=-L /usr/include
GLOG_LIB=-L /usr/lib

INC_DIR_FLAGS=$(GLOG_INC) $(PG_INC)

OBJS=verify_uk_main.o  verify_uk_init.o \
		shmsem.o verify_uk_start.o verify_uk_monitor_process.o  \
		verify_uk_verify.o verify_uk_comm_proxy.o\
		./openssl/openssl_sign_encrypt_rsa.o \
		../config_h_c/config.o


$(TARGET): $(OBJS) 
	$(CC) -o $(TARGET) $(PG_LIB) -lpq  $(GLOG_LIB) -lglog $(OBJS)  -lcrypto

$(OBJS):%.o:%.c
	$(CC) -c $(CFLAGS) $(INC_DIR_FLAGS) $< -o $@

.PHONY:clean
clean:
	find ./ -name "*.o" |xargs rm -R -v --force
	find ./ -name "log*.*" |xargs rm -R -v --force
	find ./ -name "*.orig" |xargs rm -R -v --force
	find ./ -name "*.bak" |xargs rm -R -v --force
	rm --force $(TARGET) 
	rm --force *.bak
	rm --force *.orig
	rm --force log_error.txt
	rm --force *.log
	rm --force ./log/*.*
	rm --force run_*
.PHONY:pp
pp:
	-find ./ -name "*" -print |egrep '\.cpp$$|\.c$$|\.h$$' |xargs astyle --style=linux -s -n;

