# This is for OpenSSL test unit
# 2012-12-21

PROJECT=openssl_test_unit
TARGET=otu.exe

CC=g++
AR=ar

ifdef REL
	CFLAGS=-O2 -s -DNDEBUG
	TARGET=release_test.exe
else
	CFLAGS=-g -Wall -DDEBUG -O0
	TARGET=gdb_test.exe
endif

INC_DIR_FLAGS=-I /usr/include
LIB_OPTIONS=-lglog -lcrypto

OBJS=open_ssl_main.o openssl_sign_encrypt_rsa.o

$(TARGET):$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LIB_OPTIONS)

$(OBJS):%.o:%.c
	$(CC) -c $(CFLAGS) $(INC_DIR_FLAGS) $< -o $@

<BS>.PHONY:clean
clean:
	-rm -frv $(TARGET) $(OBJS) log.txt* UNKNOW*.*

.PHONY:pp
pp:
	-find ./ -name "*" -print |egrep '\.cpp$$|\.c$$|\.h$$' |xargs astyle --style=linux -s -n;

