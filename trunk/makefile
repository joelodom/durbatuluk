GTEST_DIR = gtest-1.6.0

CC = g++
LINK = g++

INCLUDES = -I.
INCLUDES +=-I$(GTEST_DIR)
INCLUDES +=-I$(GTEST_DIR)/include

OBJS = gtest.o

SRCS = durbatuluk.cc
SRCS += durbatuluk_tests.cc
SRCS += durbatuluk.pb.cc
SRCS += openssl_aes.cc
SRCS += crypto.cc
SRCS += crypto_tests.cc
SRCS += message_handler.cc
SRCS += message_handler_tests.cc
SRCS += base64.cc
SRCS += base64_tests.cc
SRCS += encoding.cc
SRCS += encoding_tests.cc
SRCS += processing_engine.cc
SRCS += processing_engine_tests.cc
SRCS += logger.cc
SRCS += keyfile.cc
SRCS += keyfile_tests.cc
SRCS += net_fetcher.cc
SRCS += net_fetcher_tests.cc

LIBS = -lpthread
LIBS += -lcrypto
LIBS += -lssl
LIBS += -lprotobuf
LIBS += -lcurl

all: $(OBJS)
	$(CC) $(OBJS) $(INCLUDES) -Wall -std=c++0x $(SRCS) -o durbatuluk $(LIBS)

gtest.o:
	$(CC) $(INCLUDES) -c ${GTEST_DIR}/src/gtest-all.cc -o gtest.o

clean:
	rm -f *.o *.a durbatuluk
