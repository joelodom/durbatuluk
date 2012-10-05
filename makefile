GTEST_DIR = gtest-1.6.0

CC = g++
LINK = g++

INCLUDES = -I.
INCLUDES +=-I$(GTEST_DIR)
INCLUDES +=-I$(GTEST_DIR)/include

OBJS = gtest.o

SRCS = durbatuluk.cc
SRCS += durbatuluk_tests.cc
SRCS += crypto_tests.cc

LIBS = -lpthread
LIBS += -lcrypto
LIBS += -lssl

all: $(OBJS)
	$(CC) $(OBJS) $(INCLUDES) -Wall -std=c++0x $(SRCS) -o durbatuluk $(LIBS)

gtest.o:
	$(CC) $(INCLUDES) -c ${GTEST_DIR}/src/gtest-all.cc -o gtest.o

clean:
	rm -f *.o *.a durbatuluk