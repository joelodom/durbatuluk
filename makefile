GTEST_DIR = gtest-1.6.0

CC = g++
LINK = g++

INCLUDES = -I.
INCLUDES +=-I$(GTEST_DIR)
INCLUDES +=-I$(GTEST_DIR)/include

OBJS = gtest.o

SRCS = durbatuluk.cc
SRCS += durbatuluk_tests.cc

all: $(OBJS)
	$(CC) $(OBJS) $(INCLUDES) -lpthread -Wall $(SRCS) -o durbatuluk

gtest.o:
	$(CC) $(INCLUDES) -c ${GTEST_DIR}/src/gtest-all.cc -o gtest.o

clean:
	rm -f *.o *.a durbatuluk
