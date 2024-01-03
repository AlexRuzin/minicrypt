# Dynmically linkable library that contains the cryptopgrahic exports
LIBCRYPTNAME=libcryptprov

# CLI application that implements cryptprov
EXECUTABLE=crypt

# Test application
TESTCRYPT=testcrypt

# util library
UTIL=util

# Directories
SRCDIR=../src
LIBDIR=../lib
BINDIR=../bin
INCDIR=../include
BUILDDIR=../build

CC=gcc
CFLAGS=-g -Os -std=c99 -Wall -Wextra -I$(INCDIR)
LIB_CFLAGS=$(CFLAGS) -fPIC -shared
LDFLAGS=-L$(LIBDIR)
LIBS=-lcryptprov

all: util.o lib $(EXECUTABLE).o $(EXECUTABLE) $(TESTCRYPT).o $(TESTCRYPT)

lib:
	$(CC) $(LIB_CFLAGS) $(SRCDIR)/$(LIBCRYPTNAME)/$(LIBCRYPTNAME).c -o $(LIBDIR)/$(LIBCRYPTNAME).so

# crypt linked
$(EXECUTABLE): $(BUILDDIR)/$(EXECUTABLE).o
	$(CC) $(CFLAGS) $(BUILDDIR)/$(EXECUTABLE).o $(BUILDDIR)/$(UTIL).o -o $(BINDIR)/$(EXECUTABLE) $(LDFLAGS) $(LIBS)

# crypt object
$(EXECUTABLE).o: $(SRCDIR)/cryptmain.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/cryptmain.c -o $(BUILDDIR)/$(EXECUTABLE).o

# testcrypt linked
$(TESTCRYPT): $(BUILDDIR)/$(TESTCRYPT).o
	$(CC) $(CFLAGS) $(BUILDDIR)/$(TESTCRYPT).o $(BUILDDIR)/$(UTIL).o -o $(BINDIR)/$(TESTCRYPT) $(LDFLAGS) $(LIBS)

# testcrypt object
$(TESTCRYPT).o: $(SRCDIR)/testcrypt.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/testcrypt.c -o $(BUILDDIR)/$(TESTCRYPT).o

# util object
$(UTIL).o: $(SRCDIR)/util.c
	$(CC) $(CFLAGS) -c $(SRCDIR)/util.c -o $(BUILDDIR)/$(UTIL).o

clean:
	rm -f *.o $(BINDIR)/* $(BUILDDIR)/* $(EXECUTABLE) $(LIBDIR)/*.so $(LIBDIR)/$(LIBCRYPTNAME)/*.so