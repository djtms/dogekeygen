CC		= gcc
CFLAGS	= -I. -L. -Wl,--subsystem,windows -s -Wall -Wextra -std=c11 -pedantic
LIBS	= -lcrypto -lgdi32

all:
	$(CC) $(CFLAGS) dogekeygen.c $(LIBS) -o dogekeygen

clean:
	del *.exe