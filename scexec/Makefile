CC ?= gcc
STRIP ?= strip
# STRIPFLAGS += -sx
CFLAGS += -Wall -Os 
#CFLAGS += -DDEBUG=1
# CFLAGS += -static
CFLAGS64 += -fPIC 
OUT ?= scexec

32:
	$(CC) scexec.c -o $(OUT) $(CFLAGS)
	$(STRIP) $(STRIPFLAGS) $(OUT)

64:
	$(CC) scexec.c $(CFLAGS64) -o $(OUT) $(CFLAGS)
	$(STRIP) $(STRIPFLAGS) $(OUT)
