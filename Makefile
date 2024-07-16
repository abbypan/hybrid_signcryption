
#CFLAGS      = -std=c99 -pedantic -Wall -g -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-overlength-strings
INCLUDES    = -I/usr/local/include
LFLAGS      = -L/usr/local/lib
#LIBS        = -lssl -lcrypto -pthread -lm -ldl -lcbor
LIBS        = -lssl -lcrypto 

#CFLAGS     += -fsanitize=address -fno-omit-frame-pointer -g
#CFLAGS     += -fsanitize=memory -fno-omit-frame-pointer -g -fsanitize-memory-track-origins

# Linux example
#INCLUDES   = -I$(HOME)/my-openssl/include
#LFLAGS     = -L$(HOME)/my-openssl/lib

# mac OS example
#INCLUDES   = -I/usr/local/opt/openssl@1.1/include
#LFLAGS	    = -L/usr/local/opt/openssl@1.1/lib

all     : hybrid_sc hybrid_sc_multi hybrid_sc_print
	
hybrid_sc: hybrid_sc.c
	$(CC) $(CFLAGS) $(INCLUDES) -o hybrid_sc hybrid_sc.c $(LFLAGS) $(LIBS)

hybrid_sc_print: hybrid_sc_print.c
	$(CC) $(CFLAGS) $(INCLUDES) -o hybrid_sc_print hybrid_sc_print.c $(LFLAGS) $(LIBS)

hybrid_sc_multi: hybrid_sc_multi.c
	$(CC) $(CFLAGS) $(INCLUDES) -o hybrid_sc_multi hybrid_sc_multi.c $(LFLAGS) $(LIBS)

clean:
	rm -f hybrid_sc
	rm -f hybrid_sc_multi
	rm -f hybrid_sc_print
