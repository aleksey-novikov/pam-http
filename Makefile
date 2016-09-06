CFLAGS += -Werror -Wall
all: pam_http.so

clean:
	$(RM) test pam_http.so *.o

pam_http.so: pam_http.c
	$(CC) $(CFLAGS) -fPIC -shared -Xlinker -x -o $@ $< -lcurl -lpam


