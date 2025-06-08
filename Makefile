pseudoudp : pseudoudp.c
	gcc -o pseudoudp pseudoudp.c -lpcap

clean :
	rm pseudoudp

