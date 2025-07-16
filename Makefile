# Copyright (c) 2025 nuel-ch
pseudoudp : pseudoudp.c
	gcc -o pseudoudp pseudoudp.c -lpcap

clean :
	rm pseudoudp

