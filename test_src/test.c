#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/mman.h>

int
universe()
{
	return 42;
}

int
main(void)
{
	int (*p)(void);
	void *src;

	p = universe;
	
	if((src = mmap(0, sizeof(p()), PROT_EXEC|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		printf("Error!!!!\n");
	}

	memcpy(src, p, sizeof(p()));

	return 0;
}

