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
	int (*p)(void) = universe;
	void *src;

	if((src = mmap(0, sizeof(universe), PROT_EXEC|PROT_WRITE, MAP_SHARED, p(), 0)) == MAP_FAILED) {
		printf("Error!!!!\n");
	}

	return 0;
}

