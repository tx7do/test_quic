#include "stdinc.h"


int main()
{
	if (0 != lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER))
	{
		exit(EXIT_FAILURE);
	}

	lsquic_global_cleanup();
	exit(EXIT_SUCCESS);

	return 0;
}
