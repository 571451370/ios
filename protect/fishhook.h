#ifndef PROTECT_FISHHOOK_H
#define PROTECT_FISHHOOK_H

#include <stddef.h>
#include <stdint.h>

struct rebinding {
	const char *name;
	void *replacement;
	void **replaced;
};

int protect_rebind_symbols(struct rebinding rebindings[], size_t nel);
int protect_rebind_symbols_image(void *header, intptr_t slide, struct rebinding rebindings[], size_t nel);

#endif
