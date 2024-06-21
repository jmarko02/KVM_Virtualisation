#include "guest.h"

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;
	uint16_t port = 0xE9;
	
	uint8_t value = 0;
	while( (value = inb(0xE9) ) != '-'){
		print_str("1");
		outb(0xE9, value);
	}

	for (p = "\nHello, world!\n"; *p; ++p)

		outb(0xE9, *p);

	for (;;)
		asm("hlt");
}
