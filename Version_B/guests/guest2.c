#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}
static uint8_t inb(uint16_t port) {
	uint8_t value;
	asm("inb %1,%0" : "=a" (value) :	 "Nd" (port) );
	return value;
}

void print_str(const char *str) {
    while (*str) {
        outb(0xE9, *str++);
    }
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;
	uint16_t port = 0xE9;
	
	uint8_t value = 0;
	while( (value = inb(0xE9) ) != '-'){
		print_str("2");
		outb(0xE9, value);
	}

	for (p = "\nHello, world!\n"; *p; ++p)

		outb(0xE9, *p);

	for (;;)
		asm("hlt");
}
