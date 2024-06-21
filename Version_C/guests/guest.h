#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
static void outb(uint16_t port, uint8_t value) 
{
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static uint8_t inb(uint16_t port) 
{
	uint8_t value;
	asm("inb %1,%0" : "=a" (value) :	 "Nd" (port) );
	return value;
}

void print_str(const char *str)
{
    while (*str) {
        outb(0xE9, *str++);
    }
}

void write(const char* p)
{
    // for (p = "\nHello, world!\n"; *p; ++p)
    for (; *p; ++p)

		outb(0xE9, *p);

}

void write_int(int id)
{

    outb(0xE9, '\n');
	outb(0xE9, id);
    outb(0xE9, '\n');

}

void read(const char* id)
{
    uint8_t value = 0;
	while( (value = inb(0xE9) ) != '-'){
		print_str(id);
		outb(0xE9, value);
	}
}

char* int_to_str(int num,char * buffer) {
    
    int is_negative = 0;
    int index = 0;

    if (num == 0) {
        buffer[index++] = '0';
        buffer[index] = '\0';
        return buffer;
    }

    if (num < 0) {
        is_negative = 1;
        num = -num;  
    }

    // Convert each digit to a character in reverse order
    while (num != 0) {
        buffer[index++] = (num % 10) + '0';
        num /= 10;
    }

    if (is_negative) {
        buffer[index++] = '-';
    }

    buffer[index] = '\0';

    // Reverse the string to get the correct order
    for (int i = 0; i < index / 2; ++i) {
        char temp = buffer[i];
        buffer[i] = buffer[index - i - 1];
        buffer[index - i - 1] = temp;
    }

    return buffer;
}
enum op{OPEN, READ, WRITE, CLOSE};

int file_open(const char* filename, int mode)
{
    // 0 - rw, 1 - r -> KONVENCIJA
    outb(0x0278, OPEN + '0');
    outb(0x0278, '%');
    outb(0x0278, mode + '0');
    outb(0x0278, '%');
    while (*filename)
        outb(0x0278, *filename++);
    outb(0x0278, '\0');

    int fd = 0;
    int digit = 0;
    // fd = inb(0x0278);
    while ( (digit = inb(0x0278)) != '\0')
    {
        // outb(0xE9,digit);
        digit = digit - '0';
        fd *=10;
        fd += digit ;
        // outb(0xE9, fd);
    }
    return fd;
}

int file_read(int fd, char* buffer, const char* size, int buffer_size){
    outb(0x0278, READ + '0');
    outb(0x0278, '%');
    outb(0x0278, fd + '0');
    outb(0x0278, '%');
    while (*size)
        outb(0x0278, *size++);
    outb(0x0278, '\0');

    size_t bytes_read = 0;
    while (bytes_read < buffer_size) {
        uint8_t digit = inb(0x0278);
        // outb(0xE9,digit);
        if (digit == '\0') {
            break;  // Kraj stringa
        }
        buffer[bytes_read++] = digit;
    }

  
    return bytes_read;
}

void file_write(int fd, const char* buffer, int size){

    char size_buffer[12];
    char* size_str = int_to_str(size,size_buffer);


    outb(0x0278, WRITE + '0');
    outb(0x0278, '%');
    outb(0x0278, fd + '0');
    outb(0x0278, '%');

    //OVO MI NIJE POTREBNO JER MOGU U HIPERVIZORU DA PRIMIM STRING I DA UZMEM DUZINU TOG STRINGA STO CE BITI OVAJ SIZE
    // A KAD BIH SLAO OVAJ SIZE ONDA BIH MORAO DA NAPRAVIM MASINU STANJA SA 3 ZNAKA % , OVAKO OSTAJE SA 2 !!!
    // while (*size_str){
    //     // write(size_str);
    //     outb(0x0278, *size_str++);
    // }
    // outb(0x0278, '%');

    // for (int i = 0; i < size; i++) {
    //     write(buffer);
    //     outb(0x0278, buffer[i]);
    // }
     while (*buffer){
        // write(buffer);
        outb(0x0278, *buffer++);
    }
    outb(0x0278, '\0');
   
}


void file_close(int fd){
    outb(0x0278, CLOSE + '0');
    outb(0x0278, '%');
    outb(0x0278, fd + '0');
    outb(0x0278, '%');
    outb(0x0278, '\0');
}
