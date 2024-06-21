#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "guest.h"
void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;
	uint16_t port = 0xE9;
	const char* id = "2";
	
	// read(id);
	// write(p);
	int buffer_size = 1024;
	const char* buffer_size_ptr = "1024";
	char buffer[buffer_size];

	// read(id);
	// write("Pozdrav od Marka\n");

 	const char* file_name = "flowers.txt";
	const char* file_name1 = "najjaciUKafani.txt";
	
	int fd1 = file_open(file_name, 1); //0 za rw, 1 za r
	// write_int(fd1);
	int fd2 = file_open(file_name1, 0);
	//citanje i pisanje u fajl...
	int bytes_read = file_read(fd1,buffer,buffer_size_ptr,buffer_size);
	if (bytes_read > 0) {
    	buffer[bytes_read] = '\0';  // Završavamo string
    	
		for(int i = 0 ; i < bytes_read; i++){
			// outb(0xE9,buffer[i]);
		}
		
	} else {
    	// printf("No data read or error occurred.\n");
		write("guest je procitao 0 bajtova nesto ne valja\n\n");
	}
	file_write(fd2, buffer, bytes_read);
	
	// write("SALJEM ZAHTEV ZA CLOSE\n");
	// write_int(fd1);
	// write_int(fd2);
	file_close(fd1);
	file_close(fd2);
	for (;;)
		asm("hlt");
}
