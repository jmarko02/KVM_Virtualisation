#include "guest.h"

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	const char *p;
	uint16_t port = 0xE9;
	const char* id = "1";

	int buffer_size = 1024;
	const char* buffer_size_ptr = "1024";
    char buffer[buffer_size];
	// char buffer[6] = {'M','A','R','K','O','\0'};

	// read(id);
	// write("Pozdrav od Marka\n");

 	const char* file_name1 = "flowers.txt";
	int fd1 = file_open(file_name1, 0); //0 za rw, 1 za r
	// write_int(fd1);
	//citanje i pisanje u fajl...
	int bytes_read = file_read(fd1,buffer,buffer_size_ptr,buffer_size);
	if (bytes_read > 0) {
    	buffer[bytes_read] = '\0';  // Završavamo string
    	
		for(int i = 0 ; i < bytes_read; i++){
			outb(0xE9,buffer[i]);
		}
		
	} else {
    	// printf("No data read or error occurred.\n");
		// write("guest je procitao 0 bajtova nesto ne valja\n\n");
	}

	file_write(fd1, buffer, bytes_read);

    // write("SALJEM ZAHTEV ZA CLOSE\n");
	// write_int(fd1);
	file_close(fd1);

	for (;;)
		asm("hlt");
}
