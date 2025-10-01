#include <stdint.h>

#define file_port 0x278
#define open_code 0xFF
#define fputc_code 0xFE
#define fgetc_code 0xFD
#define close_code 0xFC
#define mode_read 0xFB
#define mode_write 0xFA
#define mode_rdwr 0xF9

static void outb(uint16_t port, uint8_t value) {
	asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}
static uint8_t inb(uint16_t port){
	uint8_t rtn;
	asm("inb %1,%0" : "=a"(rtn) : "Nd"(port));
	return rtn;
}

uint8_t open_file(char* file, uint8_t open_mode){
	outb(file_port, open_code);
	int i = 0;
	do{
		outb(file_port, file[i]);
	}while(file[i++] != '\0');
	outb(file_port, open_mode);
	return inb(file_port);
}

void fputc(uint8_t data, uint8_t file){
	outb(file_port, fputc_code);
	outb(file_port, file);
	outb(file_port, data);
}

uint8_t fgetc(uint8_t file){
	outb(file_port, fgetc_code);
	outb(file_port, file);
	return inb(file_port);
}

void close_file(uint8_t file){
	outb(file_port, close_code);
	outb(file_port, file);
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;
	uint16_t port = 0xE9;
	char file_name[] = "text.txt";

	uint8_t fd = open_file(file_name, mode_write);
	for(int i=0; i < 10; i++){
		fputc('0' + i, fd );
	}

	close_file(fd);


	fd = open_file(file_name, mode_read);

	for(int i=0; i < 20; i++){
		char temp = fgetc(fd);
		outb(0xE9, temp);
	}


	//for (p = "Hello, world!\n"; *p; ++p)
	//	outb(0xE9, *p);

	for (;;)
		asm("hlt");
}
