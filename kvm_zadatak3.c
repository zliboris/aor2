// Prevođenje:
//    make
// Pokretanje:
//    ./kvm_zadatak3 guest.img
//
// Koristan link: https://www.kernel.org/doc/html/latest/virt/kvm/api.html
//                https://docs.amd.com/v/u/en-US/24593_3.43
//
// Zadatak: Omogućiti ispravno izvršavanje gost C programa. Potrebno je pokrenuti gosta u long modu.
//          Podržati stranice veličine 4KB i 2MB.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/stat.h>

#define GUEST_START_ADDR 0x10000 // Početna adresa za učitavanje gosta

#define MAX_GUESTS 1024
#define MAX_SHARED_FILES 1024
#define MAX_FILES 256
#define MAX_FILE_NAME 256

// file operation codes
#define open_code 0xFF
#define fputc_code 0xFE
#define fgetc_code 0xFD
#define close_code 0xFC

// file modes
#define mode_read 0xFB
#define mode_write 0xFA
#define mode_rdwr 0xF9

// input states
#define get_code 0
#define get_mode 1
#define get_file_name 2
#define get_data 3
#define get_desc 4

// PDE bitovi
#define PDE64_PRESENT (1u << 0)
#define PDE64_RW (1u << 1)
#define PDE64_USER (1u << 2)
#define PDE64_PS (1u << 7)

// CR4 i CR0
#define CR0_PE (1u << 0)
#define CR0_PG (1u << 31)
#define CR4_PAE (1u << 5)

#define EFER_LME (1u << 8)
#define EFER_LMA (1u << 10)

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	size_t mem_size;
	struct kvm_run *run;
	int run_mmap_size;
};

int vm_init(struct vm *v, size_t mem_size)
{
	struct kvm_userspace_memory_region region;	

	memset(v, 0, sizeof(*v));
	v->kvm_fd = v->vm_fd = v->vcpu_fd = -1;
	v->mem = MAP_FAILED;
	v->run = MAP_FAILED;
	v->run_mmap_size = 0;
	v->mem_size = mem_size;

	v->kvm_fd = open("/dev/kvm", O_RDWR);
	if (v->kvm_fd < 0) {
		perror("open /dev/kvm");
		return -1;
	}

    int api = ioctl(v->kvm_fd, KVM_GET_API_VERSION, 0);
    if (api != KVM_API_VERSION) {
        printf("KVM API mismatch: kernel=%d headers=%d\n", api, KVM_API_VERSION);
        return -1;
    }

	v->vm_fd = ioctl(v->kvm_fd, KVM_CREATE_VM, 0);
	if (v->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		return -1;
	}

	v->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (v->mem == MAP_FAILED) {
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = v->mem_size;
	region.userspace_addr = (uintptr_t)v->mem;
    if (ioctl(v->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
	}

	v->vcpu_fd = ioctl(v->vm_fd, KVM_CREATE_VCPU, 0);
    if (v->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
        return -1;
	}

	v->run_mmap_size = ioctl(v->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (v->run_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	v->run = mmap(NULL, v->run_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, v->vcpu_fd, 0);
	if (v->run == MAP_FAILED) {
		perror("mmap kvm_run");
		return -1;
	}

	return 0;
}

void vm_destroy(struct vm *v) {
	if (v->run && v->run != MAP_FAILED) {
		munmap(v->run, (size_t)v->run_mmap_size);
		v->run = MAP_FAILED;
	}

	if(v->mem && v->mem != MAP_FAILED) {
		munmap(v->mem, v->mem_size);
		v->mem = MAP_FAILED;
	}

	if (v->vcpu_fd >= 0) {
		close(v->vcpu_fd);
		v->vcpu_fd = -1;
	}

	if (v->vm_fd >= 0) {
		close(v->vm_fd);
		v->vm_fd = -1;
	}

	if (v->kvm_fd >= 0) {
		close(v->kvm_fd);
		v->kvm_fd = -1;
	}
}

static void setup_segments_64(struct kvm_sregs *sregs)
{
	// .selector = 0x8,
	struct kvm_segment code = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1, // Prisutan ili učitan u memoriji
		.type = 11, // Code: execute, read, accessed
		.dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
		.db = 0, // Default size - ima vrednost 0 u long modu
		.s = 1, // Code/data tip segmenta
		.l = 1, // Long mode - 1
		.g = 1, // 4KB granularnost
	};
	struct kvm_segment data = code;
	data.type = 3; // Data: read, write, accessed
	data.l = 0;
	// data.selector = 0x10; // Data segment selector

	sregs->cs = code;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = data;
}

// Omogucavanje long moda.
// Vise od long modu mozete prociati o stranicenju u glavi 5:
// https://docs.amd.com/v/u/en-US/24593_3.43
// Pogledati figuru 5.1 na stranici 128.
//
static void setup_long_mode(struct vm *v, struct kvm_sregs *sregs, int page_size, int mem_size)
{
	// Postavljanje 4 niva ugnjezdavanja.
	// Svaka tabela stranica ima 512 ulaza, a svaki ulaz je veličine 8B.
    // Odatle sledi da je veličina tabela stranica 4KB. Ove tabele moraju da budu poravnate na 4KB. 
	uint64_t page = 0;
	uint64_t pmt4_addr = 0x1000; // Adrese su proizvoljne.
	uint64_t *pmt4 = (void *)(v->mem + pmt4_addr);

	uint64_t pmt3_addr = 0x2000;
	uint64_t *pmt3 = (void *)(v->mem + pmt3_addr);

	uint64_t pmt2_addr = 0x3000;
	uint64_t *pmt2 = (void *)(v->mem + pmt2_addr);

	//uint64_t pmt1_addr = 0x4000;
	//uint64_t *pmt1 = (void *)(v->mem + pmt1_addr);

	pmt4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pmt3_addr;
	pmt3[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pmt2_addr;

	int brojPD = mem_size / 2;
	uint64_t pmt1_addr;
	uint64_t *pmt1;

	for(int i = 0; i < brojPD; i++){
		if(page_size == 4){
			pmt1_addr = i * 0x1000 + 0x4000;
			pmt1 = (void *)(v->mem + pmt1_addr);
			pmt2[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pmt1_addr;
			for(int j = 0; j < 512; j++){
				pmt1[j] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
				page += 4 * 1024;
			}
		}
		else{
			pmt2[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
			page += 2 * 1024 * 1024;
		}
	}

	// 2MB page size
	// pmt2[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

	// 4KB page size
	// -----------------------------------------------------
	//pmt2[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pmt1_addr;
	// PC vrednost se mapira na ovu stranicu.
	//pmt1[0] = GUEST_START_ADDR | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	// SP vrednost se mapira na ovu stranicu. Vrednost 0x6000 je proizvoljno tu postavljena.
    //pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	
	// FOR petlja služi tome da mapiramo celu memoriju sa stranicama 4KB.
	// Zašti je uslov i < 512? Odgovor: jer je memorija veličine 2MB.
	// page = 0;
	// for(int i = 1; i < 512; i++) {
	// 	pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	// 	page += 0x1000;
	// }

	// -----------------------------------------------------

    // Registar koji ukazuje na PML4 tabelu stranica. Odavde kreće mapiranje VA u PA.
	sregs->cr3  = pmt4_addr; 
	sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
	sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging" 
	sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

	// Inicijalizacija segmenata za 64-bitni mod rada.
	setup_segments_64(sregs);
}

int load_guest_image(struct vm *v, const char *image_path, uint64_t load_addr) {
	FILE *f = fopen(image_path, "rb");
	if (!f) {
		perror("Failed to open guest image");
		return -1;
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		perror("Failed to seek to end of guest image");
		fclose(f);
		return -1;
	}

	long fsz = ftell(f);
	if (fsz < 0) {
		perror("Failed to get size of guest image");
		fclose(f);
		return -1;
	}
	rewind(f);

	if((uint64_t)fsz > v->mem_size - load_addr) {
		printf("Guest image is too large for the VM memory\n");
		fclose(f);
		return -1;
	}

	if (fread((uint8_t*)v->mem + load_addr, 1, (size_t)fsz, f) != (size_t)fsz) {
		perror("Failed to read guest image");
		fclose(f);
		return -1;
	}
	fclose(f);

	return 0;
}

struct kvm_arguments {
	char vm_name[MAX_FILE_NAME];

    int memoryMB;         
    int pageSizeMB;       
    char *guestImage;    

	char *sharedFiles[MAX_SHARED_FILES];
    int sharedCount;
};

int copy_file(const char *src_path, const char *dst_path) {
    int src_fd, dst_fd;
    ssize_t nread;
    char buffer[1000];

    src_fd = open(src_path, O_RDONLY);
    if (src_fd < 0) {
        perror("open source");
        return -1;
    }

    dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
		printf("%s\n", dst_path);
        perror("dst open destination");
        close(src_fd);
        return -1;
    }

    while ((nread = read(src_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t nwritten = write(dst_fd, buffer, nread);
        if (nwritten != nread) {
            perror("write");
            close(src_fd);
            close(dst_fd);
            return -1;
        }
    }

    if (nread < 0) {
        perror("read");
    }

    close(src_fd);
    close(dst_fd);

    return 0;
}

int sadrzi(char* fajlovi[], int fajloviCount, char* fajl){
	for(int i = 0; i < fajloviCount; i++){
		if(strcmp(fajlovi[i], fajl) == 0)return 1;
	}
	return 0;
}

void* kvm_thread(void* args){

	struct kvm_arguments *config = (struct kvm_arguments*) args;

	struct vm v;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;

	if (vm_init(&v, config->memoryMB * 1024 * 1024)) {
		printf("Failed to init the VM\n");
		return NULL;
	}

	if (ioctl(v.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		vm_destroy(&v);
		return NULL;
	}

	setup_long_mode(&v, &sregs, config->pageSizeMB, config->memoryMB);

    if (ioctl(v.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		vm_destroy(&v);
		return NULL;
	}

	if (load_guest_image(&v, config->guestImage, GUEST_START_ADDR) < 0) {
		printf("Failed to load guest image\n");
		vm_destroy(&v);
		return NULL;
	}

	memset(&regs, 0, sizeof(regs));
	regs.rflags = 0x2;
	
	// PC se preko pt[0] ulaza mapira na fizičku adresu GUEST_START_ADDR (0x8000).
	// a na GUEST_START_ADDR je učitan gost program.
	regs.rip = GUEST_START_ADDR; 
	regs.rsp = ((uint64_t)config->memoryMB) << 20; // SP raste nadole

	if (ioctl(v.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		return NULL;
	}

	uint8_t input;
	uint8_t code;
	int input_state = 0;
	uint8_t file_mode = 0;
	char file_name[MAX_FILE_NAME];
	int file_name_index = 0;
	uint8_t output = 0;
	int file_desc = 0;

	int opened_files[MAX_FILES];
	int file_index = 0;
	int flags = 0;

	while(stop == 0) {
		ret = ioctl(v.vcpu_fd, KVM_RUN, 0);
		if (ret == -1) {
			printf("KVM_RUN failed\n");
			vm_destroy(&v);
			return NULL;
		}

		switch (v.run->exit_reason) {
			case KVM_EXIT_IO:
				if (v.run->io.direction == KVM_EXIT_IO_OUT && v.run->io.port == 0xE9) {
					char *p = (char *)v.run;
					printf("%c", *(p + v.run->io.data_offset));
				}
				if (v.run->io.direction == KVM_EXIT_IO_OUT && v.run->io.port == 0x0278) {
					input = *((char*)v.run + v.run->io.data_offset);
					switch(input_state){
						case get_code:
							code = input;
							if(code == open_code) input_state = get_file_name;
							else input_state = get_desc;
							break;
						case get_mode:
							file_mode = input;

							if(file_mode == mode_read) flags = O_RDONLY;

							if(file_mode == mode_write) flags = O_WRONLY | O_CREAT;

							if(file_mode == mode_rdwr) flags = O_RDWR | O_CREAT;

							//otvori fajl i dodaj u output deskriptor
							if(sadrzi(config->sharedFiles, config->sharedCount, file_name) == 1){
								char temp[MAX_FILE_NAME];
								strcpy(temp, config->vm_name);
								strcat(temp, file_name);
								if(access(temp, F_OK) != 0){
									mkdir(config->vm_name,0755);
									copy_file(file_name, temp);
								}
								opened_files[file_index] = open(temp, flags, 0644);
							}
							else{
								opened_files[file_index] = open(file_name, flags, 0644);
							}

							if(opened_files[file_index] == -1){
								fprintf(stderr,"Opening of file %s failed\n",file_name);
							}
							output = file_index;
							file_index++;
							input_state = get_code;
							break;
						case get_file_name:
							file_name[file_name_index++] = input;
							if(input == '\0'){
								input_state = get_mode;
							}
							break;
						case get_data:
							// upisi input u fajl
							if(write(opened_files[file_desc], &input, 1) == -1){
								fprintf(stderr,"Write failed\n");
							}
							input_state = get_code;
							break;
						case get_desc:
							file_desc = input;
							switch(code){
								case fputc_code:
									input_state = get_data;
									break;
								case fgetc_code:
									//dohvati karakter iz fajla
									if(read(opened_files[file_desc], &output, 1) == -1){
										fprintf(stderr,"Read failed\n");
									}
									input_state = get_code;
									break;
								case close_code:
									//zatvori fajl
									if(close(opened_files[file_desc]) == -1){
										fprintf(stderr,"Close failed\n");
									}
									input_state = get_code;
									break;
							}
							break;
					}	
				}
				if (v.run->io.direction == KVM_EXIT_IO_IN && v.run->io.port == 0x0278) {
					*((char*)v.run + v.run->io.data_offset) = output;
				}
				break;
			case KVM_EXIT_HLT:
				printf("KVM_EXIT_HLT\n");
				stop = 1;
				break;
			case KVM_EXIT_SHUTDOWN:
				printf("Shutdown\n");
				stop = 1;
				break;
			default:
				printf("Default - exit reason: %d\n", v.run->exit_reason);
				break;
    	}
  	}

	vm_destroy(&v);
	return NULL; 
}

struct HypervisorConfig {
    int memoryMB;                     
    int pageSizeMB;                   
    char *guestImages[MAX_GUESTS];    
    int guestCount;

	char *sharedFiles[MAX_SHARED_FILES];
    int sharedCount;
};

void printUsage(const char *progName) {
    fprintf(stderr,
        "Usage: %s --memory <2|4|8> --page <2|4> --guest <guest1.img> [guest2.img ...]\n",
        progName);
}

int main(int argc, char *argv[]) {
    struct HypervisorConfig config;
    memset(&config, 0, sizeof(config));

    const char *short_opts = "m:p:g:f:";
    const struct option long_opts[] = {
        {"memory", required_argument, NULL, 'm'},
        {"page",   required_argument, NULL, 'p'},
        {"guest",  required_argument, NULL, 'g'},
		{"file",   required_argument, NULL, 'f'},
        {NULL,     0,                 NULL,  0 }
    };

    int opt, long_index = 0;

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &long_index)) != -1) {
        switch (opt) {
        case 'm':
            config.memoryMB = atoi(optarg);
            if (config.memoryMB != 2 && config.memoryMB != 4 && config.memoryMB != 8) {
                fprintf(stderr, "Error: Invalid memory size (%s MB). Use 2, 4, or 8.\n", optarg);
                return 1;
            }
            break;

        case 'p':
            config.pageSizeMB = atoi(optarg);
            if (config.pageSizeMB != 2 && config.pageSizeMB != 4) {
                fprintf(stderr, "Error: Invalid page size (%s). Use 2 or 4.\n", optarg);
                return 1;
            }
            break;

        case 'g':
            for (int i = optind - 1; i < argc && argv[i][0] != '-'; i++) {
                if (config.guestCount >= MAX_GUESTS) {
                    fprintf(stderr, "Error: Too many guest images (max %d).\n", MAX_GUESTS);
                    return 1;
                }
                config.guestImages[config.guestCount++] = argv[i];
            }
            optind += config.guestCount - 1;
            break;

		case 'f':
    		for (int i = optind - 1; i < argc && argv[i][0] != '-'; i++) {
        		if (config.sharedCount >= MAX_SHARED_FILES) {
            		fprintf(stderr, "Error: Too many shared files (max %d).\n", MAX_SHARED_FILES);
            		return 1;
        		}
        		config.sharedFiles[config.sharedCount++] = argv[i];
    		}
    		optind += config.sharedCount - 1;
    		break;

        default:
            printUsage(argv[0]);
            return 1;
        }
    }

    if (config.memoryMB == 0 || config.pageSizeMB == 0 || config.guestCount == 0) {
        fprintf(stderr, "Error: Missing required arguments.\n");
        printUsage(argv[0]);
        return 1;
    }

    printf("Hypervisor configuration:\n");
    printf("  Memory size: %d MB\n", config.memoryMB);
    printf("  Page size: %d %s\n",
           config.pageSizeMB, (config.pageSizeMB == 2 ? "MB" : "KB"));
    printf("  Guest images:\n");
    for (int i = 0; i < config.guestCount; i++) {
        printf("    - %s\n", config.guestImages[i]);
    }
	if (config.sharedCount > 0) {
    	printf("  Shared files (%d):\n", config.sharedCount);
    	for (int i = 0; i < config.sharedCount; i++) {
        	printf("    - %s\n", config.sharedFiles[i]);
    	}
	} else {
    	printf("  Shared files: none\n");
	}

	pthread_t guests[MAX_GUESTS];
	struct kvm_arguments* args[MAX_GUESTS];

    for (int i = 0; i < config.guestCount; i++) {

		args[i] = malloc(sizeof(struct kvm_arguments));
		
		char broj[50];
		snprintf(broj, 50, "%d", i);
		strcpy(args[i]->vm_name, "vm_dir_");
		strcat(args[i]->vm_name, broj);
		strcat(args[i]->vm_name, "/");
		args[i]->memoryMB = config.memoryMB;
		args[i]->pageSizeMB = config.pageSizeMB;
		args[i]->guestImage = config.guestImages[i];
		for(int j = 0; j < config.sharedCount; j++){
			args[i]->sharedFiles[j] = malloc(MAX_FILE_NAME * sizeof(char));
			strcpy(args[i]->sharedFiles[j], config.sharedFiles[j]);
		}
		args[i]->sharedCount = config.sharedCount;

		pthread_create(&guests[i], NULL, kvm_thread, args[i]);	

	}

    for (int i = 0; i < config.guestCount; i++){
		pthread_join(guests[i], NULL);
		free(args[i]);
	}

    return 0;
}
