
#define _GNU_SOURCE
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

#include <pthread.h>


#define BUFFER_SIZE 256
// #define MEM_SIZE 0x200000 // Veličina memorije će biti 2MB	
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

// CR4
#define CR4_PAE (1U << 5)

// CR0
#define CR0_PE 1u
#define CR0_PG (1U << 31)

#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	struct kvm_run *kvm_run;
    const char *guest_image;
    size_t mem_size;
    size_t page_size;
};

int init_vm(struct vm *vm, size_t mem_size)
{
	struct kvm_userspace_memory_region region;
	int kvm_run_mmap_size;

	vm->kvm_fd = open("/dev/kvm", O_RDWR);
	if (vm->kvm_fd < 0) {
		perror("open /dev/kvm");
		return -1;
	}

	vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
	if (vm->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		return -1;
	}

	vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (vm->mem == MAP_FAILED) {
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = mem_size;
	region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
	}

	vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
        return -1;
	}

	kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	vm->kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vm->vcpu_fd, 0);
	if (vm->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		return -1;
	}

	return 0;
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
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

	sregs->cs = seg;

	seg.type = 3; // Data: read, write, accessed
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

// Omogucavanje long moda.
// Vise od long modu mozete prociati o stranicenju u glavi 5:
// https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf
// Pogledati figuru 5.1 na stranici 128.
static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs, size_t page_size, size_t mem_size)
{
	// Postavljanje 4 niva ugnjezdavanja.
	// Svaka tabela stranica ima 512 ulaza, a svaki ulaz je veličine 8B.
    // Odatle sledi da je veličina tabela stranica 4KB. Ove tabele moraju da budu poravnate na 4KB. 
	uint64_t page = 0;
	uint64_t pml4_addr = 0x1000; // Adrese su proizvoljne.
	uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

	uint64_t pdpt_addr = 0x2000;
	uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

	uint64_t pd_addr = 0x3000;
	uint64_t *pd = (void *)(vm->mem + pd_addr);

	uint64_t pt_addr = 0x4000;
	uint64_t *pt = (void *)(vm->mem + pt_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	
    if(page_size == 2 * 1024 * 1024){
		// 2MB page size
        pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
		page += 2 << 20;
		if (mem_size >= 4 * 1024 * 1024) {
			pd[1] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
			page += 2 << 20;
			if (mem_size >= 8 * 1024 * 1024) {
				pd[2] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
				page += 2 << 20;
				pd[3] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
			}
		}
    } else if(page_size == 4 * 1024){
        // 4KB page size
        // -----------------------------------------------------
        pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
        // PC vrednost se mapira na ovu stranicu.
        for(int i = 0; i < 512; i++) {
			pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
			page += 0x1000;
		}

		if (mem_size >= 4 * 1024 * 1024) 
		{
			pt_addr += 0x1000;	
			pt = (void *)(vm->mem + pt_addr);
        	pd[1] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
			
			for(int i = 0; i < 512; i++) {
				pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
				page += 0x1000;
			}

			if (mem_size >= 8 * 1024 * 1024) {
				pt_addr += 0x1000;	
				pt = (void *)(vm->mem + pt_addr);
				pd[2] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
				
				for(int i = 0; i < 512; i++) {
					pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
					page += 0x1000;
				}
				
				pt_addr += 0x1000;	
				pt = (void *)(vm->mem + pt_addr);
				pd[3] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
				
				for(int i = 0; i < 512; i++) {
					pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
					page += 0x1000;
				}

			}
		}
    }
	
	

	// FOR petlja služi tome da mapiramo celu memoriju sa stranicama 4KB.
	// Zašti je uslov i < 512? Odgovor: jer je memorija veličine 2MB.
	// for(int i = 0; i < 512; i++) {
	// 	pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
	// 	page += 0x1000;
	// }
	// -----------------------------------------------------

    // Registar koji ukazuje na PML4 tabelu stranica. Odavde kreće mapiranje VA u PA.
	sregs->cr3  = pml4_addr; 
	sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
	sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging" 
	sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

	// Inicijalizacija segmenata procesora.
	setup_64bit_code_segment(sregs);
}

void *vm_body(void * arg){
    struct vm* vm = (struct vm*)arg;
    struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;
	FILE* img;

    if (init_vm(vm, vm->mem_size)) {
        printf("Failed to init the VM\n");
        pthread_exit(NULL);
    }
    
	if (ioctl(vm->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		pthread_exit(NULL);
	}

	setup_long_mode(vm, &sregs, vm->page_size, vm->mem_size);
    //DA LI OVDE TREBA &VM ILI SAMO VM???   

    if (ioctl(vm->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		pthread_exit(NULL);
	}

	memset(&regs, 0, sizeof(regs));
	regs.rflags = 2;
	regs.rip = 0;
	// SP raste nadole
	regs.rsp = vm->mem_size;

	if (ioctl(vm->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		pthread_exit(NULL);
	}

    // for(int i=0; i<number_of_guests ;i++)
    //     img = fopen(guest_images[i], "r");
    //     if (img == NULL) {
    //         printf("Can not open binary file\n");
    //         return -1;
    //     }
    img = fopen(vm->guest_image, "rb");
    if(img == NULL){
        printf("Cannot open guest binary file\n");
        pthread_exit(NULL);
    }

	char *p = vm->mem;
  	while(feof(img) == 0) {
    	int r = fread(p, 1, 1024, img);
    	p += r;
  	}
  	fclose(img);

	// char input_buffer[BUFFER_SIZE];
	// int buffer_index = 0;

	while(stop == 0) {
		ret = ioctl(vm->vcpu_fd, KVM_RUN, 0);
		if (ret == -1) {
		    printf("KVM_RUN failed\n");
            // break;
		}

		switch (vm->kvm_run->exit_reason) {
			case KVM_EXIT_IO:
				if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0xE9) {
					char *p = (char *)vm->kvm_run;
					printf("%c", *(p + vm->kvm_run->io.data_offset));
				    // continue;   
					// printf("A");
				}else if(vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.port == 0xE9){
                   
                    char *p = (char *)vm->kvm_run;
                       
					*(p+vm->kvm_run->io.data_offset) = getchar();
                    
                } else if(vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0x0278){

				    // continue;
                } else if(vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.port == 0x0278){

				    // continue;
                }
				continue;
			case KVM_EXIT_HLT:
				printf("KVM_EXIT_HLT\n");
				stop = 1;
				break;
			case KVM_EXIT_INTERNAL_ERROR:
				printf("Internal error: suberror = 0x%x\n", vm->kvm_run->internal.suberror);
				stop = 1;
				break;
			case KVM_EXIT_SHUTDOWN:
				printf("Shutdown\n");
				stop = 1;
				break;
			default:	
				printf("Exit reason: %d\n", vm->kvm_run->exit_reason);
				break;
    	}
  	}
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	

    size_t mem_size;
    size_t page_size;
    // char *guest_image[2];
    int number_of_guests = 0;
    int position;

    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-m") == 0  || strcmp(argv[i], "--memory")==0){
            if(i+1 < argc ){
                mem_size = strtoul(argv[++i], NULL,10) ;
                if(mem_size == 4 || mem_size == 2 || mem_size == 8){
                    mem_size = mem_size * 1024 * 1024;
                } else {
                    printf("Argument for -m/--memory must be 2 or 4 or 8\n");
                    return EXIT_FAILURE;
                }
            } else {
                printf("Option -m/--memory requires an argument \n");
                return EXIT_FAILURE;
            }
        } else if(strcmp(argv[i], "-p")==0 || strcmp(argv[i],"--page")==0 ){
            if(i+1 < argc){
                page_size = strtoul(argv[++i], NULL, 10) ;
                if(page_size == 2) {
                    page_size = page_size * 1024 * 1024;
                } else if (page_size ==4 ) {
                    page_size = page_size * 1024;
                } else {
                    printf("Argument for -p/--page must be 2 or 4\n");
                    return EXIT_FAILURE;
                }
            } else {
                printf("Option -p/--page requires an argument\n");
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--guest") == 0) {
            if (i+1 < argc) {
                position = i + 1;
                while( i+1 < argc && argv[++i][0]!= '-'){
                    // guest_image[number_of_guests] = argv[i];
                    number_of_guests++;
                }
            } else {
                fprintf(stderr, "Option -g/--guest requires an argument\n");
                return EXIT_FAILURE;
            }
        } 
    }
    
    //set default values for page_size and mem_size
    if(page_size == 0) {
        page_size = 4 * 1024;
    }
    if(mem_size == 0){
        mem_size = 2 * 1024 * 1024;
    }
    printf("Memory size: %zu MB\n", mem_size / (1024 * 1024));
    printf("Page size: %zu KB\n", page_size / 1024);
 
    char* guest_images[number_of_guests];
    for(int i = 0 ; position < argc; i++){
        guest_images[i] = argv[position++];
    }
      
   for(int i = 0; i < number_of_guests; i++){
        printf("%s\n", guest_images[i]);
    }

    
    struct vm vms[number_of_guests];
    pthread_t threads[number_of_guests];
    for(int i =0 ; i < number_of_guests; i++){
        vms[i].mem_size = mem_size;
        vms[i].page_size = page_size;
        vms[i].mem=NULL;
        vms[i].guest_image = guest_images[i];
        if(pthread_create(&threads[i],NULL,vm_body,&vms[i])){
            perror("pthread_create");
            return EXIT_FAILURE;
        }
    }

    for(int i = 0; i < number_of_guests; i++){
        pthread_join(threads[i],NULL);
    }

    return EXIT_SUCCESS;
    
}
