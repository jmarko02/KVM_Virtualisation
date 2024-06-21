
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



#include <string>
#include <vector>
#include <pthread.h>
#include <unordered_map>
#include <iostream>
#include <cstdint>
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
static int ID = 0;
struct vm
{
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	struct kvm_run *kvm_run;
	const char *guest_image;
	size_t mem_size;
	size_t page_size;
	// char **allowed_files;
	std::vector<std::string> allowed_files;
	int id;
};

int init_vm(struct vm *vm, size_t mem_size)
{
	struct kvm_userspace_memory_region region;
	int kvm_run_mmap_size;

	vm->kvm_fd = open("/dev/kvm", O_RDWR);
	if (vm->kvm_fd < 0)
	{
		perror("open /dev/kvm");
		return -1;
	}

	vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
	if (vm->vm_fd < 0)
	{
		perror("KVM_CREATE_VM");
		return -1;
	}

	vm->mem = (char *)mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
						   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (vm->mem == MAP_FAILED)
	{
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = mem_size;
	region.userspace_addr = (unsigned long)vm->mem;
	if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
	{
		perror("KVM_SET_USER_MEMORY_REGION");
		return -1;
	}

	vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
	if (vm->vcpu_fd < 0)
	{
		perror("KVM_CREATE_VCPU");
		return -1;
	}

	kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (kvm_run_mmap_size <= 0)
	{
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	vm->kvm_run = (kvm_run *)mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
								  MAP_SHARED, vm->vcpu_fd, 0);
	if (vm->kvm_run == MAP_FAILED)
	{
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
		.type = 11,	  // Code: execute, read, accessed
		.present = 1, // Prisutan ili učitan u memoriji
		.dpl = 0,	  // Descriptor Privilage Level: 0 (0, 1, 2, 3)
		.db = 0,	  // Default size - ima vrednost 0 u long modu
		.s = 1,		  // Code/data tip segmenta
		.l = 1,		  // Long mode - 1
		.g = 1,		  // 4KB granularnost
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
	uint64_t *pml4 = (uint64_t *)(vm->mem + pml4_addr);

	uint64_t pdpt_addr = 0x2000;
	uint64_t *pdpt = (uint64_t *)(vm->mem + pdpt_addr);

	uint64_t pd_addr = 0x3000;
	uint64_t *pd = (uint64_t *)(vm->mem + pd_addr);

	uint64_t pt_addr = 0x4000;
	uint64_t *pt = (uint64_t *)(vm->mem + pt_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

	if (page_size == 2 * 1024 * 1024)
	{
		// 2MB page size
		pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
		page += 2 << 20;
		if (mem_size >= 4 * 1024 * 1024)
		{
			pd[1] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
			page += 2 << 20;
			if (mem_size >= 8 * 1024 * 1024)
			{
				pd[2] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
				page += 2 << 20;
				pd[3] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page;
			}
		}
	}
	else if (page_size == 4 * 1024)
	{
		// 4KB page size
		// -----------------------------------------------------
		pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
		// PC vrednost se mapira na ovu stranicu.
		for (int i = 0; i < 512; i++)
		{
			pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
			page += 0x1000;
		}

		if (mem_size >= 4 * 1024 * 1024)
		{
			pt_addr += 0x1000;
			pt = (uint64_t *)(vm->mem + pt_addr);
			pd[1] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;

			for (int i = 0; i < 512; i++)
			{
				pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
				page += 0x1000;
			}

			if (mem_size >= 8 * 1024 * 1024)
			{
				pt_addr += 0x1000;
				pt = (uint64_t *)(vm->mem + pt_addr);
				pd[2] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;

				for (int i = 0; i < 512; i++)
				{
					pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
					page += 0x1000;
				}

				pt_addr += 0x1000;
				pt = (uint64_t *)(vm->mem + pt_addr);
				pd[3] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;

				for (int i = 0; i < 512; i++)
				{
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
	sregs->cr3 = pml4_addr;
	sregs->cr4 = CR4_PAE;			   // "Physical Address Extension" mora biti 1 za long mode.
	sregs->cr0 = CR0_PE | CR0_PG;	   // Postavljanje "Protected Mode" i "Paging"
	sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

	// Inicijalizacija segmenata procesora.
	setup_64bit_code_segment(sregs);
}


std::vector<int> file_fds;
std::vector<std::string> shared_files_arr;
std::unordered_map<int, std::unordered_map<std::string,size_t>> cursors_map;


std::unordered_map<std::string, int> global_shared_files;
std::unordered_map<uint64_t, std::string> global_shared_files_fds;
int next_fd = 3;  // Početni fajl deskriptor, s obzirom da su 0, 1 i 2 rezervisani za stdin, stdout, stderr


bool check_if_shared(const std::string& file_name, std::unordered_map<uint64_t, std::string>& shared_files_fds) {
    for (const auto& e : shared_files_fds) {
        if (e.second == file_name) {
            return true;
        }
    }
    return false;
}


int handle_open(std::string file_name, int mode, int vm_id,std::unordered_map<std::string,
	int>& local_files, std::unordered_map<uint64_t, std::string>& local_files_fds,std::unordered_map<std::string,
	int>& shared_files , std::unordered_map<uint64_t, std::string>& shared_files_fds){


	// printf("\nFILE NAME JE : %s\n", file_name.c_str());
	if (local_files.find(std::to_string(vm_id)+ file_name) != local_files.end()) {
        std::string file_name =  std::to_string(vm_id) + file_name ;

		uint64_t fd = 0;
        for (const auto& p : local_files_fds) {
            if (file_name == p.second) {
                fd = p.first;
                break;
            }
        }
		// printf("%ld\n", fd);
        return fd;
	}

	if (check_if_shared(file_name, shared_files_fds)) {
        uint64_t fd = 0;
        for (const auto& p : shared_files_fds) {
            if (file_name == p.second) {
                fd = p.first;
                break;
            }
        }
		
        return fd;
    }
	// printf("FILE NAME JE : %s\n", file_name.c_str());
	 file_name = std::to_string(vm_id) + file_name;
	 
	// printf("FILE NAME JE : %s\n", file_name.c_str());

    // Definišite prava pristupa i način otvaranja
    int flags = 0;
    if (mode == 1) { // Čitanje
        flags = O_RDONLY;
    } else if (mode == 0) { // Pisanje ili Čitanje i Pisanje
        flags = O_RDWR| O_CREAT;
    } else {
        std::cerr << "Invalid mode" << std::endl;
        return 0; // ili neki drugi kod greške
    }

    // Otvorite fajl sa definisanim pravima i načinom
    int fd = open(file_name.c_str(), flags, 0644);
	// printf("%d\n", fd);
    if (fd == -1) {
        perror("Failed to open or create file");
        return 0; // ili neki drugi kod greške
    }

    // Čuvanje informacija o lokalnom fajlu
    local_files[file_name] = fd;
    local_files_fds[next_fd] = file_name;

	// cursors_map[vm_id][file_name] = 0;

	// printf("DODAT JE KAO LOKALNI : %s za fd=%d i za next_fd=%d \n", file_name.c_str(),fd,next_fd);
	
	

    return next_fd++;

	
	
}

std::string handle_read(int guest_fd, int size, int vm_id,
	std::unordered_map<std::string, int>& local_files, std::unordered_map<uint64_t,
	std::string>& local_files_fds,std::unordered_map<std::string, int>& shared_files ,
	std::unordered_map<uint64_t, std::string>& shared_files_fds){

	

	std::string file_name;
	if(local_files_fds.find(guest_fd) != local_files_fds.end()){
		file_name = local_files_fds[guest_fd];
		// printf("actual filename %s\n", file_name.c_str() );

	} else if (shared_files_fds.find(guest_fd) !=  shared_files_fds.end()){
		file_name = shared_files_fds[guest_fd];
		// printf("actual filename %s\n", file_name.c_str() );

	}

	// printf("filename: %s\n", file_name.c_str());
	char buffer[size];

	if (local_files.find(file_name) != local_files.end()) 
	{
		
		// printf("LOCAL JEEE\n");
        // std::string file_name =  std::to_string(vm_id) + file_name ;
		int fd = local_files[file_name];
		
		int read_size = read(fd,buffer,size);

		std::string data;
		for(int i = 0; i < read_size; i++){
			data += buffer[i];
		}

        return data;

	}else if (check_if_shared(file_name,shared_files_fds)) 
	{
		
		// printf("SHARED JEEE\n");
		// printf("AAA: %s", file_name.c_str());
        int fd = shared_files[file_name];
		// printf("%d\n", fd);

		auto& vm_cursor_map = cursors_map[vm_id];
		size_t cursor = vm_cursor_map[file_name];

		if (lseek(fd, cursor, SEEK_SET) == -1) {

        	perror("GRESKA PRI SEEK");
    	}

		int read_size = read(fd,buffer,size);
		
		cursors_map[vm_id][file_name] += read_size;

		std::string data;
		for(int i = 0; i < read_size; i++){
			data += buffer[i];
		}
        return data;
    }

	printf("Greska pri handle_read - fajl nije ni local ni shared \n");
	return "greska";

}

void handle_write(int guest_fd, std::string data_to_write,int vm_id
		,std::unordered_map<std::string, int>& local_files, std::unordered_map<uint64_t,
		 std::string>& local_files_fds,std::unordered_map<std::string, int>& shared_files
  		,std::unordered_map<uint64_t, std::string>& shared_files_fds){

	std::string file_name;
	if(local_files_fds.find(guest_fd) != local_files_fds.end()){
		file_name = local_files_fds[guest_fd];
		// printf("actual filename %s\n", file_name.c_str() );

	} else if (shared_files_fds.find(guest_fd) !=  shared_files_fds.end()){
		file_name = shared_files_fds[guest_fd];
		// printf("actual filename %s\n", file_name.c_str() );

	}

	if (local_files.find(file_name) != local_files.end()) 
	{
		// printf("\n\nFAJL ZA PISANJE JE LOCAL: %s\n\n", file_name.c_str());
		int fd = local_files[file_name];
		int ret = write(fd, data_to_write.c_str(), data_to_write.size());
		// printf("\nBROJ UPISANIH BAJTOVA JE: %d\n", ret);
		return;

	}else if (check_if_shared(file_name,shared_files_fds)) 
	{
		// printf("\n\nFAJL ZA PISANJE JE SHARED %s\n\n", file_name.c_str());

		int old_fd = shared_files[file_name];
		file_name = std::to_string(vm_id) + file_name;
		// printf("\n\nPRAVIMO LOKALNU KOPIJU SA IMENOM : %s\n\n",file_name.c_str());

		int new_fd = open(file_name.c_str(),O_RDWR| O_CREAT , 0644);

		auto& vm_cursor_map = cursors_map[vm_id];
        size_t cursor = vm_cursor_map[file_name];

		//kopiramo sadrzaj fajla: OVDE TREBA VODITI RACUNA O KURSORIMA!
		char buffer[data_to_write.size()];
		ssize_t bytes_read;

		lseek(old_fd,0,SEEK_SET);
		while ((bytes_read = read(old_fd, buffer, data_to_write.size())) > 0) {
			if (write(new_fd, buffer, bytes_read) != bytes_read) {
				perror("\nNIJE LEPO KOPIRAN FAJL\n");
			}
		}
		lseek(old_fd,cursor,SEEK_SET);
		if (bytes_read == -1) {
			perror("\n Nije lepo kopiran fajl tj procitan \n");
		}

		local_files[file_name] = new_fd;
   	 	local_files_fds[guest_fd] = file_name;

		// printf("\n\nCURSOR FOR vm_id: %d IS %ld for file_name: %s  \n\n", vm_id, lseek(new_fd,cursor+bytes_read,SEEK_SET), file_name.c_str());
		// lseek(new_fd,cursor,SEEK_SET);

		// printf("DODAT JE KAO LOKALNI : %s za fd=%d za guest_fd=%d \n", file_name.c_str(),new_fd,guest_fd);

		int ret = write(new_fd, data_to_write.c_str(), data_to_write.size());
		// printf("\nBROJ UPISANIH BAJTOVA JE: %d\n", ret);

		//printamo mape:
		// std::cout << "Local Files:" << std::endl;
		// for (const auto& pair : local_files) {
        // 	std::cout << "Filename: " << pair.first << ", FD: " << pair.second << std::endl;
    	// }
		// // Ispis za local_files_fds
		// std::cout << "Local Files FDs:" << std::endl;
		// for (const auto& pair : local_files_fds) {
		// 	std::cout << "FD: " << pair.first << ", Filename: " << pair.second << std::endl;
		// }

		// // Ispis za shared_files
		// std::cout << "Shared Files:" << std::endl;
		// for (const auto& pair : shared_files) {
		// 	std::cout << "Filename: " << pair.first << ", FD: " << pair.second << std::endl;
		// }

		// // Ispis za shared_files_fds
		// std::cout << "Shared Files FDs:" << std::endl;
		// for (const auto& pair : shared_files_fds) {
		// 	std::cout << "FD: " << pair.first << ", Filename: " << pair.second << std::endl;
		// }


		return;
    }

	printf("Greska pri handle_WRITE - fajl nije ni local ni shared \n");
	
} 

	
	std::unordered_map<std::string, int> local_files;
	std::unordered_map<uint64_t, std::string> local_files_fds;

	std::unordered_map<std::string, int> shared_files = global_shared_files;
	std::unordered_map<uint64_t, std::string> shared_files_fds = global_shared_files_fds;

void handle_close(int guest_fd,int vm_id,std::unordered_map<std::string, int>& local_files,
	std::unordered_map<uint64_t, std::string>& local_files_fds,std::unordered_map<std::string, int>& shared_files ,
	std::unordered_map<uint64_t, std::string>& shared_files_fds){
	// printf("guest_fd to be closed: %d\n", guest_fd);

	
	std::string file_name;
	if(local_files_fds.find(guest_fd) != local_files_fds.end()){
		file_name = local_files_fds[guest_fd];
		// printf("actual filename %s\n", file_name.c_str() );

	} else if (shared_files_fds.find(guest_fd) !=  shared_files_fds.end() ){
		file_name = shared_files_fds[guest_fd];
		// printf("AAAactual filename %s\n", file_name.c_str() );

	} 

	if (local_files.find( file_name) != local_files.end()) 
	{
		
		int fd = local_files[file_name];
		// printf(" local file %s to be closed: %d from vm_id: %d\n", file_name.c_str(),fd,vm_id);
		int ret = close(fd);
		// if(ret == -1) printf("\n\nFajl %s fd: %d je vec zatvoren\n\n", file_name.c_str(),fd);
		// else printf(" local file successfuly closed because ret is : %d\n", ret);
		return;
		

	} else if (check_if_shared(file_name,shared_files_fds)){
		// printf("\n\n\n POSTO JE FILE SHARED OVDE GA NE ZATVARAMOOOO\n\n\n");
		return;
	}
	printf("GRESKA PRI HANDLE_CLOSE : fajl nije ni lokalan ni shared");
	return;
}

void *vm_body(void *arg)
{
	struct vm *vm = (struct vm *)arg;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;
	FILE *img;


	if (init_vm(vm, vm->mem_size))
	{
		printf("Failed to init the VM\n");
		pthread_exit(NULL);
	}

	if (ioctl(vm->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		pthread_exit(NULL);
	}

	setup_long_mode(vm, &sregs, vm->page_size, vm->mem_size);
	// DA LI OVDE TREBA &VM ILI SAMO VM???

	if (ioctl(vm->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
	{
		perror("KVM_SET_SREGS");
		pthread_exit(NULL);
	}

	memset(&regs, 0, sizeof(regs));
	regs.rflags = 2;
	regs.rip = 0;
	// SP raste nadole
	regs.rsp = vm->mem_size;

	if (ioctl(vm->vcpu_fd, KVM_SET_REGS, &regs) < 0)
	{
		perror("KVM_SET_REGS");
		pthread_exit(NULL);
	}


	img = fopen(vm->guest_image, "rb");
	if (img == NULL)
	{
		printf("Cannot open guest binary file\n");
		pthread_exit(NULL);
	}

	char *p = vm->mem;
	while (feof(img) == 0)
	{
		int r = fread(p, 1, 1024, img);
		p += r;
	}
	fclose(img);



	std::string file_name ;
	int mode = 1; //default is r
	int fun = 0; //default is open
	int num_of_percents = 0;
	int guest_fd = -1;
	std::string fd_str;

	int fd_position = 0;
	int rd_position = 0;

	std::string read_data_str;

	std::string read_size ;
	std::string data_to_write;

		
	std::unordered_map<std::string, int> local_files;
	std::unordered_map<uint64_t, std::string> local_files_fds;

	std::unordered_map<std::string, int> shared_files = global_shared_files;
	std::unordered_map<uint64_t, std::string> shared_files_fds = global_shared_files_fds;

	


	bool open_boolean = false;
	bool read_boolean = false;
	bool write_boolean = false;
	bool close_boolean = false;
	
	
	while (stop == 0)
	{
		ret = ioctl(vm->vcpu_fd, KVM_RUN, 0);
		if (ret == -1)
		{
			printf("KVM_RUN failed\n");
			// break;
		}

		switch (vm->kvm_run->exit_reason)
		{
		case KVM_EXIT_IO:
			if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT)
			{
				if (vm->kvm_run->io.port == 0xE9)
				{
					char *p = (char *)vm->kvm_run;
					printf("%c", *(p + vm->kvm_run->io.data_offset));
				}
				else if (vm->kvm_run->io.port == 0x0278)
				{
					///...
					// printf("AAAA");
					
					char *p = (char *)vm->kvm_run+ vm->kvm_run->io.data_offset;
					if(*p != '\0')
					{
						if(num_of_percents==0 && *p != '%')
						{
							// printf("%c", *p);
							fun = (int)*p-'0';
						}else if(num_of_percents==1 && *p != '%')
						{	
							// printf("%c", *p);
							switch(fun){
							case 0:
								mode = (int)*p-'0';
								break;
							case 1:
							case 2:
							case 3:
								guest_fd = (int)*p-'0';
								// printf("\nguest_fd aaaa : %d\n", guest_fd);
								break;
							}
							
						}

						if(*p == '%')
						{
							num_of_percents++;
						}
						if(num_of_percents==2  && *p != '%'){
							switch(fun){
							case 0:
								file_name += *p;
								break;
							case 1:
								 read_size += *p;
								//  printf("%s", read_size.c_str());
								break;
							case 2:
								data_to_write += *p;
								break;
							case 3: //FOR CLOSE WE DONT ENTER THIS IF
								break;
							}
							
						}
						// if(num_of_percents==1){	}

					} else {
						if (num_of_percents !=2) printf("greska pri prenosu");
						num_of_percents = 0;

						//if fun == OPEN:
						bool exists = false;
						for(int i = 0; i<vm->allowed_files.size();i++){
							if(file_name == vm->allowed_files[i]){
								exists = true;
							}
						}
						

							
						switch(fun){
						case 0: //OPEN
							// printf("FILENAME PRE HANDLE_OPEN JE: %s\n\n", file_name.c_str());
							guest_fd = handle_open(file_name,mode,vm->id,local_files, local_files_fds, shared_files, shared_files_fds);
							fd_str = std::to_string(guest_fd);
							fd_position = 0;
							open_boolean = true;
							file_name.clear();
							// printf("\n%d\n",guest_fd);
							
							// printf("A\n");
							
							break;
						case 1: //READ
							// printf("OVO JE FD: %d", guest_fd);
							read_data_str = handle_read(guest_fd, std::stoi(read_size),vm->id,local_files, local_files_fds, shared_files, shared_files_fds);
							// printf("AAAAA\n");
							
							
							rd_position = 0;
							read_boolean = true;
							read_size.clear();
							break;
						case 2: //WRITE
							
							handle_write(guest_fd,data_to_write,vm->id,local_files, local_files_fds, shared_files, shared_files_fds);
							write_boolean = true;
							data_to_write.clear();
							break;
						case 3: //CLOSE
							handle_close(guest_fd, vm->id, local_files, local_files_fds, shared_files, shared_files_fds);
							close_boolean = true;
							break;
						default:
							printf("Exit reason: %d\n",fun);
							break;
						}
						
					}
					
				}
			}
			else if (vm->kvm_run->io.direction == KVM_EXIT_IO_IN)
			{

				if (vm->kvm_run->io.port == 0xE9)
				{
					char *p = (char *)vm->kvm_run;
					// *(p + vm.kvm_run->io.data_offset) = input_buffer[--buffer_index];
					*(p + vm->kvm_run->io.data_offset) = getchar();
				}
				else if (vm->kvm_run->io.port == 0x0278)
				{

					char *p = (char *)vm->kvm_run ;

					if(open_boolean)
					{
						if(fd_position < fd_str.size()){
							// printf("\n%c\n",fd_str[fd_position]);
							// printf("\n\n\n%c\n\n\n",fd_str[fd_position++] );
							*(p+ vm->kvm_run->io.data_offset) = fd_str[fd_position++];
						} else {
							*(p+ vm->kvm_run->io.data_offset) = '\0';
							open_boolean = false;
							// fd_position =0; ???
							// printf("SALJEM NULL\n");
						}
						

					} else if(read_boolean)
					{

						// printf("%s\n", read_data_str.c_str());
						if(rd_position < read_data_str.size()){
							*(p+ vm->kvm_run->io.data_offset) = read_data_str[rd_position++];
						} else {
							*(p+ vm->kvm_run->io.data_offset) = '\0';
							read_boolean = false; //ovde ili ispod else ???
						}
						
					} 
						


                	break;

					
				}
			}
			continue;
		case KVM_EXIT_HLT:
			// printf("KVM_EXIT_HLT\n");
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
	int number_of_files = 0;
	int files_position;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--memory") == 0)
		{
			if (i + 1 < argc)
			{
				mem_size = strtoul(argv[++i], NULL, 10);
				if (mem_size == 4 || mem_size == 2 || mem_size == 8)
				{
					mem_size = mem_size * 1024 * 1024;
				}
				else
				{
					printf("Argument for -m/--memory must be 2 or 4 or 8\n");
					return EXIT_FAILURE;
				}
			}
			else
			{
				printf("Option -m/--memory requires an argument \n");
				return EXIT_FAILURE;
			}
		}
		else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--page") == 0)
		{
			if (i + 1 < argc)
			{
				page_size = strtoul(argv[++i], NULL, 10);
				if (page_size == 2)
				{
					page_size = page_size * 1024 * 1024;
				}
				else if (page_size == 4)
				{
					page_size = page_size * 1024;
				}
				else
				{
					printf("Argument for -p/--page must be 2 or 4\n");
					return EXIT_FAILURE;
				}
			}
			else
			{
				printf("Option -p/--page requires an argument\n");
				return EXIT_FAILURE;
			}
		}
		else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--guest") == 0)
		{
			if (i + 1 < argc)
			{
				position = i + 1;
				while (++i < argc && argv[i][0] != '-')
				{
					number_of_guests++;
				}
				i--;
			}
			else
			{
				fprintf(stderr, "Option -g/--guest requires an argument\n");
				return EXIT_FAILURE;
			}
		}
		else if(strcmp(argv[i], "-f")==0 || strcmp(argv[i], "--file")==0)
		{
			if(i+1 < argc)
			{
				files_position = i + 1;
				while (++i < argc && argv[i][0] != '-')
				{
					number_of_files++;
				}
				i--;
			}
			else
			{
				fprintf(stderr, "Option -f/--file requires an argument\n");
				return EXIT_FAILURE;
			}
		}
		else {
			fprintf(stderr, "unknown arg: %s\n", argv[i]);
		}
	}


	// set default values for page_size and mem_size
	if (page_size == 0)
	{
		page_size = 4 * 1024;
	}
	if (mem_size == 0)
	{
		mem_size = 2 * 1024 * 1024;
	}
	// printf("Memory size: %zu MB\n", mem_size / (1024 * 1024));
	// printf("Page size: %zu KB\n", page_size / 1024);

	char *guest_images[number_of_guests];
	for (int i = 0; i < number_of_guests; i++)
	{
		guest_images[i] = argv[position++];
	}

	for (int i = 0; i < number_of_guests; i++)
	{
		// printf("%s\n", guest_images[i]);
	}

	struct vm vms[number_of_guests];
	pthread_t threads[number_of_guests];

	size_t k = files_position;
	for(int j = 0; j < number_of_files; j++){
		std::string s = argv[k++];
		shared_files_arr.push_back(s);
	}
	for (auto& f : shared_files_arr){
			// printf("FAJL JE: %s\n", f.c_str());
			//opening shared files:
			int fd = open(f.c_str(), O_RDONLY);
			
			file_fds.push_back(fd);
			// printf("\nOTVOREN SHARED FAJL %s : FD JE : %d\n",f.c_str(), fd);
			global_shared_files[f] = fd;	
			global_shared_files_fds[next_fd++] = f;
		}

	for (int i = 0; i < number_of_guests; i++)
	{
		vms[i].mem_size = mem_size;
		vms[i].page_size = page_size;
		vms[i].mem = NULL;
		vms[i].guest_image = guest_images[i];
		vms[i].id = ID++;

		size_t iter = files_position;
		for(int j = 0; j < number_of_files; j++){
			std::string s = argv[iter++];
			vms[i].allowed_files.push_back(s);
		}

		std::unordered_map<std::string , size_t> local_map;
		for(int j = 0;  j < number_of_files; j++){
			local_map[shared_files_arr[j]] = lseek(file_fds[j], 0, SEEK_CUR);
		}
		cursors_map[vms[i].id] = local_map;
		

		if (pthread_create(&threads[i], NULL, vm_body, &vms[i]))
		{
			perror("pthread_create");
			return EXIT_FAILURE;
		}
	}

	for (int i = 0; i < number_of_guests; i++)
	{
		pthread_join(threads[i], NULL);
	}

	for (int fd: file_fds){
			// printf("\n\nZATVOREN SHARED FAJL : %d\n", fd);
			int ret = close(fd);
			if (ret == -1) printf("\n\nFAJL: %d VEC ZATVOREN\n\n", fd);
			// printf("%d\n", ret);
			
		}

	return EXIT_SUCCESS;
}
