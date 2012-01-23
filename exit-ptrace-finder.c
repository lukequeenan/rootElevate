/* NOTE: this code does not yet work */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <link.h>
#include <elf.h>

// Much from http://www.phrack.org/issues.html?issue=59&id=8#article

#if defined(__i386__)
#define Elf_Dyn Elf32_Dyn
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Word Elf32_Word
#define Elf_Start 0x08048000
#elif defined(__x86_64__)
#define Elf_Dyn Elf64_Dyn
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Word Elf64_Word
#define Elf_Start 0x00400000
#else
#error "What elf arch?"
#endif


/* 
 * search locations of DT_SYMTAB and DT_STRTAB and save them into global
 * variables, also save the nchains from hash table.
 */

unsigned long symtab;
unsigned long strtab;
int nchains;

/* attach to pid */
void ptrace_attach(int pid)
{
	if ((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0) {
		perror("[-] ptrace_attach");
		exit(-1);
	}
	waitpid(pid, NULL, WUNTRACED);
}

/* detach process */
void ptrace_detach(int pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		perror("[-] ptrace_detach");
		exit(-1);
	}
}

/* read data from location addr */
void read_data(int pid, unsigned long addr, void *vptr, int len)
{
	int i, count;
	long word;
	unsigned long *ptr = (unsigned long *)vptr;
	count = i = 0;
	while (count < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
		count += 4;
		ptr[i++] = word;
	}
}

/* read string from pid's memory */
char *read_str(int pid, unsigned long addr, int len)
{
	char *ret = calloc(32, sizeof(char));
	read_data(pid, addr, ret, len);
	return ret;
}

/* write data to location addr */
void write_data(int pid, unsigned long addr, void *vptr, int len)
{
	int i, count;
	long word;
	i = count = 0;
	while (count < len) {
		memcpy(&word, vptr + count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
		count += 4;
	}
}

/* locate link-map in pid's memory */
struct link_map *locate_linkmap(int pid)
{
	Elf_Ehdr *ehdr = malloc(sizeof(Elf_Ehdr));
	Elf_Phdr *phdr = malloc(sizeof(Elf_Phdr));
	Elf_Dyn *dyn = malloc(sizeof(Elf_Dyn));
	Elf_Word got;
	struct link_map *l = malloc(sizeof(struct link_map));
	unsigned long phdr_addr, dyn_addr, map_addr;

	/* 
	 * first we check from elf header, mapped at 0x08048000, the offset
	 * to the program header table from where we try to locate
	 * PT_DYNAMIC section.
	 */

	read_data(pid, Elf_Start, ehdr, sizeof(Elf_Ehdr));
	phdr_addr = Elf_Start + ehdr->e_phoff;
	printf("[+] Program header at %p.\n", (void *)phdr_addr);
	read_data(pid, phdr_addr, phdr, sizeof(Elf_Phdr));

	while (phdr->p_type != PT_DYNAMIC)
		read_data(pid, phdr_addr += sizeof(Elf_Phdr), phdr, sizeof(Elf_Phdr));
	
	/* 
	 * now go through dynamic section until we find address of the GOT
	 */

	read_data(pid, phdr->p_vaddr, dyn, sizeof(Elf_Dyn));
	dyn_addr = phdr->p_vaddr;

	while (dyn->d_tag != DT_PLTGOT)
		read_data(pid, dyn_addr += sizeof(Elf_Dyn), dyn, sizeof(Elf_Dyn));

	got = (Elf_Word)dyn->d_un.d_ptr;
	got += 4;	/* second GOT entry, remember? */
	/* 
	 * now just read first link_map item and return it 
	 */
	read_data(pid, (unsigned long)got, &map_addr, 4);
	read_data(pid, map_addr, l, sizeof(struct link_map));
	free(phdr);
	free(ehdr);
	free(dyn);
	return l;
}

/* resolve the tables for symbols*/
void resolv_tables(int pid, struct link_map *map)
{
	Elf_Dyn *dyn = malloc(sizeof(Elf_Dyn));
	unsigned long addr;
	addr = (unsigned long)map->l_ld;
	read_data(pid, addr, dyn, sizeof(Elf_Dyn));
	while (dyn->d_tag) {
		switch (dyn->d_tag) {
		case DT_HASH:
			read_data(pid, dyn->d_un.d_ptr + map->l_addr + 4, &nchains, sizeof(nchains));
			break;
		case DT_STRTAB:
			strtab = dyn->d_un.d_ptr;
			break;
		case DT_SYMTAB:
			symtab = dyn->d_un.d_ptr;
			break;
		default:
			break;
		}
		addr += sizeof(Elf_Dyn);
		read_data(pid, addr, dyn, sizeof(Elf_Dyn));
	}
	free(dyn);
}

/* find symbol in DT_SYMTAB */
unsigned long find_sym_in_tables(int pid, struct link_map *map, char *sym_name)
{
	Elf_Sym *sym = malloc(sizeof(Elf_Sym));
	char *str;
	int i = 0;
	while (i < nchains) {
		read_data(pid, symtab + (i * sizeof(Elf_Sym)), sym, sizeof(Elf_Sym));
		i++;
		if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		/* read symbol name from the string table */
		str = read_str(pid, strtab + sym->st_name, 32);
		printf("%s\n", str);
		/* compare it with our symbol*/
		if (strcmp(str, sym_name) == 0) {
			printf("[+] Found symbol.\n");
			return (map->l_addr + sym->st_value);
		}
	}
	/* no symbol found, return 0 */
	return 0;
}

int main(int argc, char *argv[])
{
	int child = fork();
	if (child) {
		wait(NULL);
		struct link_map *map = locate_linkmap(child);
		printf("[+] Link map located.\n");
		resolv_tables(child, map);
		char symbol[] = "exit";
		unsigned long address = find_sym_in_tables(child, map, symbol);
		if (!symbol)
			printf("[+] The value of %s is %lx.\n", symbol, address);
		else
			printf("[-] No such symbol %s.\n", symbol);
		ptrace_detach(child);
	} else {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl("/bin/su", "su", "not-a-valid-user", NULL);
	}
	return 0;
}
