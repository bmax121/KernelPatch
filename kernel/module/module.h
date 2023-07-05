#ifndef _KP_MODULE_H_
#define _KP_MODULE_H_

#define Elf_Shdr Elf64_Shdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Addr Elf64_Addr
#ifdef CONFIG_MODULES_USE_ELF_REL
#define Elf_Rel Elf64_Rel
#endif
#ifdef CONFIG_MODULES_USE_ELF_RELA
#define Elf_Rela Elf64_Rela
#endif
#define ELF_R_TYPE(X) ELF64_R_TYPE(X)
#define ELF_R_SYM(X) ELF64_R_SYM(X)

#endif