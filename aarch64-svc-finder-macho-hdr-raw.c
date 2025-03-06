
#undef NDEBUG
#include <assert.h>
#include <capstone/capstone.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif
#define PAGE_SIZE (16 * 1024)

int main(int argc, const char *argv[]) {
  if (argc != 2) {
    printf("usage: aarch64-svc-finder-macho-hdr-raw <path to mach-o dump>\n");
    return EXIT_FAILURE;
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open %s", argv[1]);
    exit(EXIT_FAILURE);
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    fprintf(stderr, "fstat %s", argv[1]);
    exit(EXIT_FAILURE);
  }
  size_t buf_sz = (size_t)st.st_size;
  const uint8_t *buf =
      (uint8_t *)mmap(NULL, buf_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (buf == NULL) {
    fprintf(stderr, "mmap");
    exit(EXIT_FAILURE);
  }
  close(fd);
  assert(buf);
  assert(buf_sz);
  assert(buf_sz % 4 == 0);
  const uintptr_t ubuf = (uintptr_t)buf;

  csh cshndl;
  cs_insn *cs_insn;
  size_t cs_count;
  int cs_open_res = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &cshndl);
  if (cs_open_res != CS_ERR_OK) {
    printf("cs_open failed with %d\n", cs_open_res);
    return 2;
  }

  for (size_t i = 0; i < buf_sz - sizeof(uint32_t); i += sizeof(uint32_t)) {
    const uint32_t *ip = (uint32_t *)(buf + i);
    const uint32_t inst = *ip;
    if (inst == 0xd4001001) {
      printf("svc 0x80 at file offset 0x%zx\n", i);
      cs_count = cs_disasm(cshndl, (const uint8_t *)(ip - 64),
                           sizeof(uint64_t) * (64 * 2 + 1), i, 0, &cs_insn);
      if (cs_count > 0) {
        size_t j;
        for (j = 0; j < cs_count; j++) {
          printf("0x%" PRIx64
                 ":\t0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\t%s\t\t%s\n",
                 cs_insn[j].address, inst & 0xff, (inst >> 8) & 0xff,
                 (inst >> 16) & 0xff, (inst >> 24) & 0xff, cs_insn[j].mnemonic,
                 cs_insn[j].op_str);
        }

        cs_free(cs_insn, cs_count);
      } else {
        printf("ERROR: Failed to disassemble given code at file offset %zx\n",
               i);
      }
      const uintptr_t up = (uintptr_t)ip;
      const uintptr_t up_page = __builtin_align_down(up, PAGE_SIZE);
      for (uintptr_t upg = up_page; upg >= ubuf; upg -= PAGE_SIZE) {
        if (*(uint32_t *)upg == MH_MAGIC_64) {
          const struct mach_header_64 *mh = (struct mach_header_64 *)upg;
          printf("mach header: %p\n", mh);
          const struct load_command *lc =
              (struct load_command *)((uintptr_t)mh + sizeof(*mh));
          for (uint32_t j = 0; j < mh->ncmds; ++j) {
            if (lc->cmd == LC_ID_DYLIB) {
              const struct dylib_command *dylib_cmd =
                  (struct dylib_command *)lc;
              const char *dylib_name =
                  (const char *)((uintptr_t)dylib_cmd +
                                 dylib_cmd->dylib.name.offset);
              printf("LC_ID_DYLIB: %s\n", dylib_name);
              break;
            }
            lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
          }
          break;
        }
      }
    }
  }
  cs_close(&cshndl);
  return EXIT_SUCCESS;
}
