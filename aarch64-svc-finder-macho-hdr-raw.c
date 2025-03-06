
#undef NDEBUG
#include <assert.h>
#include <fcntl.h>
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
  for (size_t i = 0; i < buf_sz - sizeof(uint32_t); i += sizeof(uint32_t)) {
    const uint32_t *ip = (uint32_t *)(buf + i);
    if (*ip == 0xd4001001) {
      printf("svc 0x80 at file offset 0x%zx\n", i);
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
            }
            lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
          }
        }
      }
    }
  }
  return EXIT_SUCCESS;
}
