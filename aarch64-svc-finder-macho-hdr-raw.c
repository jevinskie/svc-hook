
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
#define PAGE_SIZE (4 * 1024)

enum bcond_t {
  cinvalid = -1,
  eq = 0b0000,
  cs = 0b0010,
  mi = 0b0100,
  vs = 0b0110,
  hi = 0b1000,
  ge = 0b1010,
  gt = 0b1100,
  ne = 0b0001,
  cc = 0b0011,
  pl = 0b0101,
  vc = 0b0111,
  ls = 0b1001,
  lt = 0b1011,
  le = 0b1101,
  al = 0b1111,
  al0 = 0b1110,
};

enum regx {
  xinvalid = -1,
  x0 = 0,
  x1,
  x2,
  x3,
  x4,
  x5,
  x6,
  x7,
  x8,
  x9,
  x10,
  x11,
  x12,
  x13,
  x14,
  x15,
  x16,
  x17,
  x18,
  x19,
  x20,
  x21,
  x22,
  x23,
  x24,
  x25,
  x26,
  x27,
  x28,
  x29,
  fp = x29,
  x30,
  lr = x30,
  x31,
  xzr = x31,
  sp = x31,
};

enum regw {
  winvalid = -1,
  w0 = 0,
  w1,
  w2,
  w3,
  w4,
  w5,
  w6,
  w7,
  w8,
  w9,
  w10,
  w11,
  w12,
  w13,
  w14,
  w15,
  w16,
  w17,
  w18,
  w19,
  w20,
  w21,
  w22,
  w23,
  w24,
  w25,
  w26,
  w27,
  w28,
  w29,
  w30,
  w31,
  wzr = w31,
  wsp = w31,
};

static uint32_t ret_opc_match = 0xd65f03c0;

static bool isRET(const uint32_t inst) { return inst == ret_opc_match; }

static uint32_t svc_opc_mask = 0xffe0001f;
static uint32_t svc_opc_match = 0xd4000001;
static uint32_t svc_imm16_mask = 0x001fffe0;
static uint32_t svc_imm16_shift = 5;

static bool isSVC(const uint32_t inst) {
  return (inst & svc_opc_mask) == svc_opc_match;
}

static uint16_t decodeSVC(const uint32_t inst) {
  return (inst & svc_imm16_mask) >> svc_imm16_shift;
}

static uint32_t b_opc_mask = 0x7c000000;
static uint32_t b_opc_match = 0x14000000;
static uint32_t b_imm26_mask = 0x03ffffff;
static uint32_t b_imm26_lshift = 6;

static bool isB(const uint32_t inst) {
  return (inst & b_opc_mask) == b_opc_match;
}

static int32_t decodeB(const uint32_t inst) {
  return ((((int32_t)(inst & b_imm26_mask)) << b_imm26_lshift) >>
          (b_imm26_lshift - 2));
}

static uint32_t bcond_opc_mask = 0xff000010;
static uint32_t bcond_opc_match = 0x54000000;
static uint32_t bcond_cond_mask = 0x0000000f;
static uint32_t bcond_imm19_mask = 0xff00001f;
static uint32_t bcond_imm19_shift = 5;
static uint32_t bcond_imm19_lshift = 13;

static enum bcond_t isBcond(const uint32_t inst) {
  if ((inst & bcond_opc_mask) != bcond_opc_match) {
    return cinvalid;
  }
  return (enum bcond_t)(inst & bcond_cond_mask);
}

static int32_t decodeBcond(const uint32_t inst) {
  return ((((int32_t)((inst & bcond_imm19_mask) >> bcond_imm19_shift))
           << bcond_imm19_lshift) >>
          (bcond_imm19_lshift - 2));
}

static uint32_t adrp_opc_mask = 0x9f000000;
static uint32_t adrp_opc_match = 0x90000000;
static uint32_t adrp_immlo_mask = 0x60000000;
static uint32_t adrp_immlo_shift = 29;
static uint32_t adrp_immhi_mask = 0x00ffffe0;
static uint32_t adrp_immhi_shift = 5;

static bool isADRP(const uint32_t inst) {
  return (inst & adrp_opc_mask) == adrp_opc_match;
}

static int32_t decodeADRP(const uint32_t inst) {
  const uint32_t immlo = (inst & adrp_immlo_mask) >> adrp_immlo_shift;
  const uint32_t immhi = ((inst & adrp_immhi_mask) >> adrp_immhi_shift) << 2;
  const uint32_t immu = (immhi | immlo) << 12;
  return ((int32_t)immu << 2) >> 2;
}

static uint32_t ldrb_opc_mask = 0xffc00000;
static uint32_t ldrb_opc_match = 0x39400000;
static uint32_t ldrb_imm12_mask = 0x003ffc00;
static uint32_t ldrb_imm12_shift = 10;

static bool isLDRB(const uint32_t inst) {
  return (inst & ldrb_opc_mask) == ldrb_opc_match;
}

static uint16_t decodeLDRB(const uint32_t inst) {
  const uint16_t imm12 = (inst & ldrb_imm12_mask) >> ldrb_imm12_shift;
  return imm12;
}

static uint32_t movzwi_opc_mask = 0xffc00000;
static uint32_t movzwi_opc_match = 0x52800000;
static uint32_t movzwi_reg_mask = 0x0000001f;
static uint32_t movzwi_reg_shift = 0;
static uint32_t movzwi_imm16_pmask = 0x0000ffff;
static uint32_t movzwi_imm16_shift = 5;
static uint32_t movzwi_hw_pmask = 0x00000001;
static uint32_t movzwi_hw_shift = 21;

static enum regw isMOVZWi(const uint32_t inst) {
  if ((inst & movzwi_opc_mask) != movzwi_opc_match) {
    return winvalid;
  }
  return (enum regw)((inst & movzwi_reg_mask) >> movzwi_reg_shift);
}

static bool isMOVZWiWithReg(const uint32_t inst, const enum regw reg) {
  if ((inst & movzwi_opc_mask) != movzwi_opc_match) {
    return false;
  }
  return ((enum regw)((inst & movzwi_reg_mask) >> movzwi_reg_shift)) == reg;
}

static uint32_t decodeMOVZWi(const uint32_t inst) {
  const uint8_t hw = (inst >> movzwi_hw_shift) & movzwi_hw_pmask;
  return ((uint32_t)(inst >> movzwi_imm16_shift) & movzwi_imm16_pmask)
         << (hw * 16);
}

static uint32_t movzxi_opc_mask = 0xff800000;
static uint32_t movzxi_opc_match = 0xd2800000;
static uint32_t movzxi_reg_mask = 0x0000001f;
static uint32_t movzxi_reg_shift = 0;
static uint32_t movzxi_imm16_pmask = 0x0000ffff;
static uint32_t movzxi_imm16_shift = 5;
static uint32_t movzxi_hw_pmask = 0x00000003;
static uint32_t movzxi_hw_shift = 21;

static enum regx isMOVZXi(const uint32_t inst) {
  if ((inst & movzxi_opc_mask) != movzxi_opc_match) {
    return xinvalid;
  }
  return (enum regx)((inst & movzxi_reg_mask) >> movzxi_reg_shift);
}

static bool isMOVZXiWithReg(const uint32_t inst, const enum regx reg) {
  if ((inst & movzxi_opc_mask) != movzxi_opc_match) {
    return false;
  }
  return ((enum regx)((inst & movzxi_reg_mask) >> movzxi_reg_shift)) == reg;
}

static uint64_t decodeMOVZXi(const uint32_t inst) {
  const uint8_t hw = (inst >> movzxi_hw_shift) & movzxi_hw_pmask;
  return ((uint64_t)(inst >> movzxi_imm16_shift) & movzxi_imm16_pmask)
         << (hw * 16);
}

static uint32_t movnxi_opc_mask = 0xff800000;
static uint32_t movnxi_opc_match = 0x92800000;
static uint32_t movnxi_reg_mask = 0x0000001f;
static uint32_t movnxi_reg_shift = 0;
static uint32_t movnxi_imm16_pmask = 0x0000ffff;
static uint32_t movnxi_imm16_shift = 0;
static uint32_t movnxi_hw_pmask = 0x00000003;
static uint32_t movnxi_hw_shift = 21;

static enum regx isMOVNXi(const uint32_t inst) {
  if ((inst & movnxi_opc_mask) != movnxi_opc_match) {
    return xinvalid;
  }
  return (enum regx)((inst & movnxi_reg_mask) >> movnxi_reg_shift);
}

static bool isMOVNXiWithReg(const uint32_t inst, const enum regx reg) {
  if ((inst & movnxi_opc_mask) != movnxi_opc_match) {
    return false;
  }
  return ((enum regx)((inst & movnxi_reg_mask) >> movnxi_reg_shift)) == reg;
}

static uint64_t decodeMOVNXi(const uint32_t inst) {
  const uint8_t hw = (inst >> movnxi_hw_shift) & movnxi_hw_pmask;
  return ((uint64_t)((inst >> movnxi_imm16_shift) & movnxi_imm16_pmask))
         << (hw * 16);
}

static uint32_t movnwi_opc_mask = 0xffc00000;
static uint32_t movnwi_opc_match = 0x12800000;
static uint32_t movnwi_reg_mask = 0x0000001f;
static uint32_t movnwi_reg_shift = 0;
static uint32_t movnwi_imm16_pmask = 0x0000ffff;
static uint32_t movnwi_imm16_shift = 0;
static uint32_t movnwi_hw_pmask = 0x00000001;
static uint32_t movnwi_hw_shift = 21;

static enum regw isMOVNWi(const uint32_t inst) {
  if ((inst & movnwi_opc_mask) != movnwi_opc_match) {
    return winvalid;
  }
  return (enum regw)((inst & movnwi_reg_mask) >> movnwi_reg_shift);
}

static bool isMOVNWiWithReg(const uint32_t inst, const enum regw reg) {
  if ((inst & movnwi_opc_mask) != movnwi_opc_match) {
    return false;
  }
  return ((enum regw)((inst & movnwi_reg_mask) >> movnwi_reg_shift)) == reg;
}

static uint32_t decodeMOVNWi(const uint32_t inst) {
  const uint8_t hw = (inst >> movnwi_hw_shift) & movnwi_hw_pmask;
  return ((uint32_t)((inst >> movnwi_imm16_shift) & movnwi_imm16_pmask))
         << (hw * 16);
}

static bool is_syscall(const uint32_t *ip) {
  const uint32_t instr = ip[0];
  if (!isSVC(instr) || decodeSVC(instr) != 0x80) {
    return false;
  }
  const uint32_t prev_inst = ip[-1];
  const uint32_t next_inst = ip[1];
  const enum bcond_t cond = isBcond(next_inst);
  if (!isMOVZWiWithReg(prev_inst, w16) && !isMOVZXiWithReg(prev_inst, x16) &&
      !isMOVNXiWithReg(prev_inst, x16) && !isMOVNWiWithReg(prev_inst, w16)) {
    return false;
  }
  // if (!(isRET(next_inst) || cond != cinvalid)) {
  if (!(cond == cs || cond == cc || isRET(next_inst))) {
    return false;
  }
  return true;
}

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
    // if (inst == 0xd4001001) {
    if (is_syscall(ip)) {
      printf("svc 0x80 at file offset 0x%zx\n", i);
      for (int j = -64; j <= 64; ++j) {
        cs_count = cs_disasm(cshndl, (uint8_t *)&ip[j], sizeof(ip[j]), i + j, 1,
                             &cs_insn);
        if (cs_count == 1) {
          printf("0x%" PRIx64
                 ":\t0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\t%s\t\t%s\n",
                 cs_insn->address, inst & 0xff, (inst >> 8) & 0xff,
                 (inst >> 16) & 0xff, (inst >> 24) & 0xff, cs_insn->mnemonic,
                 cs_insn->op_str);
          cs_free(cs_insn, cs_count);
        } else {
          printf(
              "0x%zx:\t0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\t<no disassembly>\n",
              i + j, inst & 0xff, (inst >> 8) & 0xff, (inst >> 16) & 0xff,
              (inst >> 24) & 0xff);
        }
      }
      const uintptr_t up = (uintptr_t)ip;
      const uintptr_t up_page = __builtin_align_down(up, PAGE_SIZE);
      for (uintptr_t upg = up_page; upg >= ubuf; upg -= PAGE_SIZE) {
        if (*(uint32_t *)upg == MH_MAGIC_64) {
          const struct mach_header_64 *mh = (struct mach_header_64 *)upg;
          printf("mach header: %p off: 0x%zx\n", mh,
                 (uintptr_t)mh - (uintptr_t)buf);
          const struct load_command *lc =
              (struct load_command *)((uintptr_t)mh + sizeof(*mh));
          for (uint32_t j = 0; j < mh->ncmds; ++j) {
            if (lc->cmd == LC_ID_DYLIB) {
              const struct dylib_command *dylib_id_cmd =
                  (struct dylib_command *)lc;
              const char *dylib_name =
                  (const char *)((uintptr_t)dylib_id_cmd +
                                 dylib_id_cmd->dylib.name.offset);
              printf("LC_ID_DYLIB: %s mh: %p foff: 0x%zx\n", dylib_name, mh,
                     (uintptr_t)mh - (uintptr_t)buf);
              break;
            } else if (lc->cmd == LC_ID_DYLINKER) {
              const struct dylinker_command *dynlinker_cmd =
                  (struct dylinker_command *)lc;
              const char *dynlinker_name =
                  (const char *)((uintptr_t)dynlinker_cmd +
                                 dynlinker_cmd->name.offset);
              printf("LC_ID_DYLINKER: %s mh: %p foff: 0x%zx\n", dynlinker_name,
                     mh, (uintptr_t)mh - (uintptr_t)buf);
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
