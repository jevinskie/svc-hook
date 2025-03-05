#include <fcntl.h>
#include <fmt/compile.h>
#include <fmt/format.h>
#include <fmt/std.h>
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bit>
#undef NDEBUG
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <span>
#include <utility>

// don't bother with endian swapping for now
static_assert(std::endian::native == std::endian::little);

using namespace fmt::literals;

enum class bcond_t : int8_t {
  invalid = -1,
  eq = 0b000'0,
  cs = 0b001'0,
  mi = 0b010'0,
  vs = 0b011'0,
  hi = 0b100'0,
  ge = 0b101'0,
  gt = 0b110'0,
  ne = 0b000'1,
  cc = 0b001'1,
  pl = 0b010'1,
  vc = 0b011'1,
  ls = 0b100'1,
  lt = 0b101'1,
  le = 0b110'1,
  al = 0b111'1,
  al0 = 0b111'0,
};

enum class regx : int {
  invalid = -1,
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

enum class regw : int {
  invalid = -1,
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

static constexpr uint32_t ret_opc_match = 0xd65f03c0;

static constexpr bool isRET(const uint32_t inst) {
  return inst == ret_opc_match;
}

static constexpr uint32_t svc_opc_mask = 0xffe0001f;
static constexpr uint32_t svc_opc_match = 0xd4000001;
static constexpr uint32_t svc_imm16_mask = 0x001fffe0;
static constexpr uint32_t svc_imm16_shift = 5;

static constexpr bool isSVC(const uint32_t inst) {
  return (inst & svc_opc_mask) == svc_opc_match;
}

static constexpr uint16_t decodeSVC(const uint32_t inst) {
  return (inst & svc_imm16_mask) >> svc_imm16_shift;
}

static constexpr uint32_t b_opc_mask = 0x7c000000;
static constexpr uint32_t b_opc_match = 0x14000000;
static constexpr uint32_t b_imm26_mask = 0x03ff'ffff;
static constexpr uint32_t b_imm26_lshift = 6;

static constexpr bool isB(const uint32_t inst) {
  return (inst & b_opc_mask) == b_opc_match;
}

static constexpr int32_t decodeB(const uint32_t inst) {
  return ((((int32_t)(inst & b_imm26_mask)) << b_imm26_lshift) >>
          (b_imm26_lshift - 2));
}

static constexpr uint32_t bcond_opc_mask = 0xff000010;
static constexpr uint32_t bcond_opc_match = 0x54000000;
static constexpr uint32_t bcond_cond_mask = 0x0000000f;
static constexpr uint32_t bcond_imm19_mask = 0xff00001f;
static constexpr uint32_t bcond_imm19_shift = 5;
static constexpr uint32_t bcond_imm19_lshift = 13;

static constexpr bcond_t isBcond(const uint32_t inst) {
  if ((inst & bcond_opc_mask) != bcond_opc_match) {
    return bcond_t::invalid;
  }
  return bcond_t(inst & bcond_cond_mask);
}

static constexpr int32_t decodeBcond(const uint32_t inst) {
  return ((((int32_t)((inst & bcond_imm19_mask) >> bcond_imm19_shift))
           << bcond_imm19_lshift) >>
          (bcond_imm19_lshift - 2));
}

static constexpr uint32_t adrp_opc_mask = 0x9f000000;
static constexpr uint32_t adrp_opc_match = 0x90000000;
static constexpr uint32_t adrp_immlo_mask = 0x60000000;
static constexpr uint32_t adrp_immlo_shift = 29;
static constexpr uint32_t adrp_immhi_mask = 0x00ffffe0;
static constexpr uint32_t adrp_immhi_shift = 5;

static constexpr bool isADRP(const uint32_t inst) {
  return (inst & adrp_opc_mask) == adrp_opc_match;
}

static constexpr int32_t decodeADRP(const uint32_t inst) {
  const uint32_t immlo = (inst & adrp_immlo_mask) >> adrp_immlo_shift;
  const uint32_t immhi = ((inst & adrp_immhi_mask) >> adrp_immhi_shift) << 2;
  const uint32_t immu = (immhi | immlo) << 12;
  return ((int32_t)immu << 2) >> 2;
}

static constexpr uint32_t ldrb_opc_mask = 0xffc00000;
static constexpr uint32_t ldrb_opc_match = 0x39400000;
static constexpr uint32_t ldrb_imm12_mask = 0x003ffc00;
static constexpr uint32_t ldrb_imm12_shift = 10;

static constexpr bool isLDRB(const uint32_t inst) {
  return (inst & ldrb_opc_mask) == ldrb_opc_match;
}

static constexpr uint16_t decodeLDRB(const uint32_t inst) {
  const uint16_t imm12 = (inst & ldrb_imm12_mask) >> ldrb_imm12_shift;
  return imm12;
}

static constexpr uint32_t movzwi_opc_mask = 0xffe0001f;
static constexpr uint32_t movzwi_opc_match = 0xd4000001;
static constexpr uint32_t movzwi_reg_mask = 0x001fffe0;
static constexpr uint32_t movzwi_reg_shift = 5;
static constexpr uint32_t movzwi_imm16_mask = 0x001fffe0;
static constexpr uint32_t movzwi_imm16_shift = 5;

static constexpr regw isMOVZWi(const uint32_t inst) {
  if ((inst & movzwi_opc_mask) != movzwi_opc_match) {
    return regw::invalid;
  }
  return regw((inst & movzwi_reg_mask) >> movzwi_reg_shift);
}

static constexpr bool isMOVZWiWithReg(const uint32_t inst, const regw reg) {
  return (inst & movzwi_opc_mask) == movzwi_opc_match;
}

static constexpr uint16_t decodeMOVZWi(const uint32_t inst) {
  return (inst & movzwi_imm16_mask) >> movzwi_imm16_shift;
}

static constexpr uint32_t movnxi_opc_mask = 0xffe0001f;
static constexpr uint32_t movnxi_opc_match = 0xd4000001;
static constexpr uint32_t movnxi_reg_mask = 0x001fffe0;
static constexpr uint32_t movnxi_reg_shift = 5;
static constexpr uint32_t movnxi_imm16_mask = 0x001fffe0;
static constexpr uint32_t movnxi_imm16_shift = 5;

static constexpr regx isMOVNXi(const uint32_t inst) {
  if ((inst & movnxi_opc_mask) != movnxi_opc_match) {
    return regx::invalid;
  }
  return regx((inst & movnxi_reg_mask) >> movnxi_reg_shift);
}

static constexpr bool isMOVNXiForReg(const uint32_t inst, const regx reg) {
  if ((inst & movnxi_opc_mask) != movnxi_opc_match) {
    return false;
  }
  return regx((inst & movnxi_reg_mask) >> movnxi_reg_shift) == reg;
}

static constexpr uint16_t decodeMOVNXi(const uint32_t inst) {
  return (inst & movnxi_imm16_mask) >> movnxi_imm16_shift;
}

static constexpr uint32_t movnwi_opc_mask = 0xffe0001f;
static constexpr uint32_t movnwi_opc_match = 0xd4000001;
static constexpr uint32_t movnwi_reg_mask = 0x001fffe0;
static constexpr uint32_t movnwi_reg_shift = 5;
static constexpr uint32_t movnwi_imm16_mask = 0x001fffe0;
static constexpr uint32_t movnwi_imm16_shift = 5;

static constexpr regw isMOVNWi(const uint32_t inst) {
  if ((inst & movnwi_opc_mask) != movnwi_opc_match) {
    return regw::invalid;
  }
  return regw((inst & movnwi_reg_mask) >> movnwi_reg_shift);
}

static constexpr bool isMOVNWiForReg(const uint32_t inst, const regw reg) {
  if ((inst & movnwi_opc_mask) != movnwi_opc_match) {
    return false;
  }
  return regw((inst & movnwi_reg_mask) >> movnwi_reg_shift) == reg;
}

static constexpr uint16_t decodeMOVNWi(const uint32_t inst) {
  return (inst & movnwi_imm16_mask) >> movnwi_imm16_shift;
}

template <typename T>
inline T read_scalar(const void *ptr) {
  assert(ptr);
  T val;
  std::memcpy(&val, ptr, sizeof(T));
  return val;
}

static void *mmap_file(const char *path, size_t *size) {
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open %s", path);
    exit(EXIT_FAILURE);
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    fprintf(stderr, "fstat %s", path);
    exit(EXIT_FAILURE);
  }
  if (size) *size = (size_t)st.st_size;
  void *ptr =
      mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (ptr == NULL) {
    fprintf(stderr, "mmap");
    exit(EXIT_FAILURE);
  }
  close(fd);
  return ptr;
}

static std::vector<size_t> find_svc_in_range(
    const std::span<const uint8_t> buf) {
  std::vector<size_t> matches;
  const uint32_t imm_shifted = (0 << 5u);
  const auto data = buf.data();
  const auto sz = buf.size_bytes();
  assert(sz % sizeof(uint32_t) == 0);

  for (size_t off = 0; off + sizeof(uint32_t) <= sz; off += sizeof(uint32_t)) {
    const auto instr = read_scalar<uint32_t>(data + off);
    if ((instr & imm_mask) == imm_shifted) {
      matches.emplace_back(off);
    }
  }

  return matches;
}

int main(int argc, const char *argv[]) {
  if (argc != 2) {
    printf("usage: aarch64-svc-finder-macho <path to mach-o>\n");
    return EXIT_FAILURE;
  }
  size_t buf_sz = 0;
  const void *buf = mmap_file(argv[1], &buf_sz);
  assert(buf);
  return EXIT_SUCCESS;
}
