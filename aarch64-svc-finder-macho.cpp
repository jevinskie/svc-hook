#include <_types/_uint32_t.h>
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

// don't bother with endian swapping for now
static_assert(std::endian::native == std::endian::little);

using namespace fmt::literals;

static constexpr uint32_t ret_opc_match = 0xd65f03c0;

static bool isRET(const uint32_t inst) { return inst == ret_opc_match; }

static constexpr uint32_t svc_opc_mask = 0xffe0001f;
static constexpr uint32_t svc_opc_match = 0xd4000001;
static constexpr uint32_t svc_imm16_mask = 0x001fffe0;
static constexpr uint32_t svc_imm16_shift = 5;

static bool isSVC(const uint32_t inst) {
  return (inst & svc_opc_mask) == svc_opc_match;
}

static std::optional<uint16_t> decodeSVC(const uint32_t inst) {
  if (!isSVC(inst)) {
    return {};
  }
  return (inst & svc_imm16_mask) >> svc_imm16_shift;
}

static constexpr uint32_t b_opc_mask = 0x7c000000;
static constexpr uint32_t b_opc_match = 0x14000000;

static bool isB(const uint32_t inst) {
  return (inst & b_opc_mask) == b_opc_match;
}

static std::optional<int32_t> decodeB(const uint32_t inst) {
  if (!isB(inst)) {
    return {};
  }
  return ((((int32_t)(inst & ~b_opc_mask)) << 6) >> 4);
}

enum bcond_t : uint8_t {
  invalid = 0b000'0'0,
  eq = 0b000'0'1,
  cs = 0b001'0'1,
  mi = 0b010'0'1,
  vs = 0b011'0'1,
  hi = 0b100'0'1,
  ge = 0b101'0'1,
  gt = 0b110'0'1,
  ne = 0b000'1'1,
  cc = 0b001'1'1,
  pl = 0b010'1'1,
  vc = 0b011'1'1,
  ls = 0b100'1'1,
  lt = 0b101'1'1,
  le = 0b110'1'1,
  al = 0b111'1'1,
};

static constexpr uint32_t bcond_opc_mask = 0xff000010;
static constexpr uint32_t bcond_opc_match = 0x54000000;
static constexpr uint32_t bcond_cond_mask = 0x0000000f;

static bcond_t isBcond(const uint32_t inst) {
  if ((inst & bcond_opc_mask) == bcond_opc_match) {
    return bcond_t(((inst & bcond_cond_mask) << 1) | 1);
  } else {
    return bcond_t::invalid;
  }
}

static std::optional<int32_t> decodeBcond(const uint32_t inst) {
  if (!isBcond(inst)) {
    return {};
  }
  return ((((int32_t)(inst & ~bcond_opc_mask)) << 6) >> 4);
}

static constexpr uint32_t blo_opc_mask = 0x7c000000;
static constexpr uint32_t blo_opc_match = 0x14000000;

static bool isBLO(const uint32_t inst) {
  return (inst & blo_opc_mask) == blo_opc_match;
}

static std::optional<int32_t> decodeBLO(const uint32_t inst) {
  if (!isBLO(inst)) {
    return {};
  }
  return ((((int32_t)(inst & ~blo_opc_mask)) << 6) >> 4);
}

static constexpr uint32_t bhi_opc_mask = 0x7c000000;
static constexpr uint32_t bhi_opc_match = 0x14000000;

static bool isBHI(const uint32_t inst) {
  return (inst & bhi_opc_mask) == bhi_opc_match;
}

static std::optional<int32_t> decodeBHI(const uint32_t inst) {
  if (!isBHI(inst)) {
    return {};
  }
  return ((((int32_t)(inst & ~bhi_opc_mask)) << 6) >> 4);
}

static constexpr uint32_t adrp_opc_mask = 0x9f000000;
static constexpr uint32_t adrp_opc_match = 0x90000000;
static constexpr uint32_t adrp_immlo_mask = 0x60000000;
static constexpr uint32_t adrp_immlo_shift = 29;
static constexpr uint32_t adrp_immhi_mask = 0x00ffffe0;
static constexpr uint32_t adrp_immhi_shift = 5;

static bool isADRP(const uint32_t inst) {
  return (inst & adrp_opc_mask) == adrp_opc_match;
}

static std::optional<int32_t> decodeADRP(const uint32_t inst) {
  if (!isADRP(inst)) {
    return {};
  }
  const uint32_t immlo = (inst & adrp_immlo_mask) >> adrp_immlo_shift;
  const uint32_t immhi = ((inst & adrp_immhi_mask) >> adrp_immhi_shift) << 2;
  const uint32_t immu = (immhi | immlo) << 12;
  return ((int32_t)immu << 2) >> 2;
}

static constexpr uint32_t ldrb_opc_mask = 0xffc00000;
static constexpr uint32_t ldrb_opc_match = 0x39400000;
static constexpr uint32_t ldrb_imm12_mask = 0x003ffc00;
static constexpr uint32_t ldrb_imm12_shift = 10;

static bool isLDRB(const uint32_t inst) {
  return (inst & ldrb_opc_mask) == ldrb_opc_match;
}

static std::optional<uint16_t> decodeLDRB(const uint32_t inst) {
  if (!isLDRB(inst)) {
    return {};
  }
  const uint16_t imm12 = (inst & ldrb_imm12_mask) >> ldrb_imm12_shift;
  return imm12;
}

static constexpr uint32_t movi_x16_opc_mask = 0xffe0001f;
static constexpr uint32_t movi_x16_opc_match = 0xd4000001;
static constexpr uint32_t movi_x16_imm16_mask = 0x001fffe0;
static constexpr uint32_t movi_x16_imm16_shift = 5;

static bool isMOVix16(const uint32_t inst) {
  return (inst & movi_x16_opc_mask) == movi_x16_opc_match;
}

static std::optional<uint16_t> decodeMOVix16(const uint32_t inst) {
  if (!isMOVix16(inst)) {
    return {};
  }
  return (inst & movi_x16_imm16_mask) >> movi_x16_imm16_shift;
}

static constexpr uint32_t movi_w16_opc_mask = 0xffe0001f;
static constexpr uint32_t movi_w16_opc_match = 0xd4000001;
static constexpr uint32_t movi_w16_imm16_mask = 0x001fffe0;
static constexpr uint32_t movi_w16_imm16_shift = 5;

static bool isMOViw16(const uint32_t inst) {
  return (inst & movi_w16_opc_mask) == movi_w16_opc_match;
}

static std::optional<uint16_t> decodeMOViw16(const uint32_t inst) {
  if (!isMOViw16(inst)) {
    return {};
  }
  return (inst & movi_w16_imm16_mask) >> movi_w16_imm16_shift;
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
