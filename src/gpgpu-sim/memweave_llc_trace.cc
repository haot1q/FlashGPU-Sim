#include "memweave_llc_trace.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <limits>
#include <locale>
#include <map>
#include <sstream>
#include <string>

#include "mem_fetch.h"

namespace memweave_llc_trace {
namespace {

const uint64_t kMaxBytes = 268435456;

[[noreturn]] void fail(const char *operation, int error = 0) {
  std::fprintf(stderr, "MemWeave LLC trace: %s%s%s\n", operation,
               error ? ": " : "", error ? std::strerror(error) : "");
  std::fflush(stderr);
  // A partial trace must not acquire a success footer through exit handlers.
  std::_Exit(EXIT_FAILURE);
}

bool valid_run_id(const char *value) {
  if (!value || !value[0] || std::strlen(value) > 128) return false;
  for (const char *p = value; *p; ++p) {
    const bool valid = (*p >= 'a' && *p <= 'z') ||
                       (*p >= 'A' && *p <= 'Z') ||
                       (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' ||
                       *p == '-';
    if (!valid) return false;
  }
  return true;
}

uint64_t byte_limit() {
  const char *value = std::getenv("MEMWEAVE_LLC_TRACE_MAX_BYTES");
  if (!value) return kMaxBytes;
  uint64_t result = 0;
  for (const char *p = value; *p; ++p) {
    if (*p < '0' || *p > '9' || result > (kMaxBytes - (*p - '0')) / 10)
      fail("MAX_BYTES must be a decimal integer in 1..268435456");
    result = result * 10 + (*p - '0');
  }
  if (!result) fail("MAX_BYTES must be a decimal integer in 1..268435456");
  return result;
}

std::string hex_address(uint64_t address) {
  char result[19];
  std::snprintf(result, sizeof(result), "0x%016llx",
                static_cast<unsigned long long>(address));
  return result;
}

std::string byte_mask_hex(const mem_access_byte_mask_t &mask) {
  static const char digits[] = "0123456789abcdef";
  std::string result = "0x";
  for (int nibble = 31; nibble >= 0; --nibble) {
    unsigned value = 0;
    for (unsigned bit = 0; bit < 4; ++bit)
      if (mask.test(nibble * 4 + bit)) value |= 1u << bit;
    result += digits[value];
  }
  return result;
}

std::string parent_uid(mem_fetch *parent) {
  return parent ? std::to_string(parent->get_request_uid()) : "null";
}

class writer {
 public:
  writer() : file_(NULL), bytes_(0), limit_(0), events_(0), full_queries_(0) {
    const char *path = std::getenv("MEMWEAVE_LLC_TRACE");
    if (!path) return;
    if (!path[0]) fail("TRACE path must not be empty");
    const char *run_id = std::getenv("MEMWEAVE_LLC_TRACE_RUN_ID");
    if (!valid_run_id(run_id))
      fail("RUN_ID must match [A-Za-z0-9_.-]{1,128}");
    limit_ = byte_limit();
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) fail("cannot exclusively create output", errno);
    struct stat info;
    if (fstat(fd, &info) != 0) fail("cannot inspect output", errno);
    if (!S_ISREG(info.st_mode)) fail("output is not a regular file");
    file_ = fdopen(fd, "w");
    if (!file_) fail("cannot open output stream", errno);
    write_line(std::string("{\"record\":\"header\",\"schema\":\"memweave.m0.llc\","
                           "\"version\":1,\"run_id\":\"") +
               run_id +
               "\",\"boundary\":\"l2_to_dram_enqueue\",\"clock_domain\":\"core\","
               "\"cycle_unit\":\"tick\",\"mask_line_bytes\":128,\"sector_bytes\":32}\n");
  }

  ~writer() {
    if (!file_) return;
    // No GPU/request pointers are retained or dereferenced during shutdown.
    write_line("{\"record\":\"end\",\"event_count\":" + std::to_string(events_) +
               ",\"queue_full_observations\":" + std::to_string(full_queries_) +
               "}\n");
    if (std::fflush(file_) != 0) fail("cannot flush output", errno);
    if (std::fclose(file_) != 0) fail("cannot close output", errno);
  }

  void observe_full() {
    if (!file_) return;
    if (full_queries_ == std::numeric_limits<uint64_t>::max())
      fail("queue full observation counter overflow");
    ++full_queries_;
  }

  void record(mem_fetch *mf, unsigned subpartition, uint64_t cycle, bool bypass) {
    if (!file_) return;
    uint64_t &port_sequence = port_sequences_[subpartition];
    if (events_ == std::numeric_limits<uint64_t>::max() ||
        port_sequence == std::numeric_limits<uint64_t>::max())
      fail("event sequence overflow");
    const mem_access_byte_mask_t byte_mask = mf->get_access_byte_mask();
    const uint64_t address = mf->get_addr();
    const address_type pc = mf->get_pc();
    std::ostringstream line;
    line.imbue(std::locale::classic());
    line << std::boolalpha << "{\"record\":\"event\",\"event_id\":" << events_
         << ",\"port_sequence\":" << port_sequence << ",\"cycle\":" << cycle
         << ",\"subpartition\":" << subpartition << ",\"request_uid\":"
         << mf->get_request_uid() << ",\"original_request_uid\":"
         << parent_uid(mf->get_original_mf()) << ",\"original_write_request_uid\":"
         << parent_uid(mf->get_original_wr_mf()) << ",\"access_type\":\""
         << mem_access_type_str(mf->get_access_type()) << "\",\"is_write\":"
         << mf->get_is_write() << ",\"bypass\":" << bypass << ",\"address\":\""
         << hex_address(address) << "\",\"mask_line_address\":\""
         << hex_address(address & ~uint64_t(127)) << "\",\"data_size_bytes\":"
         << mf->get_data_size() << ",\"access_size_bytes\":"
         << mf->get_access_size() << ",\"sector_mask\":\"0x" << std::hex
         << mf->get_access_sector_mask().to_ulong() << std::dec
         << "\",\"byte_mask\":\"" << byte_mask_hex(byte_mask)
         << "\",\"raw_byte_mask_popcount\":" << byte_mask.count()
         << ",\"stream_id\":" << mf->get_streamID() << ",\"pc\":"
         << (pc == static_cast<address_type>(-1) ? "null"
                                               : "\"" + hex_address(pc) + "\"")
         << ",\"instruction_prefetch\":" << mf->is_instruction_prefetch()
         << ",\"raw_atomic\":" << mf->isatomic() << ",\"kernel_id\":null}\n";
    write_line(line.str());
    ++events_;
    ++port_sequence;
  }

 private:
  void write_line(const std::string &line) {
    if (line.size() > limit_ - bytes_) fail("output byte limit exceeded");
    if (std::fwrite(line.data(), 1, line.size(), file_) != line.size())
      fail("cannot write output", errno);
    // Detect storage errors while producing the trace, not just at final close.
    if (std::fflush(file_) != 0) fail("cannot flush output", errno);
    bytes_ += line.size();
  }

  FILE *file_;
  uint64_t bytes_;
  uint64_t limit_;
  uint64_t events_;
  uint64_t full_queries_;
  std::map<unsigned, uint64_t> port_sequences_;
};

writer &instance() {
  static writer output;
  return output;
}

}  // namespace

void initialize() { instance(); }

void observe_queue_full() { instance().observe_full(); }

void record_enqueue(mem_fetch *request, unsigned subpartition, uint64_t cycle,
                    bool bypass) {
  instance().record(request, subpartition, cycle, bypass);
}

}  // namespace memweave_llc_trace
