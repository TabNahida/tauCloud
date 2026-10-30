#include <taucloud/nfs.hpp>
namespace tc::nfs_detail {
std::string reader::fixed(size_t n) {
  if (n > data.size() - pos)
    throw xdr_error();
  auto v = std::string(data.substr(pos, n));
  pos += n;
  return v;
}
uint32_t reader::u32() {
  if (data.size() - pos < 4)
    throw xdr_error();
  uint32_t v = 0;
  for (unsigned i = 0; i < 4; ++i)
    v = (v << 8) | static_cast<unsigned char>(data[pos++]);
  return v;
}
uint64_t reader::u64() {
  auto hi = u32();
  return (uint64_t(hi) << 32) | u32();
}
bool reader::boolean() {
  auto n = u32();
  if (n > 1)
    throw xdr_error();
  return n != 0;
}
std::string reader::opaque(size_t limit) {
  auto n = u32();
  if (n > limit)
    throw xdr_error();
  auto v = fixed(n);
  auto padding = fixed((4 - n % 4) % 4);
  for (char c : padding)
    if (c)
      throw xdr_error();
  return v;
}
void reader::end() const {
  if (pos != data.size())
    throw xdr_error();
}
writer &writer::u32(uint32_t n) {
  for (int i = 3; i >= 0; --i)
    data += char(n >> (i * 8));
  return *this;
}
writer &writer::u64(uint64_t n) { return u32(uint32_t(n >> 32)).u32(uint32_t(n)); }
writer &writer::boolean(bool b) { return u32(b ? 1 : 0); }
writer &writer::fixed(std::string_view s) {
  data += s;
  return *this;
}
writer &writer::opaque(std::string_view s) {
  u32(uint32_t(s.size()));
  data += s;
  data.append((4 - s.size() % 4) % 4, '\0');
  return *this;
}
size_t record_decoder::fragment(uint32_t marker) {
  auto n = marker & 0x7fffffffu;
  if (++fragments > 64 || n == 0 || n > max_record || n > max_record - data.size())
    throw xdr_error();
  return n;
}
bool record_decoder::append(uint32_t marker, std::string_view b) {
  if (b.size() != (marker & 0x7fffffffu) || b.size() > max_record - data.size())
    throw xdr_error();
  data += b;
  return (marker & 0x80000000u) != 0;
}
} // namespace tc::nfs_detail
