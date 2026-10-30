#include <taucloud/dav.hpp>
#include <taucloud/files.hpp>
#include <iostream>
using namespace tc;
int main() {
  int passed = 0;
  auto ok = [&](bool v) {
    require(v, "test_failed");
    ++passed;
  };
  auto reject = [&](auto f) {
    bool failed = false;
    try {
      f();
    } catch (const error &) {
      failed = true;
    }
    ok(failed);
  };
  try {
    auto h = http_stream::parse_head(
        "PUT /dav/a/x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4294967296\r\n\r\n");
    ok(h.length == 4294967296ULL);
    for (auto headers :
         {"Content-Length: -1\r\n", "Content-Length: 1\r\nContent-Length: 1\r\n",
          "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n", "Transfer-Encoding: gzip\r\n",
          " folded: value\r\n", "Foo: a\r\nfoo: b\r\n"})
      reject([&] {
        http_stream::parse_head("PUT / HTTP/1.1\r\nHost: localhost\r\n" + std::string(headers) +
                                "\r\n");
      });
    reject([&] { http_stream::decimal("9223372036854775808"); });
    ok(dav::decode_path("/dav/share/%E4%B8%AD%E6%96%87").path == "中文");
    ok(path_fold("É") == path_fold("é"));
    for (auto path : {"/dav/a/../b", "/dav/a/%2f", "/dav/a/%00", "/dav/a/x%5Cy", "/dav/a/e%CC%81",
                      "/dav/a/%ff"})
      reject([&] { dav::decode_path(path); });
    for (auto body :
         {"<!DOCTYPE a><a/>", "<a/><b/>", "<a:b/>", "<a xmlns:x=\"\"><x:b/></a>",
          "<a xmlns:xml=\"bad\"/>", "<a xmlns:x=\"urn:x\" xmlns:y=\"urn:x\" x:b=\"1\" y:b=\"2\"/>",
          "<a>&#1;</a>", "<a>&unknown;</a>", "<1bad/>", "<a 2bad=\"x\"/>"})
      reject([&] { dav::xml(body); });
    std::string deep;
    for (int i = 0; i < 34; ++i)
      deep += "<a>";
    for (int i = 0; i < 34; ++i)
      deep += "</a>";
    reject([&] { dav::xml(deep); });
    auto doc = dav::xml("<a xmlns:p=\"urn:p\"><p:b xml:lang=\"en\">text</p:b></a>");
    ok(dav::property(doc.document_element().first_child())
           .at("xml")
           .get<std::string>()
           .find("xmlns:p=\"urn:p\"") != std::string::npos);
    std::cout << json{{"status", "passed"}, {"checks", passed}}.dump() << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
