#include <taucloud/dav.hpp>
#include <taucloud/files.hpp>
#include <iomanip>
#include <sstream>
#include <set>
#include <utf8proc.h>
namespace tc::dav {
std::string escape(std::string_view text) {
  std::string out;
  for (char c : text)
    switch (c) {
    case '&':
      out += "&amp;";
      break;
    case '<':
      out += "&lt;";
      break;
    case '>':
      out += "&gt;";
      break;
    case '"':
      out += "&quot;";
      break;
    default:
      out += c;
    }
  return out;
}
location decode_path(const std::string &input) {
  require(input.starts_with("/dav/") && input.find_first_of("?#") == std::string::npos,
          "invalid_path");
  std::string path;
  auto hex = [](char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 5; i < input.size(); ++i) {
    unsigned char c = input[i];
    if (c == '%') {
      require(i + 2 < input.size(), "invalid_path");
      int a = hex(input[++i]), b = hex(input[++i]);
      require(a >= 0 && b >= 0, "invalid_path");
      c = static_cast<unsigned char>(a * 16 + b);
      require(c != '/' && c != '\\', "invalid_path");
    }
    require(c >= 32 && c != 127 && c != '\\', "invalid_path");
    path += char(c);
  }
  location out;
  out.trailing = path.ends_with('/');
  if (out.trailing)
    path.pop_back();
  auto slash = path.find('/');
  out.share = path.substr(0, slash);
  out.path = slash == std::string::npos ? "" : path.substr(slash + 1);
  require(!out.share.empty() && out.share.size() <= 48 &&
              out.share.find_first_not_of(
                  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") ==
                  std::string::npos,
          "invalid_path");
  if (!out.path.empty())
    portable_path(out.path);
  return out;
}
std::string href(const std::string &share, const std::string &path, bool directory) {
  std::string out = "/dav/" + share + "/";
  for (unsigned char c : path) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        std::string_view("/-._~").find(c) != std::string_view::npos)
      out += char(c);
    else {
      out += '%';
      out += "0123456789ABCDEF"[c >> 4];
      out += "0123456789ABCDEF"[c & 15];
    }
  }
  if (directory && !out.ends_with('/'))
    out += '/';
  return out;
}
std::string date(int64_t nanoseconds) {
  auto seconds = static_cast<time_t>(nanoseconds / 1000000000);
  std::tm tm{};
#ifdef _WIN32
  gmtime_s(&tm, &seconds);
#else
  gmtime_r(&seconds, &tm);
#endif
  char buffer[64];
  std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  return buffer;
}
std::optional<int64_t> parse_date(const std::string &value) {
  std::tm tm{};
  std::istringstream input(value);
  input.imbue(std::locale::classic());
  input >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
  if (input.fail() || input.peek() != std::char_traits<char>::eof())
    return {};
#ifdef _WIN32
  auto seconds = _mkgmtime(&tm);
#else
  auto seconds = timegm(&tm);
#endif
  if (seconds < 0 || seconds > INT64_MAX / 1000000000)
    return {};
  return static_cast<int64_t>(seconds) * 1000000000;
}
static std::string ns(pugi::xml_node node, const std::string &prefix) {
  if (prefix == "xml")
    return "http://www.w3.org/XML/1998/namespace";
  auto attr = prefix.empty() ? "xmlns" : "xmlns:" + prefix;
  for (auto p = node; p; p = p.parent())
    if (auto a = p.attribute(attr.c_str())) {
      require(prefix.empty() || *a.value(), "invalid_xml");
      return a.value();
    }
  require(prefix.empty(), "invalid_xml");
  return "";
}
static bool ncname(std::string_view value) {
  bool first = true;
  for (size_t i = 0; i < value.size();) {
    utf8proc_int32_t c;
    auto n = utf8proc_iterate(reinterpret_cast<const utf8proc_uint8_t *>(value.data() + i),
                              value.size() - i, &c);
    if (n <= 0)
      return false;
    auto range = [&](int a, int b) { return c >= a && c <= b; };
    bool start = c == '_' || range('A', 'Z') || range('a', 'z') || range(0xC0, 0xD6) ||
                 range(0xD8, 0xF6) || range(0xF8, 0x2FF) || range(0x370, 0x37D) ||
                 range(0x37F, 0x1FFF) || range(0x200C, 0x200D) || range(0x2070, 0x218F) ||
                 range(0x2C00, 0x2FEF) || range(0x3001, 0xD7FF) || range(0xF900, 0xFDCF) ||
                 range(0xFDF0, 0xFFFD) || range(0x10000, 0xEFFFF);
    if (!start && (first || !(c == '-' || c == '.' || range('0', '9') || c == 0xB7 ||
                              range(0x300, 0x36F) || range(0x203F, 0x2040))))
      return false;
    first = false;
    i += static_cast<size_t>(n);
  }
  return !first;
}
static void qname(const std::string &value) {
  auto colon = value.find(':');
  require(colon == std::string::npos
              ? ncname(value)
              : ncname(value.substr(0, colon)) && ncname(value.substr(colon + 1)),
          "invalid_xml");
}
std::pair<std::string, std::string> name(pugi::xml_node node) {
  std::string value = node.name();
  qname(value);
  auto colon = value.find(':');
  require(colon == std::string::npos || value.find(':', colon + 1) == std::string::npos,
          "invalid_xml");
  return {ns(node, colon == std::string::npos ? "" : value.substr(0, colon)),
          value.substr(colon == std::string::npos ? 0 : colon + 1)};
}
static void xml_chars(std::string_view text) {
  for (size_t i = 0; i < text.size();) {
    utf8proc_int32_t c;
    auto n = utf8proc_iterate(reinterpret_cast<const utf8proc_uint8_t *>(text.data() + i),
                              text.size() - i, &c);
    require(n > 0 && (c == 9 || c == 10 || c == 13 || (c >= 32 && c <= 0xD7ff) ||
                      (c >= 0xE000 && c <= 0xFFFD) || (c >= 0x10000 && c <= 0x10FFFF)),
            "invalid_xml");
    i += static_cast<size_t>(n);
  }
}
pugi::xml_document xml(const std::string &body) {
  xml_chars(body);
  // pugixml deliberately preserves unknown entities; DAV requires well-formed XML.
  for (size_t i = 0; i < body.size(); ++i) {
    auto skip = [&](std::string_view begin, std::string_view end) {
      if (body.compare(i, begin.size(), begin) != 0)
        return false;
      auto close = body.find(end, i + begin.size());
      require(close != std::string::npos, "invalid_xml");
      i = close + end.size() - 1;
      return true;
    };
    if (skip("<![CDATA[", "]]>") || skip("<!--", "-->") || skip("<?", "?>"))
      continue;
    if (body[i] == '&') {
      auto end = body.find(';', i);
      require(end != std::string::npos, "invalid_xml");
      auto entity = body.substr(i + 1, end - i - 1);
      bool valid = entity == "amp" || entity == "lt" || entity == "gt" || entity == "quot" ||
                   entity == "apos";
      if (entity.starts_with("#")) {
        size_t start = entity.starts_with("#x") ? 2 : 1;
        valid = start < entity.size() &&
                entity.substr(start).find_first_not_of(
                    start == 2 ? "0123456789abcdefABCDEF" : "0123456789") == std::string::npos;
      }
      require(valid, "invalid_xml");
      i = end;
    }
  }
  require(body.size() <= 65536 && body.find("<!DOCTYPE") == std::string::npos &&
              body.find("<!ENTITY") == std::string::npos,
          "invalid_xml");
  pugi::xml_document doc;
  require(bool(doc.load_buffer(body.data(), body.size(), pugi::parse_full | pugi::parse_ws_pcdata,
                               pugi::encoding_utf8)),
          "invalid_xml");
  size_t count = 0, roots = 0;
  std::vector<std::pair<pugi::xml_node, int>> nodes;
  for (auto n : doc.children()) {
    require(n.type() != pugi::node_doctype, "invalid_xml");
    if (n.type() == pugi::node_element) {
      ++roots;
      nodes.emplace_back(n, 0);
    }
  }
  require(roots == 1, "invalid_xml");
  while (!nodes.empty()) {
    auto [n, depth] = nodes.back();
    nodes.pop_back();
    require(++count <= 4096 && depth <= 32, "invalid_xml");
    xml_chars(n.value());
    if (n.type() == pugi::node_element) {
      name(n);
      std::set<std::string> attrs;
      for (auto a : n.attributes()) {
        std::string key = a.name();
        qname(key);
        xml_chars(a.value());
        if (key == "xmlns" || key.starts_with("xmlns:")) {
          std::string value = a.value();
          require(key != "xmlns:xmlns" && value != "http://www.w3.org/2000/xmlns/", "invalid_xml");
          require(key == "xmlns" || !value.empty(), "invalid_xml");
          require((key == "xmlns:xml") == (value == "http://www.w3.org/XML/1998/namespace"),
                  "invalid_xml");
        } else {
          auto colon = key.find(':');
          if (colon != std::string::npos) {
            require(colon && colon + 1 < key.size() &&
                        key.find(':', colon + 1) == std::string::npos,
                    "invalid_xml");
            key = ns(n, key.substr(0, colon)) + "|" + key.substr(colon + 1);
          } else
            key = "|" + key;
        }
        require(attrs.insert(key).second, "invalid_xml");
      }
    }
    for (auto c : n.children())
      nodes.emplace_back(c, depth + 1);
  }
  return doc;
}
json property(pugi::xml_node node) {
  auto [uri, local] = name(node);
  require(uri.size() <= 1024 && local.size() <= 256, "invalid_xml");
  pugi::xml_document copy;
  auto root = copy.append_copy(node);
  std::set<std::string> seen;
  for (auto p = node; p; p = p.parent())
    for (auto a : p.attributes()) {
      std::string key = a.name();
      if ((key == "xmlns" || key.starts_with("xmlns:")) && seen.insert(key).second &&
          !root.attribute(key.c_str()))
        root.append_attribute(key.c_str()) = a.value();
    }
  std::ostringstream out;
  root.print(out, "", pugi::format_raw, pugi::encoding_utf8);
  return {{"namespace", uri},
          {"name", local},
          {"key", json::array({uri, local}).dump()},
          {"xml", out.str()}};
}
json conditions(const http_stream::head &h, const location &loc, const std::string &origin) {
  json out = json::object();
  if (h.headers.contains("if-unmodified-since") && !h.headers.contains("if-match"))
    if (auto date = parse_date(h.get("if-unmodified-since")))
      out["unmodified_since"] = *date;
  if (h.headers.contains("if-match"))
    out["if_match"] = h.get("if-match");
  if (h.headers.contains("if-none-match"))
    out["if_none_match"] = h.get("if-none-match");
  auto value = h.get("if");
  if (value.empty())
    return out;
  size_t pos = 0;
  json groups = json::array();
  std::string path = loc.path;
  auto skip = [&] {
    while (pos < value.size() && (value[pos] == ' ' || value[pos] == '\t'))
      ++pos;
  };
  auto bracket = [&](char a, char b) {
    require(pos < value.size() && value[pos++] == a, "invalid_if");
    auto end = value.find(b, pos);
    require(end != std::string::npos, "invalid_if");
    auto v = value.substr(pos, end - pos);
    pos = end + 1;
    return v;
  };
  while (pos < value.size()) {
    skip();
    if (pos == value.size())
      break;
    if (value[pos] == '<') {
      auto target = bracket('<', '>');
      require(target.starts_with(origin + "/"), "invalid_destination");
      auto tagged = decode_path(target.substr(origin.size()));
      require(tagged.share == loc.share, "invalid_destination");
      path = tagged.path;
      skip();
    }
    require(pos < value.size() && value[pos] == '(', "invalid_if");
    json group = {{"path", path}, {"lists", json::array()}};
    while (pos < value.size() && value[pos] == '(') {
      ++pos;
      json list = json::array();
      for (;;) {
        skip();
        require(pos < value.size(), "invalid_if");
        if (value[pos] == ')') {
          ++pos;
          break;
        }
        bool invert = false;
        if (value.substr(pos, 4) == "Not ") {
          invert = true;
          pos += 4;
          skip();
        }
        require(pos < value.size() && (value[pos] == '<' || value[pos] == '['), "invalid_if");
        bool entity = value[pos] == '[';
        auto v = bracket(entity ? '[' : '<', entity ? ']' : '>');
        list.push_back({{"kind", entity ? "etag" : "token"}, {"value", v}, {"not", invert}});
        require(list.size() <= 16, "invalid_if");
      }
      require(!list.empty(), "invalid_if");
      group["lists"].push_back(list);
      skip();
    }
    groups.push_back(group);
    require(groups.size() <= 16, "invalid_if");
  }
  out["dav_if"] = groups;
  return out;
}
std::string lock_xml(const json &lock, const std::string &share, const std::string &prefix) {
  auto path = lock.at("path").get<std::string>();
  if (!prefix.empty() && (path == prefix || path.starts_with(prefix + "/"))) {
    path.erase(0, prefix.size());
    if (path.starts_with("/"))
      path.erase(0, 1);
  }
  auto seconds = std::max<int64_t>(0, (lock.at("expires").get<int64_t>() - now()) / 1000);
  return "<D:activelock><D:lockscope><D:" + lock.at("scope").get<std::string>() +
         "/></D:lockscope><D:locktype><D:write/></D:locktype><D:depth>" +
         lock.at("depth").get<std::string>() + "</D:depth>" + lock.at("owner").get<std::string>() +
         "<D:timeout>Second-" + std::to_string(seconds) + "</D:timeout><D:locktoken><D:href>" +
         escape(lock.at("token").get<std::string>()) +
         "</D:href></D:locktoken><D:lockroot><D:href>" + href(share, path) +
         "</D:href></D:lockroot></D:activelock>";
}
std::string propfind(const std::string &body, const json &items, const std::string &share,
                     const std::string &prefix) {
  std::string mode = "allprop";
  json requested = json::array();
  if (!body.empty()) {
    auto doc = xml(body);
    require(name(doc.document_element()) == std::pair<std::string, std::string>{"DAV:", "propfind"},
            "invalid_xml");
    for (auto n : doc.document_element().children())
      if (n.type() == pugi::node_element) {
        auto [uri, local] = name(n);
        require(uri == "DAV:" && (local == "allprop" || local == "propname" || local == "prop" ||
                                  local == "include"),
                "invalid_xml");
        if (local != "include")
          mode = local;
        if (local == "prop" || local == "include")
          for (auto p : n.children())
            if (p.type() == pugi::node_element)
              requested.push_back(property(p));
      }
  }
  std::string out = "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">";
  for (auto item : items) {
    auto path = item.at("path").get<std::string>();
    auto relative = prefix.empty() ? path : path.substr(std::min(path.size(), prefix.size() + 1));
    bool dir = item.at("directory");
    std::map<std::string, json> properties;
    auto add = [&](std::string n, std::string value) {
      auto key = json::array({"DAV:", n}).dump();
      properties[key] = {
          {"namespace", "DAV:"}, {"name", n}, {"xml", "<D:" + n + ">" + value + "</D:" + n + ">"}};
    };
    add("resourcetype", dir ? "<D:collection/>" : "");
    add("getcontentlength", std::to_string(item.at("size").get<uint64_t>()));
    add("getcontenttype", dir ? "httpd/unix-directory" : "application/octet-stream");
    add("getetag", escape(item.at("etag").get<std::string>()));
    add("getlastmodified", date(item.at("modified_ns")));
    add("displayname",
        escape(path.substr(path.rfind('/') == std::string::npos ? 0 : path.rfind('/') + 1)));
    add("supportedlock",
        "<D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></"
        "D:locktype></D:lockentry><D:lockentry><D:lockscope><D:shared/></"
        "D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>");
    std::string locks;
    for (auto lock : item.at("locks"))
      locks += lock_xml(lock, share, prefix);
    add("lockdiscovery", locks);
    for (auto &[key, p] : item.at("properties").items())
      properties[key] = p;
    json selected = requested;
    if (mode != "prop") {
      selected = json::array();
      for (auto &[key, p] : properties)
        selected.push_back(p);
      for (auto p : requested)
        if (!properties.contains(p.at("key")))
          selected.push_back(p);
    }
    std::string ok, missing;
    for (auto p : selected) {
      auto key = p.value("key", json::array({p.at("namespace"), p.at("name")}).dump());
      auto blank = "<P:" + p.at("name").get<std::string>() + " xmlns:P=\"" +
                   escape(p.at("namespace").get<std::string>()) + "\"/>";
      if (p.at("namespace") == "")
        blank = "<" + p.at("name").get<std::string>() + " xmlns=\"\"/>";
      if (properties.contains(key))
        ok += mode == "propname" ? blank : properties[key].at("xml").get<std::string>();
      else
        missing += blank;
    }
    out += "<D:response><D:href>" + href(share, relative, dir) + "</D:href>";
    if (!ok.empty())
      out += "<D:propstat><D:prop>" + ok +
             "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>";
    if (!missing.empty())
      out += "<D:propstat><D:prop>" + missing +
             "</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>";
    out += "</D:response>";
    require(out.size() <= 1024 * 1024, "tree_limit");
  }
  return out + "</D:multistatus>";
}
} // namespace tc::dav
