#pragma once
#include <taucloud/http_stream.hpp>
#include <pugixml.hpp>
namespace tc::dav {
struct location {
  std::string share, path;
  bool trailing = false;
};
location decode_path(const std::string &);
std::string href(const std::string &share, const std::string &path, bool directory = false);
std::string escape(std::string_view);
std::string date(int64_t nanoseconds);
std::optional<int64_t> parse_date(const std::string &);
pugi::xml_document xml(const std::string &);
std::pair<std::string, std::string> name(pugi::xml_node);
json property(pugi::xml_node);
json conditions(const http_stream::head &, const location &, const std::string &origin);
std::string lock_xml(const json &, const std::string &share, const std::string &prefix = "");
std::string propfind(const std::string &body, const json &items, const std::string &share,
                     const std::string &prefix);
} // namespace tc::dav
