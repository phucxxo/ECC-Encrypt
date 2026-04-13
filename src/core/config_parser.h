#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <string>
#include <map>
#include <fstream>
#include <stdexcept>

class ConfigParser {
public:
    static std::map<std::string, std::string> parse(const std::string &path) {
        std::map<std::string, std::string> config;
        std::ifstream file(path);
        if (!file.is_open())
            throw std::runtime_error("Cannot open config file: " + path);

        std::string line, section;

        while (std::getline(file, line)) {
            /* Strip comment */
            auto pos = line.find('#');
            if (pos != std::string::npos) line = line.substr(0, pos);

            /* Skip blank lines */
            if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;

            /* Check indentation: section header vs key-value */
            bool indented = (line[0] == ' ' || line[0] == '\t');
            auto colon = line.find(':');
            if (colon == std::string::npos) continue;

            std::string key = line.substr(0, colon);
            key = trim(key);

            std::string val = line.substr(colon + 1);
            val = trim(val);
            val = strip_quotes(val);

            if (!indented) {
                if (val.empty()) {
                    /* Section header, e.g. "ecc:" */
                    section = key;
                } else {
                    config[key] = val;
                }
            } else {
                config[section + "." + key] = val;
            }
        }
        return config;
    }

private:
    static std::string trim(const std::string &s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    static std::string strip_quotes(const std::string &s) {
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
            return s.substr(1, s.size() - 2);
        return s;
    }
};

#endif /* CONFIG_PARSER_H */
