#pragma once

#include <algorithm>
#include <format>
#include <filesystem>
#include <fstream>
#include <map>

namespace fs = std::filesystem;

#define ID_SIZE 10
#define BUFSIZE 32

struct Signature {
    char name[BUFSIZE];
    uint16_t signatureLength;
    std::vector<uint8_t> signature;
    uint32_t offsetBegin;
    uint32_t offsetEnd;
};

class FileSystemScanner {
public:
    FileSystemScanner(const std::string&);
    std::vector<Signature> getBase() {
        return base; 
    };
    bool scanFile(std::string const&, std::vector<std::string>&);
    bool scanFolder(std::string const&, std::map<std::string, std::vector<std::string>>&);
private:
    std::vector<Signature> base;//поменять на map
    bool loadSignatureFromFile(std::ifstream&, Signature&);
    int getSizeOfFile(std::ifstream&);
    bool isExecutableFile(const fs::directory_entry&);
    bool checkFolder(std::string const&);
};
