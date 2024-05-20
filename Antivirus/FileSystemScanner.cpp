#include "FileSystemScanner.h"
#include "log.h"
#include <unordered_map>

FileSystemScanner::FileSystemScanner(const std::string& namefile) {
    std::ifstream tempBase(namefile, std::ios::binary);
    std::vector<uint8_t> expected = { 'F', 'E', 'D', 'O', 'R', 'O', 'V' };
    std::vector<uint8_t> current(expected.size());
    int64_t cPos = tempBase.tellg();
    //WriteLog(std::format("before {}", cPos));
    tempBase.read(reinterpret_cast<char*>(current.data()), current.size());
    /*cPos = tempBase.tellg();
    WriteLog(std::format("after {}", cPos));
    WriteLog(std::format("Expected - {}", expected.size()));
    for (auto item : expected) {
        WriteLog(std::format("{}", item));
    }
    WriteLog(std::format("Current - {}", current.size()));
    for (auto item : current) {
        WriteLog(std::format("{}", item));
    }*/
    if (current != expected) 
        WriteLog("Base prefix is not valid");

    while (!tempBase.eof()) {
        Signature sig;
        if (!loadSignatureFromFile(tempBase, sig))
            break;
        base.push_back(sig);
    }
    tempBase.close();
}

bool FileSystemScanner::isExecutableFile(const fs::directory_entry& entry) {
    std::string extension = entry.path().extension().string();
    if (extension == ".exe" || extension == ".bat") {
        return true;
    }
    else {
        WriteLog("Файл не является исполняемым");
    }
    return false;
}

bool FileSystemScanner::loadSignatureFromFile(std::ifstream& file, Signature& sig) {

    file.read(reinterpret_cast<char*>(&sig.name), sizeof(sig.name));
    if (!file) {
        if(!file.eof())
            WriteLog("Error reading signature name from file");
        return false;
    }

    file.read(reinterpret_cast<char*>(&sig.signatureLength), sizeof(sig.signatureLength));
    if (!file) {
        WriteLog("Error reading signature length from file");
        return false;
    }

    sig.signature.resize(sig.signatureLength);
    file.read(reinterpret_cast<char*>(sig.signature.data()), sig.signatureLength);
    if (!file) {
        WriteLog("Error reading signature data from file");
        return false;
    }

    file.read(reinterpret_cast<char*>(&sig.offsetBegin), sizeof(sig.offsetBegin));
    if (!file) {
        WriteLog("Error reading signature offset begin from file");
        return false;
    }

    file.read(reinterpret_cast<char*>(&sig.offsetEnd), sizeof(sig.offsetEnd));
    if (!file) {
        WriteLog("Error reading signature offset end from file");
        return false;
    }
    return true;
}


bool FileSystemScanner::scanFile(std::string const& filename, std::vector<std::string>& whichSignatureInside)
{
    WriteLog("Зашли в scanFile");
    std::ifstream checkingFile(filename, std::ios::binary);
    std::vector<uint8_t> dataByOffset;
    bool exist = false;
    for (auto signatureObject : base) {
        checkingFile.seekg(signatureObject.offsetBegin, std::ios::beg);
        checkingFile.read((char*)dataByOffset.data(), getSizeOfFile(checkingFile) - signatureObject.offsetEnd);
        auto it = std::search(dataByOffset.begin(), dataByOffset.end(),
            signatureObject.signature.begin(), signatureObject.signature.end());
        if (it != signatureObject.signature.end()) {
            exist = true;
            whichSignatureInside.push_back(signatureObject.name);
        }
    }
    return exist;
}

bool FileSystemScanner::scanFolder(std::string const& foldername, std::map<std::string, std::vector<std::string>>& result) {
    if (!checkFolder(foldername)) {
        WriteLog("Папка не существует или неверный путь");
        return false;
    }
    bool ret = false;
    for (const auto& file : fs::directory_iterator(foldername)) {
        if (!isExecutableFile(file)) {
            continue;
        }
        std::vector<std::string> temp;
        if (scanFile(file.path().string(), temp)) {
            ret = true;
            result[file.path().string()] = temp;
        }
    }
    return ret;
}

int FileSystemScanner::getSizeOfFile(std::ifstream& file) {
    size_t sizeBefore = file.tellg();
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(sizeBefore, std::ios::beg);
    return size;
}

bool FileSystemScanner::checkFolder(std::string const& foldername) {
    return fs::exists(foldername) && fs::is_directory(foldername);
}
