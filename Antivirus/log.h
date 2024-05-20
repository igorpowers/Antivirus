#pragma once

#include <string>
#include <fstream>

static std::ofstream errorLog;
void WriteLog(const std::string&);