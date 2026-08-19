// Json.cpp — JSON 数组文件写器实现

#include "Json.h"
#include "Str.h"

#include <cstring>

namespace das {

bool JsonArrayFile::Open(const std::wstring& p)
{
    if (h != INVALID_HANDLE_VALUE) return false;
    path = p;
    h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    firstEvent = true;
    const char* header = "[\n";
    DWORD written = 0;
    WriteFile(h, header, (DWORD)strlen(header), &written, nullptr);
    return true;
}

void JsonArrayFile::Write(const std::string& objectJson)
{
    if (h == INVALID_HANDLE_VALUE) return;
    std::string out = (firstEvent ? "" : ",\n") + objectJson;
    firstEvent = false;
    DWORD written = 0;
    WriteFile(h, out.data(), (DWORD)out.size(), &written, nullptr);
}

void JsonArrayFile::Close()
{
    if (h == INVALID_HANDLE_VALUE) return;
    const char* footer = "\n]\n";
    DWORD written = 0;
    WriteFile(h, footer, (DWORD)strlen(footer), &written, nullptr);
    CloseHandle(h);
    h = INVALID_HANDLE_VALUE;
}

} // namespace das