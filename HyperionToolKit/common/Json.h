// Json.h — 统一 JSON 序列化
//
// 原两套手拼 JSON (JsonLogger.cpp 写文件, JsonWriter.cpp printf 打 stdout)
// 收拢成:
//   JsonEscape / JsonEscapeW / BytesToHex — 字符串/hex 转义 (实现在 Str.h)
//   JsonArrayFile — 追加式 JSON 数组文件 (原 JsonLogger)
//   JsonBuilder   — 进程内构建 JSON 对象 (供安全采集模式复用)
//
// 所有 JSON 一律 UTF-8 编码输出。

#pragma once

#include <string>
#include <windows.h>
#include "Str.h"

namespace das {

// ═══════════════════════════════════════════════════════════════════════
//  JSON 数组文件写器 (原 JsonLogger): 数组开头 "[\n" → 逐条事件 → "]\n"
//  直接写文件不缓存, 每条对象是调用方拼好的完整 JSON 文本。
// ═══════════════════════════════════════════════════════════════════════
class JsonArrayFile
{
public:
    // 创建/覆盖 path, 写入数组开头 "[\n"; 失败返回 false
    bool Open(const std::wstring& path);

    // 追加一个对象 (自动管理前导逗号), 不校验合法性
    void Write(const std::string& objectJson);

    // 写入数组结尾 "]\n" 并关闭文件
    void Close();

    bool IsOpen() const { return h != INVALID_HANDLE_VALUE; }
    const std::wstring& Path() const { return path; }

private:
    HANDLE h = INVALID_HANDLE_VALUE;
    std::wstring path;
    bool firstEvent = true;
};

// ═══════════════════════════════════════════════════════════════════════
//  进程内 JSON 对象构建器 (供安全采集模式 / 单对象输出使用)
//  用法: JsonBuilder o; o.Set("pid", 123); o.Set("name", "...");
//        std::string s = o.ToString();
//  自动处理引号转义与逗号。
// ═══════════════════════════════════════════════════════════════════════
class JsonBuilder
{
public:
    // 写入 key: value (value 已自行做好转义/序列化)
    void Field(const std::string& key, const std::string& rawValueJson)
    {
        if (fields > 0) body += ",";
        body += "\"" + key + "\":" + rawValueJson;
        fields++;
    }

    void Field(const std::string& key, long long value) { Field(key, std::to_string(value)); }
    void Field(const std::string& key, unsigned long long value) { Field(key, std::to_string(value)); }
    void Field(const std::string& key, int value) { Field(key, std::to_string(value)); }
    void Field(const std::string& key, unsigned long value) { Field(key, std::to_string(value)); }
    void Field(const std::string& key, bool value) { Field(key, value ? "true" : "false"); }
    // 字符串字段 (自动转义, 输入为 UTF-8)
    void FieldStr(const std::string& key, const std::string& utf8Value)
    {
        Field(key, "\"" + JsonEscape(utf8Value) + "\"");
    }
    // 宽字符串字段 (自动转 UTF-8 + 转义)
    void FieldW(const std::string& key, const std::wstring& value)
    {
        Field(key, "\"" + JsonEscapeW(value) + "\"");
    }

    std::string ToString() const { return "{" + body + "}"; }

private:
    std::string body;
    int fields = 0;
};

} // namespace das