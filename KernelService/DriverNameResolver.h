#pragma once

// 不在这里 include ntifs.h,避免和 ntddk.h 的 wdm.h 冲突
// 调用方 .c 文件必须在 include 任何其他头文件之前先 include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>

// 驱动对象名解析器 (Driver Name Resolver)
//
// 功能:
//   给定驱动的 ImageBase，即从 PsLoadedModuleList 拿到的基址,
//   在内核对象管理器中查找对应的 DRIVER_OBJECT,通过比对
//   DriverObject->DriverStart == ImageBase,找到该驱动真实
//   的对象名，即 \Driver\<Name> 中的 <Name>，通常等于服务名。
//
// 为什么要做这一步:
//   应用层从 PsLoadedModuleList 拿到的是文件名，例如 "OpenArkDrv64.sys",
//   但驱动在对象管理器里的名字是基于服务名创建的，例如 "OpenArkDrv"。
//   简单去掉 .sys 后缀是错的,必须通过 ImageBase 反查。
//
// 实现:
//   1. ZwOpenDirectoryObject 打开 \Driver 目录
//   2. ZwQueryDirectoryObject 循环遍历目录中所有对象
//   3. 对每个对象名,ObReferenceObjectByName 拿 PDRIVER_OBJECT
//   4. 比对 DriverObject->DriverStart == ImageBase
//   5. 匹配则返回对象名;不匹配 ObDereferenceObject 继续下一个
//   6. \Driver 找不到再扫 \FileSystem
//
// 注意:
//   - 本模块无状态,Init/Unload 为空
//   - 遍历过程 best-effort,不加锁，对象目录可能变化，但 ImageBase 不变

// 在给定目录中按 ImageBase 查找驱动对象名，目录为 \Driver 或 \FileSystem
// 成功返回 STATUS_SUCCESS,OutName 填入驱动对象名，不含 \Driver\ 前缀
// 失败返回 STATUS_NOT_FOUND 或其他错误码
NTSTATUS FindDriverNameByImageBase(
	_In_ PCWSTR DirName,            // 如 L"\\Driver" / L"\\FileSystem"
	_In_ PVOID TargetImageBase,     // 目标驱动基址
	_Out_writes_z_(OutNameChars) PWSTR OutName,
	_In_ ULONG OutNameChars);

// 同时扫 \Driver 和 \FileSystem,按 ImageBase 找驱动对象名
// 优先扫 \Driver，绝大多数驱动都在此；找不到再扫 \FileSystem
NTSTATUS FindDriverObjectNameByImageBase(
	_In_ PVOID TargetImageBase,
	_Out_writes_z_(OutNameChars) PWSTR OutName,
	_In_ ULONG OutNameChars);

// 初始化 / 卸载，本模块无状态
NTSTATUS DriverNameResolverInit(VOID);
VOID     DriverNameResolverUnload(VOID);
