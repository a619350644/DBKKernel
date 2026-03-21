#pragma once

// ================================================================
// HvMemoryClient.h
//
// Include this in your modified CE to use the hypervisor memory R/W.
// Replace CE's dbk64 read/write calls with HvReadMemory/HvWriteMemory.
//
// Usage:
//   HvClient client;
//   if (client.Connect()) {
//       int value = 0;
//       client.ReadMemory(targetPid, 0x7FF612340000, &value, sizeof(value));
//       value = 999;
//       client.WriteMemory(targetPid, 0x7FF612340000, &value, sizeof(value));
//   }
// ================================================================

#include <windows.h>

#define IOCTL_HV_READ_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_WRITE_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PROTECT_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _HV_MEMORY_REQUEST {
    ULONG64 TargetPid;
    ULONG64 Address;
    ULONG64 Size;
    ULONG64 BufferAddress;  // unused in current implementation
} HV_MEMORY_REQUEST;

typedef struct _PROTECT_INFO {
    ULONG64 Pid;
    WCHAR ProcessName[260];
} PROTECT_INFO;
#pragma pack(pop)

class HvClient {
    HANDLE hDevice;

public:
    HvClient() : hDevice(INVALID_HANDLE_VALUE) {}

    ~HvClient() {
        Disconnect();
    }

    bool Connect(const wchar_t* deviceName = L"\\\\.\\SvmDebug") {
        hDevice = CreateFileW(
            deviceName,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        return (hDevice != INVALID_HANDLE_VALUE);
    }

    void Disconnect() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    bool IsConnected() const {
        return (hDevice != INVALID_HANDLE_VALUE);
    }

    // Set the target PID to hide (process hiding + DKOM)
    bool SetProtectedProcess(DWORD pid, const wchar_t* processName) {
        PROTECT_INFO info = {};
        info.Pid = pid;
        wcscpy_s(info.ProcessName, processName);

        DWORD ret = 0;
        return DeviceIoControl(
            hDevice, IOCTL_SET_PROTECT_INFO,
            &info, sizeof(info),
            NULL, 0, &ret, NULL) != FALSE;
    }

    // Read memory from target process via hypervisor
    // Completely invisible to ACE - no kernel API called
    bool ReadMemory(DWORD targetPid, ULONG64 address, void* buffer, size_t size) {
        if (!IsConnected() || !buffer || size == 0) return false;

        // Input: HV_MEMORY_REQUEST header
        HV_MEMORY_REQUEST req = {};
        req.TargetPid = targetPid;
        req.Address = address;
        req.Size = size;

        // Output buffer receives the read data
        // For METHOD_BUFFERED, input and output share the same buffer
        // We need a buffer large enough for both
        size_t totalSize = (sizeof(HV_MEMORY_REQUEST) > size) ? sizeof(HV_MEMORY_REQUEST) : size;
        BYTE* ioBuf = new BYTE[totalSize + sizeof(HV_MEMORY_REQUEST)];
        if (!ioBuf) return false;

        memcpy(ioBuf, &req, sizeof(req));

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_HV_READ_MEMORY,
            ioBuf, sizeof(HV_MEMORY_REQUEST),  // input: just the header
            ioBuf, (DWORD)size,                 // output: read data
            &bytesReturned, NULL);

        if (ok && bytesReturned > 0) {
            memcpy(buffer, ioBuf, bytesReturned);
        }

        delete[] ioBuf;
        return (ok && bytesReturned == size);
    }

    // Write memory to target process via hypervisor
    bool WriteMemory(DWORD targetPid, ULONG64 address, const void* buffer, size_t size) {
        if (!IsConnected() || !buffer || size == 0) return false;

        // Input layout: [HV_MEMORY_REQUEST][data to write]
        size_t totalInput = sizeof(HV_MEMORY_REQUEST) + size;
        BYTE* ioBuf = new BYTE[totalInput];
        if (!ioBuf) return false;

        HV_MEMORY_REQUEST* pReq = (HV_MEMORY_REQUEST*)ioBuf;
        pReq->TargetPid = targetPid;
        pReq->Address = address;
        pReq->Size = size;
        pReq->BufferAddress = 0;

        memcpy(ioBuf + sizeof(HV_MEMORY_REQUEST), buffer, size);

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_HV_WRITE_MEMORY,
            ioBuf, (DWORD)totalInput,
            NULL, 0,
            &bytesReturned, NULL);

        delete[] ioBuf;
        return (ok != FALSE);
    }

    // Template helpers for convenience
    template<typename T>
    T Read(DWORD pid, ULONG64 addr) {
        T val = {};
        ReadMemory(pid, addr, &val, sizeof(T));
        return val;
    }

    template<typename T>
    bool Write(DWORD pid, ULONG64 addr, const T& val) {
        return WriteMemory(pid, addr, &val, sizeof(T));
    }
};
