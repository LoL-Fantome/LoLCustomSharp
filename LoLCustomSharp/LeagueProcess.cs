using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace LoLCustomSharp
{
    public class LeagueProcess : IDisposable
    {
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint SYNCHRONIZE = 0x00100000;

        private const uint INFINITE = 0xFFFFFFFF;

        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_READWRITE = 0x04;

        private const uint MEM_COMMIT = 0x00001000;
        private const uint MEM_RESERVE = 0x00002000;

        [DllImport("kernel32.dll")]
        private static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(int hProcess);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(int hProcess, uint lpBaseAddress, byte[] lpBuffer, int dwSize, out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(int hProcess, uint lpBaseAddress, byte[] lpBuffer, int dwSize, out uint lpNumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtWriteVirtualMemory(int hProcess, uint lpBaseAddress, byte[] lpBuffer, int dwSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(int hProcess, uint lpAddress, int dwSize, uint flNewProtect, out int lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern uint VirtualAllocEx(int hProcess, uint lpBaseAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern int WaitForSingleObject(int hProcess, uint miliseconds);

        private int hProcess;
        private uint _moduleBase;
        private int _moduleSize;

        internal uint Base => this._moduleBase;

        public LeagueProcess(Process process)
        {
            this.hProcess = 0;
            this._moduleBase = (uint)process.MainModule.BaseAddress;
            this._moduleSize = process.MainModule.ModuleMemorySize;

            uint pid = (uint)process.Id;
            this.hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false, pid);
        }

        ~LeagueProcess()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (this.hProcess != 0 && this.hProcess != -1)
            {
                CloseHandle(this.hProcess);
                this.hProcess = 0;
            }
        }
        public void Dispose()
        {
            Dispose(true);
        }

        internal byte[] Dump()
        {
            byte[] data = new byte[80 * 1024 * 1024];
            byte[] buffer = new byte[0x1000];
            uint baseAddress = this.Base;
            for (int i = 0; i < data.Length; i += buffer.Length)
            {
                ReadProcessMemory(this.hProcess, baseAddress + (uint)i, buffer, buffer.Length, out uint _);
                Buffer.BlockCopy(buffer, 0, data, i, buffer.Length);
            }
            return data;
        }

        internal byte[] ReadMemory(uint address, int size)
        {
            byte[] buffer = new byte[size];
            if (!ReadProcessMemory(this.hProcess, address, buffer, size, out uint _))
            {
                throw new IOException("Failed to read memory!");
            }
            return buffer;
        }
        internal void WriteMemory(uint address, byte[] buffer)
        {
            if (NtWriteVirtualMemory(this.hProcess, address, buffer, buffer.Length, out uint _) != 0)
            {
                throw new IOException("Failed to write memory");
            }
        }
        internal void MarkMemoryExecutable(uint address, int size)
        {
            if (!VirtualProtectEx(this.hProcess, address, size, PAGE_EXECUTE, out int _))
            {
                throw new IOException("Failed to mark region as executable");
            }
        }
        internal uint AllocateMemory(int size)
        {
            uint ptr = VirtualAllocEx(this.hProcess, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (ptr == 0)
            {
                throw new IOException("Failed to allocate memory");
            }
            return ptr;
        }

        public void WaitForExit()
        {
            WaitForSingleObject(this.hProcess, INFINITE);
        }
        internal uint WaitPointerNonZero(uint address)
        {
            byte[] buffer = new byte[4];
            do
            {
                Thread.Sleep(1);
                ReadProcessMemory(this.hProcess, address, buffer, 4, out uint _); //This can fail sometimes
            } while (buffer[0] == 0 && buffer[1] == 0 && buffer[2] == 0 && buffer[3] == 0);
            return BitConverter.ToUInt32(buffer, 0);
        }

        internal uint Allocate<T>() where T : struct
        {
            return AllocateMemory(Marshal.SizeOf(typeof(T)));
        }
        internal T Read<T>(uint address) where T : struct
        {
            T structure = new T();

            int structSize = Marshal.SizeOf(structure);
            byte[] structBuffer = ReadMemory(address, structSize);
            IntPtr structPointer = Marshal.AllocHGlobal(structSize);

            Marshal.Copy(structBuffer, 0, structPointer, structSize);

            structure = (T)Marshal.PtrToStructure(structPointer, structure.GetType());
            Marshal.FreeHGlobal(structPointer);

            return structure;
        }
        internal void Write<T>(uint address, T value) where T : struct
        {
            int structSize = Marshal.SizeOf(value);
            byte[] structBuffer = new byte[structSize];

            IntPtr structPointer = Marshal.AllocHGlobal(structSize);
            Marshal.StructureToPtr(value, structPointer, true);
            Marshal.Copy(structPointer, structBuffer, 0, structSize);
            Marshal.FreeHGlobal(structPointer);

            WriteMemory(address, structBuffer);
        }

        internal static uint ExtractChecksum(byte[] data)
        {
            ushort magic = BitConverter.ToUInt16(data, 0);
            if (magic != 0x5A4D)
            {
                throw new IOException("Not a PE header!");
            }
            int nt = BitConverter.ToInt32(data, 60);
            if ((nt + 248) > data.Length)
            {
                throw new IOException("NT header offset out of range!");
            }
            uint signature = BitConverter.ToUInt32(data, nt);
            if (signature != 0x00004550)
            {
                throw new IOException("Not a NT header!");
            }
            uint checksum = BitConverter.ToUInt32(data, nt + 24 + 64);
            return checksum;
        }
    }
}
