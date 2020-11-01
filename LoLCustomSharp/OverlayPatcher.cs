using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading;

namespace LoLCustomSharp
{
    public class OverlayPatcher
    {
        private const string CONFIG_FILE = "lolcustomskin-sharp.bin";
        private const uint VERSION = 4;

        // Please, please for the love of god do not attempt to use File/Build version of .exe
        // Those are not reliable 
        // Please!!
        private uint Checksum { get; set; }
        private uint CreateFileARefOffset { get; set; }
        private uint CreateFileAOffset { get; set; }
        private uint ReturnAddressOffset { get; set; }
        private uint FreePointerOffset { get; set; }
        private uint FreeFunctionOffset { get; set; }


        public string Prefix { get; set; }

        // TODO: actually normalize the path ?
        public string PrefixNormalized => Prefix.EndsWith("/") || Prefix.EndsWith("\\") ? Prefix : Prefix + "/";

        private string _configPath;

        private Thread _thread;

        private static readonly SigScanner PAT_CreateFileA_CALL = SigScanner.Pattern("6A 03 68 00 00 00 C0 68 ?? ?? ?? ?? FF 15", 14);

        private static readonly SigScanner PAT_ReturnAddress = SigScanner.Pattern("56 8B CF E8 ?? ?? ?? ?? 84 C0 75 12", 8);

        private static readonly SigScanner PAT_FreePointerOffset = SigScanner.Pattern("A1 ?? ?? ?? ?? 85 C0 74 09 3D ?? ?? ?? ?? 74 02 FF E0 FF 74 24 04 E8", 1);

        private static readonly int OFF_FreeFunctionOffset = 17;

        public delegate void PatcherMessageCallback(string message);
        public delegate void PatcherErrorCallback(Exception exception);

        private PatcherMessageCallback _messageCallback;
        private PatcherErrorCallback _errorCallback;

        public OverlayPatcher(string configLocation = CONFIG_FILE)
        {
            _configPath = configLocation;
            if (File.Exists(configLocation))
            {
                ReadConfig();
            }
        }

        public void Start(string overlayFolder, PatcherMessageCallback messageCallback, PatcherErrorCallback errorCallback)
        {
            this.Prefix = overlayFolder;
            this._messageCallback = messageCallback;
            this._errorCallback = errorCallback;

            this._thread = new Thread(delegate ()
            {
                try
                {
                    messageCallback?.Invoke("Starting patcher");
                    this.PrintConfig();

                    while (true)
                    {
                        foreach (Process process in Process.GetProcessesByName("League of Legends"))
                        {
                            if (!IsLeague(process))
                            {
                                break;
                            }

                            messageCallback?.Invoke("Found League process");

                            bool offsetsUpdated = false;
                            using (LeagueProcess league = new LeagueProcess(process))
                            {
                                bool needsUpdate = NeedsUpdate(league);

                                if (process.WaitForInputIdle())
                                {
                                    if(needsUpdate)
                                    {
                                        messageCallback?.Invoke("Updating offsets");

                                        UpdateOffsets(league);
                                        offsetsUpdated = true;
                                        messageCallback?.Invoke("Offsets updated");
                                    }

                                    messageCallback?.Invoke("Patching League...");
                                    Patch(league);
                                }
                                else
                                {
                                    messageCallback?.Invoke("Failed to wait for idle input from process");
                                }
                            }

                            if (offsetsUpdated)
                            {
                                WriteConfig(_configPath);
                            }

                            process.WaitForExit();
                            break;
                        }

                        Thread.Sleep(1000);
                    }
                }
                catch(Exception exception)
                {
                    errorCallback?.Invoke(exception);
                }
            });

            this._thread.IsBackground = true; //Thread needs to be background so it closes when the parent process dies
            this._thread.Start();
        }
        public void Stop()
        {
            this._thread.Abort();
        }

        public void Join()
        {
            this._thread.Join();
        }

        public static bool IsLeague(Process league)
        {
            if (league.ProcessName == "League of Legends")
            {
                return league.MainModule.ModuleName == "League of Legends.exe";
            }
            return false;
        }

        public bool NeedsUpdate(LeagueProcess league)
        {
            byte[] dataPE = league.ReadMemory(league.Base, 0x1000);
            uint actualChecksum = LeagueProcess.ExtractChecksum(dataPE);
            return actualChecksum != this.Checksum || this.CreateFileARefOffset == 0 || this.CreateFileAOffset == 0 || this.ReturnAddressOffset == 0 || this.FreePointerOffset == 0 || this.FreeFunctionOffset == 0;
        }

        private void PrintConfig()
        {
            this._messageCallback?.Invoke($"Checksum: 0x{Checksum:X08}");
            this._messageCallback?.Invoke($"CreateFileARefOffset: 0x{CreateFileARefOffset:X08}");
            this._messageCallback?.Invoke($"CreateFileAOffset: 0x{CreateFileAOffset:X08}");
            this._messageCallback?.Invoke($"ReturnAddressOffset: 0x{ReturnAddressOffset:X08}");
            this._messageCallback?.Invoke($"FreePointerOffset: 0x{FreePointerOffset:X08}");
            this._messageCallback?.Invoke($"FreeFunctionOffset: 0x{FreeFunctionOffset:X08}");
        }

        private void ReadConfig(string configLocation = CONFIG_FILE)
        {
            using (BinaryReader br = new BinaryReader(File.OpenRead(configLocation)))
            {
                uint version = br.ReadUInt32();
                if (version != VERSION)
                {
                    //Don't need to read rest of config, let the patcher update itself
                    return;
                }

                this.Checksum = br.ReadUInt32();
                this.CreateFileARefOffset = br.ReadUInt32();
                this.CreateFileAOffset = br.ReadUInt32();
                this.ReturnAddressOffset = br.ReadUInt32();
                this.FreePointerOffset = br.ReadUInt32();
                this.FreeFunctionOffset = br.ReadUInt32();
            }
        }

        private void WriteConfig(string configLocation = CONFIG_FILE)
        {
            using (BinaryWriter bw = new BinaryWriter(File.Create(configLocation)))
            {
                bw.Write(VERSION);
                bw.Write(this.Checksum);
                bw.Write(this.CreateFileARefOffset);
                bw.Write(this.CreateFileAOffset);
                bw.Write(this.ReturnAddressOffset);
                bw.Write(this.FreePointerOffset);
                bw.Write(this.FreeFunctionOffset);
            }
        }

        public void UpdateOffsets(LeagueProcess league)
        {
            byte[] data = league.Dump();
            uint checksum = LeagueProcess.ExtractChecksum(data);

            int createFileARefOffset = PAT_CreateFileA_CALL.Find(data);
            if (createFileARefOffset == -1)
            {
                throw new IOException("Failed to find CreateFileA reference index!");
            }
            int createFileAOffset = BitConverter.ToInt32(data, createFileARefOffset) - (int)league.Base;

            int returnAddressOffset = PAT_ReturnAddress.Find(data);
            if (returnAddressOffset == -1)
            {
                throw new IOException("Failed to find ReturnAddress!");
            }

            int freePointerOffsetIndex = PAT_FreePointerOffset.Find(data);
            if (freePointerOffsetIndex == -1)
            {
                throw new IOException("Failed to find FreePointer!");
            }
            int freePointerOffset = BitConverter.ToInt32(data, freePointerOffsetIndex) - (int)league.Base;
            int freeFunctionOffset = freePointerOffsetIndex + OFF_FreeFunctionOffset;

            this.Checksum = checksum;
            this.CreateFileARefOffset = (uint)createFileARefOffset;
            this.CreateFileAOffset = (uint)createFileAOffset;
            this.ReturnAddressOffset = (uint)returnAddressOffset;
            this.FreePointerOffset = (uint)freePointerOffset;
            this.FreeFunctionOffset = (uint)freeFunctionOffset;
            this.PrintConfig();
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct ImportTrampoline
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            byte[] Data;

            public ImportTrampoline(uint address)
            {
                Data = new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, };
                byte[] addressData = BitConverter.GetBytes(address);
                Array.Copy(addressData, 0, Data, 1, 4);
                Array.Resize(ref Data, 64);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct Payload
        {
            uint OriginalCreateFileAPointer;
            uint PrefixCreateFileAPointer;
            uint OriginalFreePointer;
            uint FindReturnAddress;
            uint HookReturnAddress;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
            byte[] HookCreateFileA;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
            byte[] HookFree;

            [MarshalAs(UnmanagedType.Struct)]
            ImportTrampoline OriginalCreateFileATrampoline;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            string PrefixCreateFileA;

            public uint HookCreateFileAPointer(uint payloadPointer)
            {
                return payloadPointer + (uint)Marshal.OffsetOf<Payload>(nameof(HookCreateFileA));
            }

            public uint HookFreePointer(uint payloadPointer)
            {
                return payloadPointer + (uint)Marshal.OffsetOf<Payload>(nameof(HookFree));
            }

            public Payload(uint payloadPointer, ImportTrampoline originalCreateFileATrampoline, string prefix, uint originalFreePointer, uint findReturnAddress)
            {
                OriginalCreateFileATrampoline = originalCreateFileATrampoline;
                OriginalCreateFileAPointer = payloadPointer + (uint)Marshal.OffsetOf<Payload>(nameof(OriginalCreateFileATrampoline));

                PrefixCreateFileA = prefix;
                PrefixCreateFileAPointer = payloadPointer + (uint)Marshal.OffsetOf<Payload>(nameof(PrefixCreateFileA));

                OriginalFreePointer = originalFreePointer;
                FindReturnAddress = findReturnAddress;
                HookReturnAddress = findReturnAddress + 0x16;

                HookCreateFileA = new byte[]
                {
                    0xc8, 0x00, 0x10, 0x00, 0x53, 0x57, 0x56, 0xe8,
                    0x00, 0x00, 0x00, 0x00, 0x5b, 0x81, 0xe3, 0x00,
                    0xf0, 0xff, 0xff, 0x8d, 0xbd, 0x00, 0xf0, 0xff,
                    0xff, 0x8b, 0x73, 0x04, 0xac, 0xaa, 0x84, 0xc0,
                    0x75, 0xfa, 0x4f, 0x8b, 0x75, 0x08, 0xac, 0xaa,
                    0x84, 0xc0, 0x75, 0xfa, 0x8d, 0x85, 0x00, 0xf0,
                    0xff, 0xff, 0xff, 0x75, 0x20, 0xff, 0x75, 0x1c,
                    0xff, 0x75, 0x18, 0xff, 0x75, 0x14, 0xff, 0x75,
                    0x10, 0xff, 0x75, 0x0c, 0x50, 0xff, 0x13, 0x83,
                    0xf8, 0xff, 0x75, 0x17, 0xff, 0x75, 0x20, 0xff,
                    0x75, 0x1c, 0xff, 0x75, 0x18, 0xff, 0x75, 0x14,
                    0xff, 0x75, 0x10, 0xff, 0x75, 0x0c, 0xff, 0x75,
                    0x08, 0xff, 0x13, 0x5e, 0x5f, 0x5b, 0xc9, 0xc2,
                    0x1c, 0x00
                };
                Array.Resize(ref HookCreateFileA, 128);
                HookFree = new byte[]
                {
                    0xc8, 0x00, 0x00, 0x00, 0x53, 0x56, 0xe8, 0x00,
                    0x00, 0x00, 0x00, 0x5b, 0x81, 0xe3, 0x00, 0xf0,
                    0xff, 0xff, 0x8b, 0x73, 0x0c, 0x89, 0xe8, 0x05,
                    0x80, 0x01, 0x00, 0x00, 0x83, 0xe8, 0x04, 0x39,
                    0xe8, 0x74, 0x09, 0x3b, 0x30, 0x75, 0xf5, 0x8b,
                    0x73, 0x10, 0x89, 0x30, 0x8b, 0x43, 0x08, 0x5e,
                    0x5b, 0xc9, 0xff, 0xe0
                };
                Array.Resize(ref HookFree, 128);
            }
        }

        public void Patch(LeagueProcess league)
        {
            uint createFileARefPointer = this.CreateFileARefOffset + league.Base;
            uint createFileAPointer = this.CreateFileAOffset + league.Base;
            uint returnAddress = this.ReturnAddressOffset + league.Base;
            uint freePointer = this.FreePointerOffset + league.Base;
            uint freeFunction = this.FreeFunctionOffset + league.Base;

            // wait untill CreateFileA has been used and unpacmaned
            league.WaitPointerEquals(createFileARefPointer, createFileAPointer);
            // wait until free pointer has been set
            league.WaitPointerNonZero(freePointer);

            // read trampoline shellcode that league creates for CreateFileA
            uint createFileATrampolinePointer = league.Read<uint>(createFileAPointer);
            ImportTrampoline originalCreateFileATrampoline = league.Read<ImportTrampoline>(createFileATrampolinePointer);

            uint payloadPointer = league.AllocateMemory(0x1000);
            Payload payload = new Payload(
                payloadPointer: payloadPointer,
                originalCreateFileATrampoline: originalCreateFileATrampoline,
                prefix: PrefixNormalized,
                originalFreePointer: freeFunction,
                findReturnAddress: returnAddress
                );
            uint hookCreateFileAPointer = payload.HookCreateFileAPointer(payloadPointer);
            uint hookFreePointer = payload.HookFreePointer(payloadPointer);
            ImportTrampoline hookCreateFileATrampoline = new ImportTrampoline(hookCreateFileAPointer);

            league.Write(payloadPointer, payload);
            league.MarkMemoryExecutable(payloadPointer, 0x1000);

            // write hooks
            league.Write(freePointer, hookFreePointer);
            league.Write(createFileATrampolinePointer, hookCreateFileATrampoline);
        }
    }
}
