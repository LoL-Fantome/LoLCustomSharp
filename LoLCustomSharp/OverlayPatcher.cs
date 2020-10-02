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
        public const string CONFIG_FILE = "lolcustomskin-sharp.bin";
        public const uint VERSION = 2;

        // Please, please for the love of god do not attempt to use File/Build version of .exe
        // Those are not reliable 
        // Please!!
        private uint Checksum { get; set; }
        private uint RSAMethOffset { get; set; }
        private uint CreateFileARefOffset { get; set; }
        private uint CreateFileAOffset { get; set; }
        public string Prefix { get; set; }

        private byte[] _prefixBytes
        {
            get
            {
                string str = this.Prefix;
                if (string.IsNullOrEmpty(str))
                {
                    return new byte[256];
                }
                if (!str.EndsWith("/") && !str.EndsWith("\\"))
                {
                    str += "/";
                }
                byte[] bytes = Encoding.ASCII.GetBytes(str);
                byte[] buffer = new byte[256];
                Buffer.BlockCopy(bytes, 0, buffer, 0, bytes.Length);
                return buffer;
            }
        }
        private Thread _thread;

        private static readonly SigScanner PAT_CreateFileA_CALL = SigScanner.Pattern("6A 03 68 00 00 00 C0 68 ?? ?? ?? ?? FF 15", 14);
        private static readonly SigScanner PAT_RSA_METH_NAME = SigScanner.ExactString("OpenSSL PKCS#1 RSA");

        public delegate void PatcherMessageCallback(string message);
        public delegate void PatcherErrorCallback(Exception exception);

        private PatcherMessageCallback _messageCallback;
        private PatcherErrorCallback _errorCallback;

        public OverlayPatcher(string configLocation = CONFIG_FILE)
        {
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
                                WriteConfig();
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

        public void Patch(LeagueProcess league)
        {
            uint payloadPointer = league.AllocateMemory(0x1000);
            uint rsaVerifyPointer = this.RSAMethOffset + league.Base + 48;
            uint createFileARefPointer = this.CreateFileARefOffset + league.Base;
            uint createFileAPointer = this.CreateFileAOffset + league.Base;

            // wait untill CreateFileA has been used and unpacmaned
            league.WaitPointerEquals(createFileARefPointer, createFileAPointer);

            // read trampoline shellcode that league creates for CreateFileA
            uint createFileATrampolinePointer = league.Read<uint>(createFileAPointer);
            byte[] originalTrampoline = league.ReadMemory(createFileATrampolinePointer, 64);

            // build our own trampoline
            List<byte> modifiedTrampoline = new List<byte>();
            modifiedTrampoline.Add(0xB8); // mov eax, 
            modifiedTrampoline.AddRange(BitConverter.GetBytes(payloadPointer + 8));
            modifiedTrampoline.AddRange(new byte[] { 0xff, 0xE0 }); // jmp eax

            // build payload
            league.WriteMemory(payloadPointer, new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, });
            league.WriteMemory(payloadPointer + 0x8, new byte[]
            {
                0xC8, 0x00, 0x10, 0x00, 0x53, 0x57, 0x56, 0xE8,
                0x00, 0x00, 0x00, 0x00, 0x5B, 0x83, 0xE3, 0x80,
                0x81, 0xC3, 0x80, 0x00, 0x00, 0x00, 0x8D, 0xBD,
                0x00, 0xF0, 0xFF, 0xFF, 0x8D, 0x73, 0x40, 0xAC,
                0xAA, 0x84, 0xC0, 0x75, 0xFA, 0x4F, 0x8B, 0x75,
                0x08, 0xAC, 0xAA, 0x84, 0xC0, 0x75, 0xFA, 0xFF,
                0x75, 0x20, 0xFF, 0x75, 0x1C, 0xFF, 0x75, 0x18,
                0xFF, 0x75, 0x14, 0xFF, 0x75, 0x10, 0xFF, 0x75,
                0x0C, 0x8D, 0x85, 0x00, 0xF0, 0xFF, 0xFF, 0x50,
                0x8D, 0x03, 0xFF, 0xD0, 0x83, 0xF8, 0xFF, 0x75,
                0x19, 0xFF, 0x75, 0x20, 0xFF, 0x75, 0x1C, 0xFF,
                0x75, 0x18, 0xFF, 0x75, 0x14, 0xFF, 0x75, 0x10,
                0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x08, 0x8D, 0x03,
                0xFF, 0xD0, 0x5E, 0x5F, 0x5B, 0xC9, 0xC2, 0x1C,
                0x00
            });
            league.WriteMemory(payloadPointer + 0x80, originalTrampoline);
            league.WriteMemory(payloadPointer + 0x80 + 64, _prefixBytes);
            league.MarkMemoryExecutable(payloadPointer, 0x1000);

            // write hooks
            league.Write(rsaVerifyPointer, payloadPointer);
            league.WriteMemory(createFileATrampolinePointer, modifiedTrampoline.ToArray());
        }

        public bool NeedsUpdate(LeagueProcess league)
        {
            byte[] dataPE = league.ReadMemory(league.Base, 0x1000);
            uint actualChecksum = LeagueProcess.ExtractChecksum(dataPE);
            return actualChecksum != this.Checksum || this.RSAMethOffset == 0 || this.CreateFileARefOffset == 0 || this.CreateFileAOffset == 0;
        }
        public void UpdateOffsets(LeagueProcess league)
        {
            byte[] data = league.Dump();
            uint checksum = LeagueProcess.ExtractChecksum(data);

            int rsaMethNameOffset = PAT_RSA_METH_NAME.Find(data);
            if (rsaMethNameOffset == -1)
            {
                throw new IOException("Failed to find RSA method name index!");
            }
            SigScanner pat_RSA_METH = SigScanner.ExactInt(rsaMethNameOffset + (int)league.Base);
            int rsaMethOffset = pat_RSA_METH.Find(data);
            if (rsaMethOffset == -1)
            {
                throw new IOException("Failed to find RSA method index!");
            }

            int createFileARefOffset = PAT_CreateFileA_CALL.Find(data);
            if (createFileARefOffset == -1)
            {
                throw new IOException("Failed to find CreateFileA reference index!");
            }

            int createFileAOffset = BitConverter.ToInt32(data, createFileARefOffset) - (int)league.Base;

            this.Checksum = checksum;
            this.RSAMethOffset = (uint)rsaMethOffset;
            this.CreateFileARefOffset = (uint)createFileARefOffset;
            this.CreateFileAOffset = (uint)createFileAOffset;

            this._messageCallback?.Invoke(string.Format("Checksum: {0}", checksum));
            this._messageCallback?.Invoke(string.Format("RSAMethOffset: {0}", RSAMethOffset));
            this._messageCallback?.Invoke(string.Format("CreateFileARefOffset: {0}", CreateFileARefOffset));
            this._messageCallback?.Invoke(string.Format("CreateFileAOffset: {0}", CreateFileAOffset));
        }

        public static bool IsLeague(Process league)
        {
            if (league.ProcessName == "League of Legends")
            {
                return league.MainModule.ModuleName == "League of Legends.exe";
            }
            return false;
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
                this.RSAMethOffset = br.ReadUInt32();
                this.CreateFileARefOffset = br.ReadUInt32();
                this.CreateFileAOffset = br.ReadUInt32();
            }
        }
        private void WriteConfig(string configLocation = CONFIG_FILE)
        {
            using (BinaryWriter bw = new BinaryWriter(File.Create(configLocation)))
            {
                bw.Write(VERSION);
                bw.Write(this.Checksum);
                bw.Write(this.RSAMethOffset);
                bw.Write(this.CreateFileARefOffset);
                bw.Write(this.CreateFileAOffset);
            }
        }
    }
}
