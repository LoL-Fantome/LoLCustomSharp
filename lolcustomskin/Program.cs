using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using LoLCustomSharp;
using System.IO;
using System.Threading;
using System.Diagnostics;
using System.Reflection;

namespace lolcustomskin
{
    class Program
    {
        static void Main(string[] args)
        {
            string exePath = Assembly.GetEntryAssembly().Location;
            string configPath = Path.GetDirectoryName(exePath) + "/lolcustomskin-sharp.bin";
            OverlayPatcher patcher = new OverlayPatcher();
            patcher.Start(args.Length > 0 ? args[0] : "MOD/", (msg) => Console.WriteLine(msg), (err) => Console.WriteLine(err.StackTrace));
            patcher.Join();
            Console.ReadKey();
        }
    }
}
