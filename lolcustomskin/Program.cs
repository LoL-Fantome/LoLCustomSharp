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
        static void MessageHandler(string message)
        {
            Console.WriteLine(message);
        }

        static void ErrorHandler(Exception error)
        {
            Console.WriteLine(error.Message);
            Console.WriteLine(error.StackTrace);
        }

        static void Main(string[] args)
        {
            string exePath = Assembly.GetEntryAssembly().Location;
            string configPath = Path.GetDirectoryName(exePath) + "/lolcustomskin-sharp.bin";
            OverlayPatcher patcher = new OverlayPatcher(configPath);
            patcher.Start(args.Length > 0 ? args[0] : "MOD/", MessageHandler, ErrorHandler);
            patcher.Join();
            Console.ReadKey();
        }
    }
}
