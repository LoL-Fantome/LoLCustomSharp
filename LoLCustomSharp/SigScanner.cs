using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace LoLCustomSharp
{
    public class SigScanner
    {
        private readonly byte[] _pattern;
        private readonly bool[] _wildcard;
        private readonly int _offset;

        private SigScanner(byte[] pattern, bool[] wildcard, int offset)
        {
            _pattern = pattern;
            _wildcard = wildcard;
            _offset = offset;
        }

        public static SigScanner Pattern(string data, int offset = 0)
        {
            string[] chars = data.Split(' ');
            byte[] pattern = chars.Select((x) =>
            {
                if (x == "??" || x == "?")
                {
                    return (byte)0;
                }
                return byte.Parse(x, NumberStyles.HexNumber);
            }).ToArray();
            bool[] wildcard = chars.Select((x) =>
            {
                return x == "??" || x == "?";
            }).ToArray();
            return new SigScanner(pattern, wildcard, offset);
        }

        public static SigScanner ExactBytes(byte[] data, int offset = 0)
        {
            return new SigScanner(data, new bool[data.Length], offset);
        }

        public static SigScanner ExactString(string data, int offset = 0)
        {
            return ExactBytes(Encoding.ASCII.GetBytes(data), offset);
        }

        public static SigScanner ExactInt(int data, int offset = 0)
        {
            return ExactBytes(BitConverter.GetBytes(data), offset);
        }

        public int Find(byte[] data)
        {
            int[] skipTable = new int[256];
            int lastIndex = this._pattern.Length - 1;

            var lastWildCard = Array.LastIndexOf(this._wildcard, true);
            int safeSkip = Math.Max(lastWildCard == -1 ? 0 : lastIndex - lastWildCard, 1);
            for (int i = 0; i < skipTable.Length; i++)
            {
                skipTable[i] = safeSkip;
            }

            for (int i = lastIndex - safeSkip; i < lastIndex; i++)
            {
                skipTable[this._pattern[i]] = lastIndex - i;
            }

            for (int i = 0; i <= data.Length - this._pattern.Length; )
            {
                for (int j = lastIndex; this._wildcard[j] || data[i + j] == this._pattern[j]; --j)
                {
                    if (j == 0)
                    {
                        return i + this._offset;
                    }
                }
                i += Math.Max(skipTable[data[i + lastIndex] & 0xFF], 1);
            }

            return -1;
        }
    }
}
