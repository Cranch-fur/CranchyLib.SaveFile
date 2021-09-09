// Original Code was created by Marsik
// Decompiled & Changed by Cranch
// Compiled in to DLL by Cranch (Кранч) the wolf - SERVERNAME 2021

using System;
using System.IO;
using System.Text;
using Newtonsoft.Json; // Newtonsoft.Json.dll
using System.Security.Cryptography;
using Org.BouncyCastle.Utilities.Zlib; // BouncyCastle.Crypto.dll
using ICSharpCode.SharpZipLib.Zip.Compression.Streams; // ICSharpCode.SharpZipLib.dll

namespace CranchyLib.SaveFile
{
    public static class SaveFile
    {
        private const string SAVEFILE_AESKEY = "5BCC2D6A95D4DF04A005504E59A9B36E"; // SaveFile AES key, implemented in HEX format.
        private const string SAVEFILE_INNER = "DbdDAQEB";
        private const string SAVEFILE_OUTER = "DbdDAgAC";
        public static DateTime NETTimeStampStart { get; private set; }

        public static string DecryptSavefile(string input)
        {
            string input_decrypted = Raw_Decrypt(input.Substring(8).Trim());
            string savefile_ascii = "";
            foreach (char c in input_decrypted)
            {
                savefile_ascii += (char)(c + '\u0001');
            }
            savefile_ascii = savefile_ascii.Replace("\u0001", "");

            if (savefile_ascii.StartsWith("DbdDAQEB"))
            {
                byte[] array = Convert.FromBase64String(savefile_ascii.Substring(8));
                byte[] buffer = array.Subset(4, array.Length - 4);
                MemoryStream memoryStream = new MemoryStream();
                InflaterInputStream inflaterInputStream = new InflaterInputStream(new MemoryStream(buffer));
                inflaterInputStream.CopyTo(memoryStream);
                memoryStream.Position = 0L;
                return Encoding.Unicode.GetString(ReadToEnd(memoryStream));
            }
            else
                return savefile_ascii;
        }
        public static string EncryptSavefile(string input)
        {
            byte[] input_asbyte = Encoding.Unicode.GetBytes(input);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (ZOutputStream zoutputStream = new ZOutputStream(memoryStream, -1))
                {
                    zoutputStream.Write(input_asbyte, 0, input_asbyte.Length);
                    zoutputStream.Flush();
                }

                string saveFile = Convert.ToBase64String(PaddingWithNumber(memoryStream.ToArray(), input_asbyte.Length));
                int _pad = 16 - ((SAVEFILE_INNER.Length + saveFile.Length) % 16);
                saveFile = SAVEFILE_INNER + saveFile.PadRight(saveFile.Length + _pad, '\u0001');
                string output = null;
                foreach (char c in saveFile)
                {
                    output += (char)(c - '\u0001');
                }
                return SAVEFILE_OUTER + Raw_Encrypt(output);
            }
        }
        public static string Ressurect_TimeStamp(string input)
        {
            dynamic JsSaveFile = JsonConvert.DeserializeObject(input);
            JsSaveFile["currentSeasonTicks"] = (long)((DateTime.Now.ToUniversalTime() - NETTimeStampStart).TotalMilliseconds + 0.5);
            return JsonConvert.SerializeObject(JsSaveFile, Formatting.None);
        }
        public static string Ressurect_UID(string input, string steamtoken)
        {
            dynamic JsSaveFile = JsonConvert.DeserializeObject(input);
            if (steamtoken.Length == 16) // 16 Symbols - Length of the playerUID, so DLL just use it instead of manipulations with SteamToken
                JsSaveFile["playerUId"] = steamtoken;
            else JsSaveFile["playerUId"] = SteamAuthToken_toUID(steamtoken);

            return JsonConvert.SerializeObject(JsSaveFile, Formatting.None);
        }
        public static string Ressurect_All(string input, string steamtoken)
        {
            dynamic JsSaveFile = JsonConvert.DeserializeObject(input);
            if(steamtoken.Length == 16) // 16 Symbols - Length of the playerUID, so DLL just use it instead of manipulations with SteamToken
                JsSaveFile["playerUId"] = steamtoken;
            else JsSaveFile["playerUId"] = SteamAuthToken_toUID(steamtoken);

            JsSaveFile["currentSeasonTicks"] = (long)((DateTime.Now.ToUniversalTime() - NETTimeStampStart).TotalMilliseconds + 0.5);
            return JsonConvert.SerializeObject(JsSaveFile, Formatting.None);
        }



        private static string Raw_Decrypt(string text)
        {
            byte[] input_asbyte = Convert.FromBase64String(text);
            ICryptoTransform transform = new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros
            }.CreateDecryptor(Encoding.ASCII.GetBytes(SAVEFILE_AESKEY), null);


            MemoryStream memoryStream = new MemoryStream(input_asbyte);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
            byte[] array = new byte[input_asbyte.Length];
            int length = cryptoStream.Read(array, 0, array.Length);
            memoryStream.FlushAsync(); memoryStream.Close();
            cryptoStream.Flush(); cryptoStream.Close();
            return Encoding.UTF8.GetString(array, 0, length);
        }
        private static string Raw_Encrypt(string input)
        {
            byte[] input_asbyte = Encoding.UTF8.GetBytes(input);
            ICryptoTransform transform = new RijndaelManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros
            }.CreateEncryptor(Encoding.ASCII.GetBytes(SAVEFILE_AESKEY), null);


            MemoryStream memoryStream = new MemoryStream(input_asbyte);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
            byte[] array = new byte[input_asbyte.Length];
            int length = cryptoStream.Read(array, 0, array.Length);
            memoryStream.FlushAsync(); memoryStream.Close();
            cryptoStream.Flush(); cryptoStream.Close();
            return Convert.ToBase64String(array, 0, length);
        }

        private static byte[] PaddingWithNumber(byte[] buffer, int num)
        {
            byte[] bytes = BitConverter.GetBytes(num);
            byte[] array = new byte[bytes.Length + buffer.Length];
            Buffer.BlockCopy(bytes, 0, array, 0, bytes.Length);
            Buffer.BlockCopy(buffer, 0, array, bytes.Length, buffer.Length);
            return array;
        }

        private static byte[] ReadToEnd(Stream stream)
        {
            long startposition = 0L;
            if (stream.CanSeek == true)
            {
                startposition = stream.Position;
                stream.Position = 0L;
            }

            try
            {
                byte[] array = new byte[8388608];
                int counter_fromend = 0;
                int counter_fromstart;
                while ((counter_fromstart = stream.Read(array, counter_fromend, array.Length - counter_fromend)) > 0)
                {
                    counter_fromend += counter_fromstart;
                    if (counter_fromend == array.Length)
                    {
                        if (stream.ReadByte() != -1)
                        {
                            byte[] _temparray = new byte[array.Length * 2];
                            Buffer.BlockCopy(array, 0, _temparray, 0, array.Length);
                            Buffer.SetByte(_temparray, counter_fromend, (byte)stream.ReadByte());
                            array = _temparray;
                            counter_fromend++;
                        }
                    }
                }


                if (array.Length != counter_fromend)
                {
                    byte[] _array = new byte[counter_fromend];
                    Buffer.BlockCopy(array, 0, _array, 0, counter_fromend);
                    return _array;
                }
                else
                    return array;
            }

            finally
            {
                if (stream.CanSeek == true)
                    stream.Position = startposition;
            }
        }
        public static string SteamAuthToken_toUID(string input)
        {
            string output = input.Remove(0, 24);
            output = output.Remove(16, output.Length - 16);
            return output;
        }
    }
}
