using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace lab5
{
    class Program
    {
        static void Main(string[] Fileargs)
        {
            string dataFile;
            string signedFile;
            if (Fileargs.Length < 2)
            {
                dataFile = @"text.txt";
                signedFile = "signedFile.enc";

                if (!File.Exists(dataFile))
                {
                    using (StreamWriter sw = File.CreateText(dataFile))
                    {
                        sw.WriteLine("Here is a message to sign");
                    }
                }

            }
            else
            {
                dataFile = Fileargs[0];
                signedFile = Fileargs[1];
            }
            try
            {
                byte[] secretkey = new Byte[64];
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(secretkey);

                    SignFile(secretkey, dataFile, signedFile);

                    VerifyFile(secretkey, signedFile);
                }
                Console.ReadKey();
            }
            catch (IOException e)
            {
                Console.WriteLine("Error: File not found", e);
            }
        }
        public static void SignFile(byte[] key, String sourceFile, String destFile)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                using (FileStream inStream = new FileStream(sourceFile, FileMode.Open))
                {
                    using (FileStream outStream = new FileStream(destFile, FileMode.Create))
                    {
                        byte[] hashValue = hmac.ComputeHash(inStream);
                        inStream.Position = 0;
                        outStream.Write(hashValue, 0, hashValue.Length);
                        int bytesRead;
                        byte[] buffer = new byte[1024];
                        do
                        {
                            bytesRead = inStream.Read(buffer, 0, 1024);
                            outStream.Write(buffer, 0, bytesRead);
                        } while (bytesRead > 0);
                    }
                }
            }
            return;
        }

        public static bool VerifyFile(byte[] key, String sourceFile)
        {
            bool err = false;
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                byte[] storedHash = new byte[hmac.HashSize / 8];
                using (FileStream inStream = new FileStream(sourceFile, FileMode.Open))
                {
                    inStream.Read(storedHash, 0, storedHash.Length);
                    byte[] computedHash = hmac.ComputeHash(inStream);

                    for (int i = 0; i < storedHash.Length; i++)
                    {
                        if (computedHash[i] != storedHash[i])
                        {
                            err = true;
                        }
                    }
                }
            }
            if (err)
            {
                Console.WriteLine("Hash values differ! Signed file has been tampered with!");
                return false;
            }
            else
            {
                Console.WriteLine("Hash values agree -- no tampering occurred.");
                return true;
            }

        }

    }
}
