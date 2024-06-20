using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace ICP.KeyExchange.TestLibrary.Helpers
{
    public class RsaCryptoHelper
    {
        private string _publicKey = null;
        private string _privateKey = null;

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="content"></param>
        /// <returns></returns>
        public string Encrypt(string content)
        {
            byte[] input = Encoding.UTF8.GetBytes(content);
            byte[] output = processCrypto(true, _publicKey, input);
            return Convert.ToBase64String(output);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="base64Content"></param>
        /// <returns></returns>
        public string Decrypt(string base64Content)
        {
            byte[] input = Convert.FromBase64String(base64Content);
            byte[] output = processCrypto(false, _privateKey, input);
            return Encoding.UTF8.GetString(output);
        }

        /// <summary>
        /// 簽章 RSA Signing - SHA256
        /// </summary>
        /// <param name="base64String"></param>
        /// <returns></returns>
        public string SignDataWithSha256(string content)
        {
            byte[] input = Encoding.UTF8.GetBytes(content);
            byte[] output = null;

            using (var provider = new RSACryptoServiceProvider())
            {
                provider.FromXmlString(_privateKey);

                using (var sha256 = new SHA256CryptoServiceProvider())
                {
                    output = provider.SignData(input, sha256);
                }
            }

            return Convert.ToBase64String(output);
        }

        /// <summary>
        /// 驗證 RSA Signing - SHA256
        /// </summary>
        /// <param name="base64Content"></param>
        /// <param name="base64Signature"></param>
        /// <returns></returns>
        public bool VerifySignDataWithSha256(string content, string base64Signature)
        {
            byte[] input = Encoding.UTF8.GetBytes(content);
            byte[] inputSignature = Convert.FromBase64String(base64Signature);

            using (var provider = new RSACryptoServiceProvider())
            {
                provider.FromXmlString(_publicKey);

                using (var sha256 = new SHA256CryptoServiceProvider())
                {
                    return provider.VerifyData(input, sha256, inputSignature);
                }
            }
        }

        /// <summary>
        /// 產生 RSA 金鑰(Pem)
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public (string PublicKey, string PrivateKey) GeneratePemKey(int size = 2048)
        {
            var key = GenerateXmlKey(size);
            using (var provider = new RSACryptoServiceProvider())
            {
                provider.FromXmlString(key.PrivateKey);

                string publicKey = exportPublicKey(provider);
                string privateKey = exportPrivateKey(provider);

                return (publicKey, privateKey);
            }
        }

        /// <summary>
        /// 產生 RSA 金鑰(Xml)
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public (string PublicKey, string PrivateKey) GenerateXmlKey(int size = 2048)
        {
            using (var provider = new RSACryptoServiceProvider(size))
            {
                string publicKey = provider.ToXmlString(false);
                string privateKey = provider.ToXmlString(true);

                return (publicKey, privateKey);
            }
        }

        /// <summary>
        /// 匯入 Private XML 金鑰
        /// </summary>
        /// <param name="xml"></param>
        public void ImportXmlPrivateKey(string xml)
        {
            _privateKey = xml;
        }

        /// <summary>
        /// 匯入 Public XML 金鑰
        /// </summary>
        /// <param name="xml"></param>
        public void ImportXmlPublicKey(string xml)
        {
            _publicKey = xml;
        }

        /// <summary>
        /// Import OpenSSH PEM private key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public void ImportPemPrivateKey(string pem)
        {
            pem = $"-----BEGIN RSA PRIVATE KEY-----{Environment.NewLine + pem + Environment.NewLine}-----END RSA PRIVATE KEY-----";

            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            //Console.WriteLine("Par1");
            //Console.WriteLine(rsaParams);

            using (var provider = new RSACryptoServiceProvider())
            {
                provider.ImportParameters(rsaParams);
                _privateKey = provider.ToXmlString(true);
                _publicKey = provider.ToXmlString(false);

                //Console.WriteLine("Par2");
                //Console.WriteLine(_privateKey);

            }
        }

        /// <summary>
        /// Import OpenSSH PEM public key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public void ImportPemPublicKey(string pem)
        {
            // iOS PKCS#1
            if (pem.Length == 360)
            {
                pem = $"-----BEGIN RSA PUBLIC KEY-----{Environment.NewLine + pem + Environment.NewLine}-----END RSA PUBLIC KEY-----";
            }
            // PKCS#8
            else
            {
                pem = $"-----BEGIN PUBLIC KEY-----{Environment.NewLine + pem + Environment.NewLine}-----END PUBLIC KEY-----";
            }

            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

            using (var provider = new RSACryptoServiceProvider())
            {
                provider.ImportParameters(rsaParams);
                _publicKey = provider.ToXmlString(false);
            }
        }

        /// <summary>
        /// Export private (including public) key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="provider"></param>
        /// <returns></returns>
        private string exportPrivateKey(RSACryptoServiceProvider provider)
        {
            using (var sw = new StringWriter())
            {
                if (provider.PublicOnly)
                {
                    throw new ArgumentException("CSP does not contain a private key", "csp");
                }

                var parameters = provider.ExportParameters(true);
                using (var ms = new MemoryStream())
                {
                    using (var bw = new BinaryWriter(ms))
                    {
                        bw.Write((byte)0x30); // SEQUENCE
                        using (var innerMS = new MemoryStream())
                        {
                            using (var innerBW = new BinaryWriter(innerMS))
                            {
                                encodeIntegerBigEndian(innerBW, new byte[] { 0x00 }); // Version
                                encodeIntegerBigEndian(innerBW, parameters.Modulus);
                                encodeIntegerBigEndian(innerBW, parameters.Exponent);
                                encodeIntegerBigEndian(innerBW, parameters.D);
                                encodeIntegerBigEndian(innerBW, parameters.P);
                                encodeIntegerBigEndian(innerBW, parameters.Q);
                                encodeIntegerBigEndian(innerBW, parameters.DP);
                                encodeIntegerBigEndian(innerBW, parameters.DQ);
                                encodeIntegerBigEndian(innerBW, parameters.InverseQ);

                                int length = (int)innerMS.Length;
                                encodeLength(bw, length);
                                bw.Write(innerMS.GetBuffer(), 0, length);
                            }
                        }

                        char[] base64 = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length).ToCharArray();
                        // Output as Base64 with lines chopped at 64 characters
                        for (var i = 0; i < base64.Length; i += 64)
                        {
                            sw.Write(base64, i, Math.Min(64, base64.Length - i));
                        }
                    }
                }

                return sw.ToString();
            }
        }

        /// <summary>
        /// Export public key from MS RSACryptoServiceProvider into OpenSSH PEM string
        /// slightly modified from https://stackoverflow.com/a/28407693
        /// </summary>
        /// <param name="provider"></param>
        /// <returns></returns>
        private string exportPublicKey(RSACryptoServiceProvider provider)
        {
            using (var sw = new StringWriter())
            {
                var parameters = provider.ExportParameters(false);
                using (var ms = new MemoryStream())
                {
                    using (var bw = new BinaryWriter(ms))
                    {
                        bw.Write((byte)0x30); // SEQUENCE
                        using (var innerMS = new MemoryStream())
                        {
                            using (var innerBW = new BinaryWriter(innerMS))
                            {
                                innerBW.Write((byte)0x30); // SEQUENCE
                                encodeLength(innerBW, 13);
                                innerBW.Write((byte)0x06); // OBJECT IDENTIFIER
                                var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                                encodeLength(innerBW, rsaEncryptionOid.Length);
                                innerBW.Write(rsaEncryptionOid);
                                innerBW.Write((byte)0x05); // NULL
                                encodeLength(innerBW, 0);
                                innerBW.Write((byte)0x03); // BIT STRING
                                using (var bitStringStream = new MemoryStream())
                                {
                                    using (var bitStringWriter = new BinaryWriter(bitStringStream))
                                    {
                                        bitStringWriter.Write((byte)0x00); // # of unused bits
                                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                                        using (var paramsStream = new MemoryStream())
                                        {
                                            using (var paramsWriter = new BinaryWriter(paramsStream))
                                            {
                                                encodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                                                encodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent

                                                int paramsLength = (int)paramsStream.Length;
                                                encodeLength(bitStringWriter, paramsLength);
                                                bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                                            }
                                        }

                                        var bitStringLength = (int)bitStringStream.Length;
                                        encodeLength(innerBW, bitStringLength);
                                        innerBW.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                                    }
                                }

                                int length = (int)innerMS.Length;
                                encodeLength(bw, length);
                                bw.Write(innerMS.GetBuffer(), 0, length);
                            }
                        }

                        char[] base64 = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length).ToCharArray();
                        for (var i = 0; i < base64.Length; i += 64)
                        {
                            sw.Write(base64, i, Math.Min(64, base64.Length - i));
                        }
                    }
                }

                return sw.ToString();
            }
        }

        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="length"></param>
        private void encodeLength(BinaryWriter stream, int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            }

            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        /// <summary>
        /// https://stackoverflow.com/a/23739932/2860309
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        /// <param name="forceUnsigned"></param>
        private void encodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                encodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    encodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    encodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        private byte[] processCrypto(bool isEncrypt, string key, byte[] input)
        {
            using (var provider = new RSACryptoServiceProvider())
            {
                provider.FromXmlString(key);

                // 1024的密鑰長度加密上限為117，2048的為245
                int bufferSize = (provider.KeySize / 8);
                if (isEncrypt)
                {
                    bufferSize -= 11;
                }

                byte[] buffer = new byte[bufferSize];

                // 分段處理
                using (var inputMS = new MemoryStream(input))
                {
                    using (var ouputMS = new MemoryStream())
                    {
                        while (true)
                        {
                            int readLine = inputMS.Read(buffer, 0, bufferSize);
                            if (readLine <= 0)
                            {
                                break;
                            }

                            byte[] temp = new byte[readLine];
                            Array.Copy(buffer, 0, temp, 0, readLine);

                            byte[] crypt = null;
                            if (isEncrypt)
                            {
                                crypt = provider.Encrypt(temp, false);
                            }
                            else
                            {
                                crypt = provider.Decrypt(temp, false);
                            }

                            ouputMS.Write(crypt, 0, crypt.Length);
                        }

                        return ouputMS.ToArray();
                    }
                }
            }
        }
    }
}
