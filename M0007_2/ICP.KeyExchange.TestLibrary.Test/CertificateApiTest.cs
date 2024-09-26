using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Web;
using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
namespace ICP.KeyExchange.TestLibrary.Test
{
    [TestClass]
    public class CertificateApiTest
    {
        int i = 0;
        string enc;
        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
            BaseAddress = new Uri("https://icp-member-stage.icashpay.com.tw/")
        };
        private readonly RsaCryptoHelper _rsaCryptoHelper = new RsaCryptoHelper();
        private readonly AesCryptoHelper _aesCryptoHelper = new AesCryptoHelper();
        private string _serverPublicKey = null;
        private string _clientPublicKey = null;
        private string _clientPrivateKey = null;
        private long _aesClientCertId = -1;
        private string _aesKey = null;
        private string _aesIv = null;
        [TestMethod]
        public void GetDefaultPucCert()
        {
            getDefaultPucCert();
        }
        [TestMethod]
        public void ExchangePucCert()
        {
            exchangePucCert();
        }
        [TestMethod]
        public void GenerateAES()
        {
            generateAES();
        }
        private (string Content, string Signature) callCertificateApi(string action, long certId, string serverPublicKey, string clientPrivateKey, object obj, string certHeaderName)
        {
            string json = JsonConvert.SerializeObject(obj);
            _rsaCryptoHelper.ImportPemPublicKey(serverPublicKey);
            string encData = _rsaCryptoHelper.Encrypt(json);
            _rsaCryptoHelper.ImportPemPrivateKey(clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);
            var content = new FormUrlEncodedContent(form);
            content.Headers.Add(certHeaderName, certId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            var postResult = _httpClient.PostAsync(action, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();
            string resultSignature = headerSignature.Value?.FirstOrDefault();
            return (stringResult, resultSignature);
        }
        private void checkTimestamp(string timestamp)
        {
            if (!DateTime.TryParse(timestamp, out DateTime dt))
            {
                throw new Exception("Timestamp 有誤");
            }
            double subSec = DateTime.Now.Subtract(dt).TotalSeconds;
            if (subSec > 30 || subSec < -30)
            {
                throw new Exception("Timestamp 誤差過大");
            }
        }
        private (long CertId, string PublicKey) getDefaultPucCert()
        {
            string url = "/api/member/Certificate/GetDefaultPucCert";
            var postResult = _httpClient.PostAsync(url, null).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
            Console.WriteLine($"回傳：{stringResult}");
            JObject jObj = JObject.Parse(stringResult);
            int rtnCode = jObj.Value<int>("RtnCode");
            Assert.AreEqual(1, rtnCode);
            long certId = jObj.Value<long>("DefaultPubCertID");
            string publicKey = jObj.Value<string>("DefaultPubCert");
            return (certId, publicKey);
        }
        private (ExchangePucCertResult Result, string ClientPrivateKey) exchangePucCert()
        {
            var getDefaultPucCertResult = getDefaultPucCert();
            var key = _rsaCryptoHelper.GeneratePemKey();
            var result = callCertificateApi("/api/member/Certificate/ExchangePucCert",
                                 getDefaultPucCertResult.CertId,
                                 getDefaultPucCertResult.PublicKey,
                                 key.PrivateKey,
                                 new ExchangePucCertRequest
                                 {
                                     ClientPubCert = key.PublicKey,
                                     Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
                                 },
                                 "X-iCP-DefaultPubCertID");
            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }
            _rsaCryptoHelper.ImportPemPrivateKey(key.PrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
            var exchangePucCertResult = JsonConvert.DeserializeObject<ExchangePucCertResult>(json);
            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            checkTimestamp(exchangePucCertResult.Timestamp);
            _clientPrivateKey = key.PrivateKey;
            _clientPublicKey = key.PublicKey;
            _serverPublicKey = exchangePucCertResult.ServerPubCert;
            return (exchangePucCertResult, key.PrivateKey);
        }
        private void generateAES()
        {
            var exchangePucCertResult = exchangePucCert();
            var result = callCertificateApi("/api/member/Certificate/GenerateAES",
                                 exchangePucCertResult.Result.ServerPubCertID,
                                 exchangePucCertResult.Result.ServerPubCert,
                                 exchangePucCertResult.ClientPrivateKey,
            new BaseAuthorizationApiRequest
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
            },
                                 "X-iCP-ServerPubCertID");
            var apiResult = JsonConvert.DeserializeObject<AuthorizationApiEncryptResult>(result.Content);
            if (apiResult.RtnCode != 1)
            {
                throw new Exception(apiResult.RtnMsg);
            }
            _rsaCryptoHelper.ImportPemPrivateKey(exchangePucCertResult.ClientPrivateKey);
            string json = _rsaCryptoHelper.Decrypt(apiResult.EncData);
            using (StreamWriter writer = new StreamWriter("keyiv1.txt"))
            {
                writer.WriteLine(json);
                Console.WriteLine("168168168");
                Console.WriteLine(json);
            }
            var generateAesResult = JsonConvert.DeserializeObject<GenerateAesResult>(json);
            _rsaCryptoHelper.ImportPemPublicKey(exchangePucCertResult.Result.ServerPubCert);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(result.Content, result.Signature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            checkTimestamp(generateAesResult.Timestamp);
            _aesClientCertId = generateAesResult.EncKeyID;
            _aesKey = generateAesResult.AES_Key;
            _aesIv = generateAesResult.AES_IV;

        
        }
        private string callNormalApi(string url, object obj, ref string decryptContent)
        {
            string json = JsonConvert.SerializeObject(obj);
            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);
            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            IDictionary<string, string> form = new Dictionary<string, string>();
            form.Add("EncData", encData);
            var content = new FormUrlEncodedContent(form);
            content.Headers.Add("X-iCP-EncKeyID", _aesClientCertId.ToString());
            content.Headers.Add("X-iCP-Signature", signature);
            string s = _aesClientCertId.ToString();
            string a = signature;
            var postResult = _httpClient.PostAsync(url, content).Result;
            string stringResult = postResult.Content.ReadAsStringAsync().Result;
            var headerSignature = postResult.Headers.Where(x => x.Key == "X-iCP-Signature").FirstOrDefault();
            string resultSignature = headerSignature.Value?.FirstOrDefault();
            _rsaCryptoHelper.ImportPemPublicKey(_serverPublicKey);
            bool isValid = _rsaCryptoHelper.VerifySignDataWithSha256(stringResult, resultSignature);
            if (!isValid)
            {
                throw new Exception("簽章驗證失敗");
            }
            JToken jToken = JToken.Parse(stringResult);
            if (jToken["RtnCode"].Value<int>() != 1)
            {
                throw new Exception(jToken["RtnMsg"].Value<string>());
            }
            decryptContent = _aesCryptoHelper.Decrypt(jToken["EncData"].Value<string>());
            string encryptedData = jToken["EncData"].Value<string>();

            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string decryptedData = _aesCryptoHelper.Decrypt(encryptedData);
            decryptContent = decryptedData;
            Console.WriteLine("SendAuthSMS");
            Console.WriteLine(decryptContent);

            //// 提取AuthCode的值
            int startIndex = decryptedData.IndexOf("\"AuthCode\":\"") + "\"AuthCode\":\"".Length;
            int endIndex = decryptedData.IndexOf(',', startIndex);
            string authCode = decryptedData.Substring(startIndex, endIndex - startIndex);

            //// 移除AuthCode值中的引號
            authCode = authCode.Replace("\"", "");

            //// 输出AuthCode的值
            Console.WriteLine(authCode);

            //// 将AuthCode写入AuthCode.txt文件
            File.WriteAllText("authcode.txt", authCode);



            // using (StreamWriter writer = new StreamWriter("NGetToken.txt"))
            //  {
            //   writer.WriteLine(decryptContent);


            //  }





            //// 提取LoginTokenID的值
            //int startIndex = decryptedData.IndexOf("\"LoginTokenID\":\"") + "\"LoginTokenID\":\"".Length;
            //int endIndex = decryptedData.IndexOf(',', startIndex);
            //string loginTokenID = decryptedData.Substring(startIndex, endIndex - startIndex);

            //// 输出LoginTokenID的值
            //Console.WriteLine(loginTokenID);

            //// 将LoginTokenID写入token.txt文件
            //File.WriteAllText("token.txt", loginTokenID);


            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }
        [TestMethod]
        public void GetCellphone()
        {
            generateAES();
            string url = "/app/MemberInfo/SendAuthSMS";
            var request1 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                CellPhone = "0976100004",
                SMSAuthType = 5,
                UserCode = "",
               // IDNo = "B198052452",
                //AuthCode = "114972",
                LoginTokenID = System.IO.File.ReadAllText(@"C:\IcashPost\ICPLogin\M0001_1\ConsoleApp1\bin\Debug\logintokenid.txt")
               

            };
            string decryptContent1 = null;
            string response1 = callNormalApi(url, request1, ref decryptContent1);
            Console.WriteLine("SendAuthSMS");
            Console.WriteLine(response1);
        



        }
    }
}
