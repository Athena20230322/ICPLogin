using ICP.KeyExchange.TestLibrary.Helpers;
using ICP.KeyExchange.TestLibrary.Models;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
namespace ICP.KeyExchange.TestLibrary.Test
{
    [TestClass]
    public class CertificateApiTest
    {
        int i = 0;
        string enc;
        string post1;
        private readonly HttpClient _httpClient = new HttpClient
        {
            //BaseAddress = new Uri("https://icp-plus-stage.icashpay.com.tw")

            BaseAddress = new Uri("https://icp-member-stage.icashpay.com.tw/")


        };

        private readonly HttpClient _httpClient2 = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")
            BaseAddress = new Uri("https://icp-plus-stage.icashpay.com.tw")
            //BaseAddress = new Uri("https://icp-payment-stage.icashpay.com.tw")


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
                Console.WriteLine($"無法解析的 Timestamp：{timestamp}");
                // 或者您也可以使用其他方式記錄除錯訊息，如日誌系統
                // throw new Exception("Timestamp 有誤");

            }
            double subSec = DateTime.Now.Subtract(dt).TotalSeconds;
            if (subSec > 30 || subSec < -30)
            {
                Console.WriteLine($"Timestamp 誤差過大：{timestamp}");
                // 或者您也可以使用其他方式記錄除錯訊息，如日誌系統
                // throw new Exception("Timestamp 誤差過大");

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
            Console.WriteLine("123123455");
            Console.WriteLine(a);
            Console.WriteLine("123123456");
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
            Console.WriteLine("LoginTokenID");
            Console.WriteLine(decryptContent);

            //// 提取AuthCode的值
            int startIndex = decryptedData.IndexOf("\"LoginTokenID\":\"") + "\"LoginTokenID\":\"".Length;
            int endIndex = decryptedData.IndexOf(',', startIndex);
            string authCode = decryptedData.Substring(startIndex, endIndex - startIndex);

            //// 移除AuthCode值中的引號
            authCode = authCode.Replace("\"", "");

            //// 输出AuthCode的值
            Console.WriteLine(authCode);

            //// 將AuthCode寫入AuthCode.txt文件
            File.WriteAllText("logintokenid.txt", authCode);


            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }



        private string callNormalApi1(string url, object obj, ref string decryptContent)
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
            var postResult = _httpClient2.PostAsync(url, content).Result;
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
            Console.WriteLine("15515155");
            Console.WriteLine(decryptContent);

            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }

        private string callNormalApio(string url, object obj, ref string decryptContent)
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


            var jObj = JObject.Parse(decryptContent);
            string Timestamp = jObj.Value<string>("Timestamp");
            checkTimestamp(Timestamp);
            return stringResult;
        }



        private string _postDataFileName;
        private string callNormalApiL(string url, object obj, ref string decryptContent, string postDataFileName)

        {
            _postDataFileName = postDataFileName; // 設置類級別變量的值
            string json = JsonConvert.SerializeObject(obj);
            _aesCryptoHelper.Key = _aesKey;
            _aesCryptoHelper.Iv = _aesIv;
            string encData = _aesCryptoHelper.Encrypt(json);
            _rsaCryptoHelper.ImportPemPrivateKey(_clientPrivateKey);
            string signature = _rsaCryptoHelper.SignDataWithSha256(encData);
            string s = _aesClientCertId.ToString();
            string postData = $"{s},{signature},{encData}";
            string filePath = Path.Combine("C:\\testicashapi\\OpostData", postDataFileName);
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine(postData);
            }
            return post1;
        }

        [TestMethod]
      //  [TestMethod]
        public void GetCellphone()
        {
            generateAES();

            string url1 = "/app/MemberInfo/RefreshLoginToken";
            string url2 = "/app/MemberInfo/SendAuthSMS";
            string url3 = "/app/MemberInfo/UserCodeLogin2022";
            string url4 = "/app/Payment/ParserQrCode";

            var request1 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                CellPhone = "0976100004"
            };
            string decryptContent1 = null;
            string response1 = callNormalApi(url1, request1, ref decryptContent1);
            Console.WriteLine("LoginTokenID");
            Console.WriteLine(response1);

            var request2 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                CellPhone = "0976100004",
                SMSAuthType = 5,
                UserCode = "",
                LoginTokenID = System.IO.File.ReadAllText(@"C:\IcashPost\ICPLogin\M0005_3_P0037\ConsoleApp1\bin\Debug\logintokenid.txt")
            };
            string decryptContent2 = null;
            string response2 = callNormalApio(url2, request2, ref decryptContent2);
            Console.WriteLine("SendAuthSMS");
            Console.WriteLine(response2);

            var request3 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                LoginType = "1",
                UserCode = "tester1851",
                UserPwd = "Aa123456",
                SMSAuthCode = System.IO.File.ReadAllText(@"C:\IcashPost\ICPLogin\M0005_3_P0037\ConsoleApp1\bin\Debug\authcode.txt")
            };
            string decryptContent3 = null;
            string response3 = callNormalApi(url3, request3, ref decryptContent3);
            Console.WriteLine("UserCodeLogin2022");
            Console.WriteLine(response3);

            var request4 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                MerchantQRcode = "e8nvRG%2BGx60Ao5II23oGqO8kzpeICtZ%2F2Q6HfCUnXsXklcuDwCyplbAlztmyRoCXbOnFmco5rKkj0zbynAzC8QhQSz%2B6TUuYR7MhP%2Bg84YKHkPhGgt%2BbLg1iXXiZ%2BAbA"
            };
            string decryptContent4 = null;
            string response4 = callNormalApi1(url4, request4, ref decryptContent4);
            Console.WriteLine("MerchantQRcode");
            Console.WriteLine(response4);

            // 提取並印出所需的參數和值
            try
            {
                JToken jToken = JToken.Parse(decryptContent4);

                // 提取 CodeType
                int codeType = jToken.Value<int>("CodeType");
                Console.WriteLine($"CodeType: {codeType}");

                // 提取 RtnValue 中的 QRCodeType 和 UsePointType
                string rtnValueJson = jToken.Value<string>("RtnValue");
                if (!string.IsNullOrEmpty(rtnValueJson))
                {
                    JToken rtnValueToken = JToken.Parse(rtnValueJson);

                    string qrCodeType = rtnValueToken.Value<string>("QRCodeType");
                    int usePointType = rtnValueToken.Value<int>("UsePointType");

                    Console.WriteLine($"QRCodeType: {qrCodeType}");
                    Console.WriteLine($"UsePointType: {usePointType}");
                }
                else
                {
                    Console.WriteLine("RtnValue is null or empty.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing JSON: {ex.Message}");
            }
        }
    }
}