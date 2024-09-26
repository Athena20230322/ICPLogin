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
            //BaseAddress = new Uri("http://localhost:3311")

            BaseAddress = new Uri("https://icp-member-stage.icashpay.com.tw/")
            

        };

        private readonly HttpClient _httpClient2 = new HttpClient
        {
            //BaseAddress = new Uri("http://localhost:3311")

            BaseAddress = new Uri("https://icp-payment-stage.icashpay.com.tw")


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
            Console.WriteLine("16616166");
            Console.WriteLine(decryptContent);



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
        public void GetCellphone()
        {
            generateAES();
      
               string url = "/app/MemberInfo/UserCodeLogin2022";
               string url71 = "/app/Payment/GetAvailableBalance";
               string url72 = "/app/Payment/GetMemberPaymentInfo";
               string url73 = "/app/MemberInfo/GetEInvoiceCarrierInfo";
               string url74 = "/app/MemberInfo/QueryMMember";
               string url75 = "/app/MemberInfo/GetRangeNotifyMessageList";
               string url76 = "/app/TopUpPayment/GetAutoTopUpInfo";
               string url77 = "/app/TopUpPayment/GetListChannelInfo";
               string url78 = "/app/MemberInfo/QueryMemberOpPoint";
               string url79 = "/app/Payment/CreateTrafficQRCode";
               string url80 = "/app/MemberInfo/QueryMemberPointSwitch";
               string url81 = "/app/MemberInfo/Payment/CreateBarcode";
               string url82 = "/app/MemberInfo/GetFinanceAD";
               //string url83 = "/app/MemberInfo/GetInsuranceAD2022";
               string url84 = "/icp-payment-stage.icashpay.com.tw/app/TransferAccount/GetFiscHandlingCharge";
               string url85 = "/app/MemberInfo/GetListBankInfo";

            var request1 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                LoginType = "1",
                UserCode = "tester1851",
                UserPwd = "Aa123456",
                SMSAuthCode = System.IO.File.ReadAllText(@"C:\IcashPost\ICPLogin\M0007_2\ConsoleApp1\bin\Debug\authcode.txt")
              
               
            };
            string decryptContent1 = null;
            string response1 = callNormalApi(url, request1, ref decryptContent1);
            Console.WriteLine("UserCodeLogin2022");
            Console.WriteLine(response1);

          
            var request9 = new
            {

                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),

            };

            string decryptContent9 = null;
            string response9 = callNormalApiL(url71, request9, ref decryptContent9,"postData2.txt");

            var request10 = new
            {

                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                MerchantID = "10512932"
            };

            string decryptContent10 = null;
            string response10 = callNormalApiL(url72, request10, ref decryptContent10, "postData3.txt");

            var request11 = new
            {

                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

            };

            string decryptContent11 = null;
            string response11 = callNormalApiL(url73, request11, ref decryptContent11, "postData4.txt");

            var request12 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

            };

            string decryptContent12 = null;
            string response12 = callNormalApiL(url74, request12, ref decryptContent12, "postData5.txt");


            var request13 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                MsgID = "0",
                Type = "1",
                Count = "100"

            };

            string decryptContent13 = null;
            string response13 = callNormalApiL(url75, request13, ref decryptContent13, "postData6.txt");

            var request14 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

            };

            string decryptContent14 = null;
            string response14 = callNormalApiL(url76, request14, ref decryptContent14, "postData7.txt");

            var request15 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

            };

            string decryptContent15 = null;
            string response15 = callNormalApiL(url77, request15, ref decryptContent15, "postData8.txt");

            var request16 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")

            };

            string decryptContent16 = null;
            string response16 = callNormalApiL(url78, request16, ref decryptContent16, "postData9.txt");

            var request17 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                PayID = "11682311000002951",
                PaymentType = "1",
                Token = System.IO.File.ReadAllText(@"C:\IcashPost\NEWICPAPI\NewLogin\ML202\ConsoleApp1\bin\Debug\ntoken.txt")


            };

            string decryptContent17 = null;
            string response17 = callNormalApiL(url79, request17, ref decryptContent17, "postData10.txt");

            var request18 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")
            


            };

            string decryptContent18 = null;
            string response18 = callNormalApiL(url80, request18, ref decryptContent18, "postData11.txt");

            var request19 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                PayID = "11682311000002951",
                PaymentType = "1"
              


            };

            string decryptContent19 = null;
            string response19 = callNormalApiL(url81, request19, ref decryptContent19, "postData12.txt");

            var request20 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                ADType = "0",
                ADStartTime = "2021/06/08 09:44:33",
                ADEndTime = "2023/06/08 09:44:33"


            };

            string decryptContent20 = null;
            string response20 = callNormalApiL(url82, request20, ref decryptContent20, "postData13.txt");

            var request21 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                ADType = "0",
                ADStartTime = "2021/06/08 09:44:33",
                ADEndTime = "2023/06/20 09:44:33"


            };

            string decryptContent21 = null;
            string response21 = callNormalApiL(url84, request21, ref decryptContent21, "postData14.txt");

            var request22 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                TransferAmount = "100"



            };

            string decryptContent22 = null;
            string response22 = callNormalApiL(url84, request22, ref decryptContent22, "postData15.txt");

            var request23 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                TransferAmount = "501"



            };

            string decryptContent23 = null;
            string response23 = callNormalApiL(url84, request23, ref decryptContent23, "postData16.txt");

            var request24 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                TransferAmount = "1001"



            };

            string decryptContent24 = null;
            string response24 = callNormalApiL(url84, request24, ref decryptContent24, "postData17.txt");

            var request25 = new
            {
                Timestamp = DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"),
                BankInfoType = "1"
             



            };

            string decryptContent25 = null;
            string response25 = callNormalApiL(url85, request25, ref decryptContent25, "postData18.txt");




        }
    }
}
