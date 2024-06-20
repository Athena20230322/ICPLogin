using ICP.KeyExchange.TestLibrary.Utils;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.KeyExchange.TestLibrary.Models
{
    /// <summary>
    /// 可驗證的資料模型
    /// </summary>
    public class ValidatableObject
    {
        /// <summary>
        /// 是否驗證成功
        /// </summary>
        /// <returns></returns>
        public virtual bool IsValid()
        {
            return GetValidationResults().Count == 0;
        }

        /// <summary>
        /// 取得驗證結果
        /// </summary>
        /// <returns></returns>
        public IList<ValidationResult> GetValidationResults()
        {
            ValidateUtil.TryValidateObject(this, out IList<ValidationResult> validationResults);
            return validationResults;
        }
    }
}
