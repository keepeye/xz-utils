/**
 * Created by admin on 16/3/13.
 */
"use strict"
var crypto = require('crypto');

module.exports = {
  /**
   * 返回当前时间的unix时间戳
   * @returns {number}
   */
  time: function () {
    return Math.floor(new Date().getTime() / 1000);
  },

  /**
   * md5 加密
   * @param data 待加密字符串
   * @returns {string} 加密结果
   */
  md5: function (data) {
    //字符串先通过buffer转成二进制模式,否则中文加密不对
    var Buffer = require("buffer").Buffer;
    var buf = new Buffer(data);
    var str = buf.toString("binary");
    return crypto.createHash("md5").update(str).digest("hex");
  },

  /**
   * AES加密
   *
   * 基于aes-128-cbc算法
   *
   * @param data 待加密内容,可以是字符串或Buffer,若是字符串需要同时指定inputEncoding
   * @param key 密钥,16位字符串或Buffer
   * @param iv 向量,16位字符串或Buffer
   * @param inputEncoding data的字符串类型,可以是utf8,ascii或binary,如果未指定该项data必须是Buffer
   * @param outputEncoding 返回密文的格式,可以是'binary', 'base64' 或者 'hex',若未指定则返回Buffer
   * @returns (Buffer|String) 密文
   */
  aesEncrypt: function (data, key, iv, inputEncoding, outputEncoding,zeroPadding) {
    //非buffer转成buffer对象
    if (!(data instanceof Buffer)){
      data = new Buffer(data,inputEncoding);
    }
    var cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    //关闭自动补码,使用0x0进行补码
    if (zeroPadding == true) {
      cipher.setAutoPadding(false);
      var padding = new Array(128 - data.length % 128);
      padding.fill(0x0);
      data = Buffer.concat([data,new Buffer(padding)]);
    }
    var bufArr = [cipher.update(data)];
    bufArr.push(cipher.final());
    var encrypted = Buffer.concat(bufArr);
    if (outputEncoding == 'binary' || outputEncoding == 'hex' || outputEncoding == 'base64') {
      return encrypted.toString(outputEncoding);
    } else {
      return encrypted;
    }
  },

  /**
   * AES解密
   *
   * 基于aes-128-cbc算法
   *
   * @param data 待解密内容,可以是字符串或Buffer,若是字符串需要同时指定inputEncoding
   * @param key 密钥,16位字符串或Buffer
   * @param iv 向量,16位字符串或Buffer
   * @param inputEncoding data的字符串类型,可以是'binary', 'base64' 或者 'hex',如果未指定该项data必须是Buffer
   * @param outputEncoding 返回密文的格式,可以是'binary', 'ascii' 或者 'utf8',若未指定则返回Buffer
   * @returns (Buffer|String) 明文
   */
  aesDecrypt: function (data, key, iv, inputEncoding, outputEncoding,zeroPadding) {
    var decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    if (zeroPadding == true) {
      decipher.setAutoPadding(false)
    }
    var bufArr = [decipher.update(data, inputEncoding)];
    bufArr.push(decipher.final());
    var decrypted = Buffer.concat(bufArr);
    if (outputEncoding == 'binary' || outputEncoding == 'ascii' || outputEncoding == 'utf8') {
      return decrypted.toString(outputEncoding);
    } else {
      return decrypted;
    }
  }
}