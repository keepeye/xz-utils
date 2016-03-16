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
  }
}