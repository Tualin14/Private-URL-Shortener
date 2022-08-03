(() => {
  // src/token/murmurhash3.ts
  function hash32(key, seed = 0) {
    let i;
    let remainder = key.length % 4;
    let bytes = key.length - remainder;
    let h1 = seed;
    let k1 = 0;
    const c1 = 3432918353;
    const c2 = 461845907;
    for (i = 0; i < bytes; i = i + 4) {
      k1 = key.charCodeAt(i) & 255 | (key.charCodeAt(i + 1) & 255) << 8 | (key.charCodeAt(i + 2) & 255) << 16 | (key.charCodeAt(i + 3) & 255) << 24;
      k1 = _x86Multiply(k1, c1);
      k1 = _x86Rotl(k1, 15);
      k1 = _x86Multiply(k1, c2);
      h1 ^= k1;
      h1 = _x86Rotl(h1, 13);
      h1 = _x86Multiply(h1, 5) + 3864292196;
    }
    k1 = 0;
    switch (remainder) {
      case 3:
        k1 ^= (key.charCodeAt(i + 2) & 255) << 16;
        break;
      case 2:
        k1 ^= (key.charCodeAt(i + 1) & 255) << 8;
        break;
      case 1:
        k1 ^= key.charCodeAt(i) & 255;
        k1 = _x86Multiply(k1, c1);
        k1 = _x86Rotl(k1, 15);
        k1 = _x86Multiply(k1, c2);
        h1 ^= k1;
    }
    h1 ^= key.length;
    h1 = _x86Fmix(h1);
    return h1 >>> 0;
  }
  function _x86Multiply(m, n) {
    return (m & 65535) * n + (((m >>> 16) * n & 65535) << 16);
  }
  function _x86Rotl(m, n) {
    return m << n | m >>> 32 - n;
  }
  function _x86Fmix(h) {
    h ^= h >>> 16;
    h = _x86Multiply(h, 2246822507);
    h ^= h >>> 13;
    h = _x86Multiply(h, 3266489909);
    h ^= h >>> 16;
    return h;
  }

  // src/token/index.ts
  async function tokenGenerate(lurl) {
    let num = hash32(lurl, SEED);
    let token = to58(num);
    return token;
  }
  async function to58(num) {
    const s58 = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    let token = "";
    while (num) {
      token = s58.charAt(num % 58) + token;
      num = Math.floor(num / 58);
    }
    return token;
  }

  // src/totp/index.ts
  var Totp = class {
    constructor(expiry = 30, length = 6) {
      this.expiry = expiry;
      this.length = length;
      if (this.length > 8 || this.length < 6) {
        throw "Error: invalid code length";
      }
    }
    dec2hex(s) {
      return (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
    }
    hex2dec(s) {
      return parseInt(s, 16);
    }
    base32tohex(base32) {
      let base32chars, bits, chunk, hex, i, val;
      base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      bits = "";
      hex = "";
      i = 0;
      while (i < base32.length) {
        val = base32chars.indexOf(base32.charAt(i).toUpperCase());
        bits += this.leftpad(val.toString(2), 5, "0");
        i++;
      }
      i = 0;
      while (i + 4 <= bits.length) {
        chunk = bits.substr(i, 4);
        hex = hex + parseInt(chunk, 2).toString(16);
        i += 4;
      }
      return hex;
    }
    leftpad(str, len, pad) {
      if (len + 1 >= str.length) {
        str = Array(len + 1 - str.length).join(pad) + str;
      }
      return str;
    }
    getOtp(secret, now = new Date().getTime()) {
      let epoch, hmac, key, offset, otp, shaObj, time;
      key = this.base32tohex(secret);
      epoch = Math.round(now / 1e3);
      time = this.leftpad(this.dec2hex(Math.floor(epoch / this.expiry)), 16, "0");
      shaObj = new jsSHA("SHA-1", "HEX");
      shaObj.setHMACKey(key, "HEX");
      shaObj.update(time);
      hmac = shaObj.getHMAC("HEX");
      if (hmac === "KEY MUST BE IN BYTE INCREMENTS") {
        throw "Error: hex key must be in byte increments";
      } else {
        offset = this.hex2dec(hmac.substring(hmac.length - 1));
      }
      otp = (this.hex2dec(hmac.substr(offset * 2, 8)) & this.hex2dec("7fffffff")) + "";
      if (otp.length > this.length) {
        otp = otp.substr(otp.length - this.length, this.length);
      } else {
        otp = this.leftpad(otp, this.length, "0");
      }
      return otp;
    }
    getOtp1(secret, now = new Date().getTime() - 3e4) {
      return this.getOtp(secret, now);
    }
  };
  var SUPPORTED_ALGS = 4 | 2 | 1;
  var Int_64 = class {
    constructor(msint_32, lsint_32) {
      this.highOrder = msint_32;
      this.lowOrder = lsint_32;
    }
  };
  function str2binb(str, utfType, existingBin = [0], existingBinLen = 0) {
    let bin = [], codePnt, binArr = [], byteCnt = 0, i, j, existingByteLen, intOffset, byteOffset;
    bin = existingBin || [0];
    existingBinLen = existingBinLen || 0;
    existingByteLen = existingBinLen >>> 3;
    if (utfType === "UTF8") {
      for (i = 0; i < str.length; i += 1) {
        codePnt = str.charCodeAt(i);
        binArr = [];
        if (128 > codePnt) {
          binArr.push(codePnt);
        } else if (2048 > codePnt) {
          binArr.push(192 | codePnt >>> 6);
          binArr.push(128 | codePnt & 63);
        } else if (55296 > codePnt || 57344 <= codePnt) {
          binArr.push(224 | codePnt >>> 12, 128 | codePnt >>> 6 & 63, 128 | codePnt & 63);
        } else {
          i += 1;
          codePnt = 65536 + ((codePnt & 1023) << 10 | str.charCodeAt(i) & 1023);
          binArr.push(240 | codePnt >>> 18, 128 | codePnt >>> 12 & 63, 128 | codePnt >>> 6 & 63, 128 | codePnt & 63);
        }
        for (j = 0; j < binArr.length; j += 1) {
          byteOffset = byteCnt + existingByteLen;
          intOffset = byteOffset >>> 2;
          while (bin.length <= intOffset) {
            bin.push(0);
          }
          bin[intOffset] |= binArr[j] << 8 * (3 - byteOffset % 4);
          byteCnt += 1;
        }
      }
    } else if (utfType === "UTF16BE" || utfType === "UTF16LE") {
      for (i = 0; i < str.length; i += 1) {
        codePnt = str.charCodeAt(i);
        if (utfType === "UTF16LE") {
          j = codePnt & 255;
          codePnt = j << 8 | codePnt >>> 8;
        }
        byteOffset = byteCnt + existingByteLen;
        intOffset = byteOffset >>> 2;
        while (bin.length <= intOffset) {
          bin.push(0);
        }
        bin[intOffset] |= codePnt << 8 * (2 - byteOffset % 4);
        byteCnt += 2;
      }
    }
    return { "value": bin, "binLen": byteCnt * 8 + existingBinLen };
  }
  function hex2binb(str, existingBin, existingBinLen) {
    let bin, length = str.length, i, num, intOffset, byteOffset, existingByteLen;
    bin = existingBin || [0];
    existingBinLen = existingBinLen || 0;
    existingByteLen = existingBinLen >>> 3;
    if (length % 2 !== 0) {
      throw new Error("String of HEX type must be in byte increments");
    }
    for (i = 0; i < length; i += 2) {
      num = parseInt(str.substr(i, 2), 16);
      if (!isNaN(num)) {
        byteOffset = (i >>> 1) + existingByteLen;
        intOffset = byteOffset >>> 2;
        while (bin.length <= intOffset) {
          bin.push(0);
        }
        bin[intOffset] |= num << 8 * (3 - byteOffset % 4);
      } else {
        throw new Error("String of HEX type contains invalid characters");
      }
    }
    return { "value": bin, "binLen": length * 4 + existingBinLen };
  }
  function bytes2binb(str, existingBin, existingBinLen) {
    let bin = [], codePnt, i, existingByteLen, intOffset, byteOffset;
    bin = existingBin || [0];
    existingBinLen = existingBinLen || 0;
    existingByteLen = existingBinLen >>> 3;
    for (i = 0; i < str.length; i += 1) {
      codePnt = str.charCodeAt(i);
      byteOffset = i + existingByteLen;
      intOffset = byteOffset >>> 2;
      if (bin.length <= intOffset) {
        bin.push(0);
      }
      bin[intOffset] |= codePnt << 8 * (3 - byteOffset % 4);
    }
    return { "value": bin, "binLen": str.length * 8 + existingBinLen };
  }
  function b642binb(str, existingBin, existingBinLen) {
    let bin = [], byteCnt = 0, index, i, j, tmpInt, strPart, firstEqual, b64Tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", existingByteLen, intOffset, byteOffset;
    bin = existingBin || [0];
    existingBinLen = existingBinLen || 0;
    existingByteLen = existingBinLen >>> 3;
    if (str.search(/^[a-zA-Z0-9=+\/]+$/) === -1) {
      throw new Error("Invalid character in base-64 string");
    }
    firstEqual = str.indexOf("=");
    str = str.replace(/\=/g, "");
    if (firstEqual !== -1 && firstEqual < str.length) {
      throw new Error("Invalid '=' found in base-64 string");
    }
    for (i = 0; i < str.length; i += 4) {
      strPart = str.substr(i, 4);
      tmpInt = 0;
      for (j = 0; j < strPart.length; j += 1) {
        index = b64Tab.indexOf(strPart[j]);
        tmpInt |= index << 18 - 6 * j;
      }
      for (j = 0; j < strPart.length - 1; j += 1) {
        byteOffset = byteCnt + existingByteLen;
        intOffset = byteOffset >>> 2;
        while (bin.length <= intOffset) {
          bin.push(0);
        }
        bin[intOffset] |= (tmpInt >>> 16 - j * 8 & 255) << 8 * (3 - byteOffset % 4);
        byteCnt += 1;
      }
    }
    return { "value": bin, "binLen": byteCnt * 8 + existingBinLen };
  }
  function binb2hex(binarray, formatOpts) {
    let hex_tab = "0123456789abcdef", str = "", length = binarray.length * 4, i, srcByte;
    for (i = 0; i < length; i += 1) {
      srcByte = binarray[i >>> 2] >>> (3 - i % 4) * 8;
      str += hex_tab.charAt(srcByte >>> 4 & 15) + hex_tab.charAt(srcByte & 15);
    }
    return formatOpts["outputUpper"] ? str.toUpperCase() : str;
  }
  function binb2b64(binarray, formatOpts) {
    let str = "", length = binarray.length * 4, i, j, triplet, offset, int1, int2, b64Tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (i = 0; i < length; i += 3) {
      offset = i + 1 >>> 2;
      int1 = binarray.length <= offset ? 0 : binarray[offset];
      offset = i + 2 >>> 2;
      int2 = binarray.length <= offset ? 0 : binarray[offset];
      triplet = (binarray[i >>> 2] >>> 8 * (3 - i % 4) & 255) << 16 | (int1 >>> 8 * (3 - (i + 1) % 4) & 255) << 8 | int2 >>> 8 * (3 - (i + 2) % 4) & 255;
      for (j = 0; j < 4; j += 1) {
        if (i * 8 + j * 6 <= binarray.length * 32) {
          str += b64Tab.charAt(triplet >>> 6 * (3 - j) & 63);
        } else {
          str += formatOpts["b64Pad"];
        }
      }
    }
    return str;
  }
  function binb2bytes(binarray) {
    let str = "", length = binarray.length * 4, i, srcByte;
    for (i = 0; i < length; i += 1) {
      srcByte = binarray[i >>> 2] >>> (3 - i % 4) * 8 & 255;
      str += String.fromCharCode(srcByte);
    }
    return str;
  }
  function getOutputOpts(options = {}) {
    let retVal = { "outputUpper": false, "b64Pad": "=" }, outputOptions;
    outputOptions = options || {};
    retVal["outputUpper"] = outputOptions["outputUpper"] || false;
    retVal["b64Pad"] = outputOptions["b64Pad"] || "=";
    if (typeof retVal["outputUpper"] !== "boolean") {
      throw new Error("Invalid outputUpper formatting option");
    }
    if (typeof retVal["b64Pad"] !== "string") {
      throw new Error("Invalid b64Pad formatting option");
    }
    return retVal;
  }
  function getStrConverter(format, utfType) {
    let retVal;
    switch (utfType) {
      case "UTF8":
      case "UTF16BE":
      case "UTF16LE":
        break;
      default:
        throw new Error("encoding must be UTF8, UTF16BE, or UTF16LE");
    }
    switch (format) {
      case "HEX":
        retVal = hex2binb;
        break;
      case "TEXT":
        retVal = function(str, existingBin = [0], existingBinLen = 0) {
          return str2binb(str, utfType, existingBin, existingBinLen);
        };
        break;
      case "B64":
        retVal = b642binb;
        break;
      case "BYTES":
        retVal = bytes2binb;
        break;
      default:
        throw new Error("format must be HEX, TEXT, B64, or BYTES");
    }
    return retVal;
  }
  function rotl_32(x, n) {
    return x << n | x >>> 32 - n;
  }
  function rotr_32(x, n) {
    return x >>> n | x << 32 - n;
  }
  function rotr_64(x, n) {
    let retVal = null, tmp = new Int_64(x.highOrder, x.lowOrder);
    if (32 >= n) {
      retVal = new Int_64(tmp.highOrder >>> n | tmp.lowOrder << 32 - n & 4294967295, tmp.lowOrder >>> n | tmp.highOrder << 32 - n & 4294967295);
    } else {
      retVal = new Int_64(tmp.lowOrder >>> n - 32 | tmp.highOrder << 64 - n & 4294967295, tmp.highOrder >>> n - 32 | tmp.lowOrder << 64 - n & 4294967295);
    }
    return retVal;
  }
  function shr_32(x, n) {
    return x >>> n;
  }
  function shr_64(x, n) {
    let retVal = null;
    if (32 >= n) {
      retVal = new Int_64(x.highOrder >>> n, x.lowOrder >>> n | x.highOrder << 32 - n & 4294967295);
    } else {
      retVal = new Int_64(0, x.highOrder >>> n - 32);
    }
    return retVal;
  }
  function parity_32(x, y, z) {
    return x ^ y ^ z;
  }
  function ch_32(x, y, z) {
    return x & y ^ ~x & z;
  }
  function ch_64(x, y, z) {
    return new Int_64(x.highOrder & y.highOrder ^ ~x.highOrder & z.highOrder, x.lowOrder & y.lowOrder ^ ~x.lowOrder & z.lowOrder);
  }
  function maj_32(x, y, z) {
    return x & y ^ x & z ^ y & z;
  }
  function maj_64(x, y, z) {
    return new Int_64(x.highOrder & y.highOrder ^ x.highOrder & z.highOrder ^ y.highOrder & z.highOrder, x.lowOrder & y.lowOrder ^ x.lowOrder & z.lowOrder ^ y.lowOrder & z.lowOrder);
  }
  function sigma0_32(x) {
    return rotr_32(x, 2) ^ rotr_32(x, 13) ^ rotr_32(x, 22);
  }
  function sigma0_64(x) {
    let rotr28 = rotr_64(x, 28), rotr34 = rotr_64(x, 34), rotr39 = rotr_64(x, 39);
    return new Int_64(rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder, rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder);
  }
  function sigma1_32(x) {
    return rotr_32(x, 6) ^ rotr_32(x, 11) ^ rotr_32(x, 25);
  }
  function sigma1_64(x) {
    let rotr14 = rotr_64(x, 14), rotr18 = rotr_64(x, 18), rotr41 = rotr_64(x, 41);
    return new Int_64(rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder, rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder);
  }
  function gamma0_32(x) {
    return rotr_32(x, 7) ^ rotr_32(x, 18) ^ shr_32(x, 3);
  }
  function gamma0_64(x) {
    let rotr1 = rotr_64(x, 1), rotr8 = rotr_64(x, 8), shr7 = shr_64(x, 7);
    return new Int_64(rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder, rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder);
  }
  function gamma1_32(x) {
    return rotr_32(x, 17) ^ rotr_32(x, 19) ^ shr_32(x, 10);
  }
  function gamma1_64(x) {
    let rotr19 = rotr_64(x, 19), rotr61 = rotr_64(x, 61), shr6 = shr_64(x, 6);
    return new Int_64(rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder, rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder);
  }
  function safeAdd_32_2(a, b) {
    let lsw = (a & 65535) + (b & 65535), msw = (a >>> 16) + (b >>> 16) + (lsw >>> 16);
    return (msw & 65535) << 16 | lsw & 65535;
  }
  function safeAdd_32_4(a, b, c, d) {
    let lsw = (a & 65535) + (b & 65535) + (c & 65535) + (d & 65535), msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (lsw >>> 16);
    return (msw & 65535) << 16 | lsw & 65535;
  }
  function safeAdd_32_5(a, b, c, d, e) {
    let lsw = (a & 65535) + (b & 65535) + (c & 65535) + (d & 65535) + (e & 65535), msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) + (e >>> 16) + (lsw >>> 16);
    return (msw & 65535) << 16 | lsw & 65535;
  }
  function safeAdd_64_2(x, y) {
    let lsw, msw, lowOrder, highOrder;
    lsw = (x.lowOrder & 65535) + (y.lowOrder & 65535);
    msw = (x.lowOrder >>> 16) + (y.lowOrder >>> 16) + (lsw >>> 16);
    lowOrder = (msw & 65535) << 16 | lsw & 65535;
    lsw = (x.highOrder & 65535) + (y.highOrder & 65535) + (msw >>> 16);
    msw = (x.highOrder >>> 16) + (y.highOrder >>> 16) + (lsw >>> 16);
    highOrder = (msw & 65535) << 16 | lsw & 65535;
    return new Int_64(highOrder, lowOrder);
  }
  function safeAdd_64_4(a, b, c, d) {
    let lsw, msw, lowOrder, highOrder;
    lsw = (a.lowOrder & 65535) + (b.lowOrder & 65535) + (c.lowOrder & 65535) + (d.lowOrder & 65535);
    msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) + (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (lsw >>> 16);
    lowOrder = (msw & 65535) << 16 | lsw & 65535;
    lsw = (a.highOrder & 65535) + (b.highOrder & 65535) + (c.highOrder & 65535) + (d.highOrder & 65535) + (msw >>> 16);
    msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) + (c.highOrder >>> 16) + (d.highOrder >>> 16) + (lsw >>> 16);
    highOrder = (msw & 65535) << 16 | lsw & 65535;
    return new Int_64(highOrder, lowOrder);
  }
  function safeAdd_64_5(a, b, c, d, e) {
    let lsw, msw, lowOrder, highOrder;
    lsw = (a.lowOrder & 65535) + (b.lowOrder & 65535) + (c.lowOrder & 65535) + (d.lowOrder & 65535) + (e.lowOrder & 65535);
    msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) + (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (e.lowOrder >>> 16) + (lsw >>> 16);
    lowOrder = (msw & 65535) << 16 | lsw & 65535;
    lsw = (a.highOrder & 65535) + (b.highOrder & 65535) + (c.highOrder & 65535) + (d.highOrder & 65535) + (e.highOrder & 65535) + (msw >>> 16);
    msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) + (c.highOrder >>> 16) + (d.highOrder >>> 16) + (e.highOrder >>> 16) + (lsw >>> 16);
    highOrder = (msw & 65535) << 16 | lsw & 65535;
    return new Int_64(highOrder, lowOrder);
  }
  function getH(letiant) {
    let retVal, H_trunc, H_full;
    if (letiant === "SHA-1" && 1 & SUPPORTED_ALGS) {
      retVal = [
        1732584193,
        4023233417,
        2562383102,
        271733878,
        3285377520
      ];
    } else if (6 & SUPPORTED_ALGS) {
      H_trunc = [
        3238371032,
        914150663,
        812702999,
        4144912697,
        4290775857,
        1750603025,
        1694076839,
        3204075428
      ];
      H_full = [
        1779033703,
        3144134277,
        1013904242,
        2773480762,
        1359893119,
        2600822924,
        528734635,
        1541459225
      ];
      switch (letiant) {
        case "SHA-224":
          retVal = H_trunc;
          break;
        case "SHA-256":
          retVal = H_full;
          break;
        case "SHA-384":
          retVal = [
            new Int_64(3418070365, H_trunc[0]),
            new Int_64(1654270250, H_trunc[1]),
            new Int_64(2438529370, H_trunc[2]),
            new Int_64(355462360, H_trunc[3]),
            new Int_64(1731405415, H_trunc[4]),
            new Int_64(41048885895, H_trunc[5]),
            new Int_64(3675008525, H_trunc[6]),
            new Int_64(1203062813, H_trunc[7])
          ];
          break;
        case "SHA-512":
          retVal = [
            new Int_64(H_full[0], 4089235720),
            new Int_64(H_full[1], 2227873595),
            new Int_64(H_full[2], 4271175723),
            new Int_64(H_full[3], 1595750129),
            new Int_64(H_full[4], 2917565137),
            new Int_64(H_full[5], 725511199),
            new Int_64(H_full[6], 4215389547),
            new Int_64(H_full[7], 327033209)
          ];
          break;
        default:
          throw new Error("Unknown SHA letiant");
      }
    } else {
      throw new Error("No SHA letiants supported");
    }
    return retVal;
  }
  function roundSHA1(block, H) {
    let W = [], a, b, c, d, e, T, ch = ch_32, parity = parity_32, maj = maj_32, rotl = rotl_32, safeAdd_2 = safeAdd_32_2, t, safeAdd_5 = safeAdd_32_5;
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    for (t = 0; t < 80; t += 1) {
      if (t < 16) {
        W[t] = block[t];
      } else {
        W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
      }
      if (t < 20) {
        T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, 1518500249, W[t]);
      } else if (t < 40) {
        T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 1859775393, W[t]);
      } else if (t < 60) {
        T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, 2400959708, W[t]);
      } else {
        T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 3395469782, W[t]);
      }
      e = d;
      d = c;
      c = rotl(b, 30);
      b = a;
      a = T;
    }
    H[0] = safeAdd_2(a, H[0]);
    H[1] = safeAdd_2(b, H[1]);
    H[2] = safeAdd_2(c, H[2]);
    H[3] = safeAdd_2(d, H[3]);
    H[4] = safeAdd_2(e, H[4]);
    return H;
  }
  function finalizeSHA1(remainder, remainderBinLen, processedBinLen, H) {
    let i, appendedMessageLength, offset;
    offset = (remainderBinLen + 65 >>> 9 << 4) + 15;
    while (remainder.length <= offset) {
      remainder.push(0);
    }
    remainder[remainderBinLen >>> 5] |= 128 << 24 - remainderBinLen % 32;
    remainder[offset] = remainderBinLen + processedBinLen;
    appendedMessageLength = remainder.length;
    for (i = 0; i < appendedMessageLength; i += 16) {
      H = roundSHA1(remainder.slice(i, i + 16), H);
    }
    return H;
  }
  var K_sha2;
  var K_sha512;
  if (6 & SUPPORTED_ALGS) {
    K_sha2 = [
      1116352408,
      1899447441,
      3049323471,
      3921009573,
      961987163,
      1508970993,
      2453635748,
      2870763221,
      3624381080,
      310598401,
      607225278,
      1426881987,
      1925078388,
      2162078206,
      2614888103,
      3248222580,
      3835390401,
      4022224774,
      264347078,
      604807628,
      770255983,
      1249150122,
      1555081692,
      1996064986,
      2554220882,
      2821834349,
      2952996808,
      3210313671,
      3336571891,
      3584528711,
      113926993,
      338241895,
      666307205,
      773529912,
      1294757372,
      1396182291,
      1695183700,
      1986661051,
      2177026350,
      2456956037,
      2730485921,
      2820302411,
      3259730800,
      3345764771,
      3516065817,
      3600352804,
      4094571909,
      275423344,
      430227734,
      506948616,
      659060556,
      883997877,
      958139571,
      1322822218,
      1537002063,
      1747873779,
      1955562222,
      2024104815,
      2227730452,
      2361852424,
      2428436474,
      2756734187,
      3204031479,
      3329325298
    ];
    if (4 & SUPPORTED_ALGS) {
      K_sha512 = [
        new Int_64(K_sha2[0], 3609767458),
        new Int_64(K_sha2[1], 602891725),
        new Int_64(K_sha2[2], 3964484399),
        new Int_64(K_sha2[3], 2173295548),
        new Int_64(K_sha2[4], 4081628472),
        new Int_64(K_sha2[5], 3053834265),
        new Int_64(K_sha2[6], 2937671579),
        new Int_64(K_sha2[7], 3664609560),
        new Int_64(K_sha2[8], 2734883394),
        new Int_64(K_sha2[9], 1164996542),
        new Int_64(K_sha2[10], 1323610764),
        new Int_64(K_sha2[11], 3590304994),
        new Int_64(K_sha2[12], 4068182383),
        new Int_64(K_sha2[13], 991336113),
        new Int_64(K_sha2[14], 633803317),
        new Int_64(K_sha2[15], 3479774868),
        new Int_64(K_sha2[16], 2666613458),
        new Int_64(K_sha2[17], 944711139),
        new Int_64(K_sha2[18], 2341262773),
        new Int_64(K_sha2[19], 2007800933),
        new Int_64(K_sha2[20], 1495990901),
        new Int_64(K_sha2[21], 1856431235),
        new Int_64(K_sha2[22], 3175218132),
        new Int_64(K_sha2[23], 2198950837),
        new Int_64(K_sha2[24], 3999719339),
        new Int_64(K_sha2[25], 766784016),
        new Int_64(K_sha2[26], 2566594879),
        new Int_64(K_sha2[27], 3203337956),
        new Int_64(K_sha2[28], 1034457026),
        new Int_64(K_sha2[29], 2466948901),
        new Int_64(K_sha2[30], 3758326383),
        new Int_64(K_sha2[31], 168717936),
        new Int_64(K_sha2[32], 1188179964),
        new Int_64(K_sha2[33], 1546045734),
        new Int_64(K_sha2[34], 1522805485),
        new Int_64(K_sha2[35], 2643833823),
        new Int_64(K_sha2[36], 2343527390),
        new Int_64(K_sha2[37], 1014477480),
        new Int_64(K_sha2[38], 1206759142),
        new Int_64(K_sha2[39], 344077627),
        new Int_64(K_sha2[40], 1290863460),
        new Int_64(K_sha2[41], 3158454273),
        new Int_64(K_sha2[42], 3505952657),
        new Int_64(K_sha2[43], 106217008),
        new Int_64(K_sha2[44], 3606008344),
        new Int_64(K_sha2[45], 1432725776),
        new Int_64(K_sha2[46], 1467031594),
        new Int_64(K_sha2[47], 851169720),
        new Int_64(K_sha2[48], 3100823752),
        new Int_64(K_sha2[49], 1363258195),
        new Int_64(K_sha2[50], 3750685593),
        new Int_64(K_sha2[51], 3785050280),
        new Int_64(K_sha2[52], 3318307427),
        new Int_64(K_sha2[53], 3812723403),
        new Int_64(K_sha2[54], 2003034995),
        new Int_64(K_sha2[55], 3602036899),
        new Int_64(K_sha2[56], 1575990012),
        new Int_64(K_sha2[57], 1125592928),
        new Int_64(K_sha2[58], 2716904306),
        new Int_64(K_sha2[59], 442776044),
        new Int_64(K_sha2[60], 593698344),
        new Int_64(K_sha2[61], 3733110249),
        new Int_64(K_sha2[62], 2999351573),
        new Int_64(K_sha2[63], 3815920427),
        new Int_64(3391569614, 3928383900),
        new Int_64(3515267271, 566280711),
        new Int_64(3940187606, 3454069534),
        new Int_64(4118630271, 4000239992),
        new Int_64(116418474, 1914138554),
        new Int_64(174292421, 2731055270),
        new Int_64(289380356, 3203993006),
        new Int_64(460393269, 320620315),
        new Int_64(685471733, 587496836),
        new Int_64(852142971, 1086792851),
        new Int_64(1017036298, 365543100),
        new Int_64(1126000580, 2618297676),
        new Int_64(1288033470, 3409855158),
        new Int_64(1501505948, 4234509866),
        new Int_64(1607167915, 987167468),
        new Int_64(1816402316, 1246189591)
      ];
    }
  }
  function roundSHA2(block, H, letiant) {
    let a, b, c, d, e, f, g, h, T1, T2, numRounds, t, binaryStringMult, safeAdd_2, safeAdd_4, safeAdd_5, gamma0, gamma1, sigma0, sigma1, ch, maj, Int, W = [], int1, int2, offset, K;
    if ((letiant === "SHA-224" || letiant === "SHA-256") && 2 & SUPPORTED_ALGS) {
      numRounds = 64;
      binaryStringMult = 1;
      Int = Number;
      safeAdd_2 = safeAdd_32_2;
      safeAdd_4 = safeAdd_32_4;
      safeAdd_5 = safeAdd_32_5;
      gamma0 = gamma0_32;
      gamma1 = gamma1_32;
      sigma0 = sigma0_32;
      sigma1 = sigma1_32;
      maj = maj_32;
      ch = ch_32;
      K = K_sha2;
    } else if ((letiant === "SHA-384" || letiant === "SHA-512") && 4 & SUPPORTED_ALGS) {
      numRounds = 80;
      binaryStringMult = 2;
      Int = Int_64;
      safeAdd_2 = safeAdd_64_2;
      safeAdd_4 = safeAdd_64_4;
      safeAdd_5 = safeAdd_64_5;
      gamma0 = gamma0_64;
      gamma1 = gamma1_64;
      sigma0 = sigma0_64;
      sigma1 = sigma1_64;
      maj = maj_64;
      ch = ch_64;
      K = K_sha512;
    } else {
      throw new Error("Unexpected error in SHA-2 implementation");
    }
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];
    for (t = 0; t < numRounds; t += 1) {
      if (t < 16) {
        offset = t * binaryStringMult;
        int1 = block.length <= offset ? 0 : block[offset];
        int2 = block.length <= offset + 1 ? 0 : block[offset + 1];
        W[t] = new Int(int1, int2);
      } else {
        W[t] = safeAdd_4(gamma1(W[t - 2]), W[t - 7], gamma0(W[t - 15]), W[t - 16]);
      }
      T1 = safeAdd_5(h, sigma1(e), ch(e, f, g), K[t], W[t]);
      T2 = safeAdd_2(sigma0(a), maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = safeAdd_2(d, T1);
      d = c;
      c = b;
      b = a;
      a = safeAdd_2(T1, T2);
    }
    H[0] = safeAdd_2(a, H[0]);
    H[1] = safeAdd_2(b, H[1]);
    H[2] = safeAdd_2(c, H[2]);
    H[3] = safeAdd_2(d, H[3]);
    H[4] = safeAdd_2(e, H[4]);
    H[5] = safeAdd_2(f, H[5]);
    H[6] = safeAdd_2(g, H[6]);
    H[7] = safeAdd_2(h, H[7]);
    return H;
  }
  function finalizeSHA2(remainder, remainderBinLen, processedBinLen, H, letiant) {
    let i, appendedMessageLength, offset, retVal, binaryStringInc;
    if ((letiant === "SHA-224" || letiant === "SHA-256") && 2 & SUPPORTED_ALGS) {
      offset = (remainderBinLen + 65 >>> 9 << 4) + 15;
      binaryStringInc = 16;
    } else if ((letiant === "SHA-384" || letiant === "SHA-512") && 4 & SUPPORTED_ALGS) {
      offset = (remainderBinLen + 129 >>> 10 << 5) + 31;
      binaryStringInc = 32;
    } else {
      throw new Error("Unexpected error in SHA-2 implementation");
    }
    while (remainder.length <= offset) {
      remainder.push(0);
    }
    remainder[remainderBinLen >>> 5] |= 128 << 24 - remainderBinLen % 32;
    remainder[offset] = remainderBinLen + processedBinLen;
    appendedMessageLength = remainder.length;
    for (i = 0; i < appendedMessageLength; i += binaryStringInc) {
      H = roundSHA2(remainder.slice(i, i + binaryStringInc), H, letiant);
    }
    if (letiant === "SHA-224" && 2 & SUPPORTED_ALGS) {
      retVal = [
        H[0],
        H[1],
        H[2],
        H[3],
        H[4],
        H[5],
        H[6]
      ];
    } else if (letiant === "SHA-256" && 2 & SUPPORTED_ALGS) {
      retVal = H;
    } else if (letiant === "SHA-384" && 4 & SUPPORTED_ALGS) {
      retVal = [
        H[0].highOrder,
        H[0].lowOrder,
        H[1].highOrder,
        H[1].lowOrder,
        H[2].highOrder,
        H[2].lowOrder,
        H[3].highOrder,
        H[3].lowOrder,
        H[4].highOrder,
        H[4].lowOrder,
        H[5].highOrder,
        H[5].lowOrder
      ];
    } else if (letiant === "SHA-512" && 4 & SUPPORTED_ALGS) {
      retVal = [
        H[0].highOrder,
        H[0].lowOrder,
        H[1].highOrder,
        H[1].lowOrder,
        H[2].highOrder,
        H[2].lowOrder,
        H[3].highOrder,
        H[3].lowOrder,
        H[4].highOrder,
        H[4].lowOrder,
        H[5].highOrder,
        H[5].lowOrder,
        H[6].highOrder,
        H[6].lowOrder,
        H[7].highOrder,
        H[7].lowOrder
      ];
    } else {
      throw new Error("Unexpected error in SHA-2 implementation");
    }
    return retVal;
  }
  var jsSHA = class {
    constructor(letiant, inputFormat, options = {}) {
      this.processedLen = 0;
      this.remainder = [];
      this.remainderLen = 0;
      this.finalized = false;
      this.hmacKeySet = false;
      this.keyWithIPad = [];
      this.keyWithOPad = [];
      this.updatedCalled = false;
      this.inputOptions = options || {};
      this.utfType = this.inputOptions["encoding"] || "UTF8";
      this.numRounds = this.inputOptions["numRounds"] || 1;
      this.shaletiant = letiant;
      this.converterFunc = getStrConverter(inputFormat, this.utfType);
      if (this.numRounds !== parseInt(this.numRounds, 10) || 1 > this.numRounds) {
        throw new Error("numRounds must a integer >= 1");
      }
      if (this.shaletiant === "SHA-1" && 1 & SUPPORTED_ALGS) {
        this.letiantBlockSize = 512;
        this.roundFunc = roundSHA1;
        this.finalizeFunc = finalizeSHA1;
        this.outputBinLen = 160;
      } else {
        if (6 & SUPPORTED_ALGS) {
          this.roundFunc = function(block, H) {
            return roundSHA2(block, H, this.shaletiant);
          };
          this.finalizeFunc = function(remainder, remainderBinLen, processedBinLen, H) {
            return finalizeSHA2(remainder, remainderBinLen, processedBinLen, H, this.shaletiant);
          };
        }
        if (this.shaletiant === "SHA-224" && 2 & SUPPORTED_ALGS) {
          this.letiantBlockSize = 512;
          this.outputBinLen = 224;
        } else if (this.shaletiant === "SHA-256" && 2 & SUPPORTED_ALGS) {
          this.letiantBlockSize = 512;
          this.outputBinLen = 256;
        } else if (this.shaletiant === "SHA-384" && 4 & SUPPORTED_ALGS) {
          this.letiantBlockSize = 1024;
          this.outputBinLen = 384;
        } else if (this.shaletiant === "SHA-512" && 4 & SUPPORTED_ALGS) {
          this.letiantBlockSize = 1024;
          this.outputBinLen = 512;
        } else {
          throw new Error("Chosen SHA letiant is not supported");
        }
      }
      this.intermediateH = getH(this.shaletiant);
    }
    setHMACKey(key, inputFormat, options = {}) {
      let keyConverterFunc, convertRet, keyBinLen, keyToUse, blockByteSize, i, lastArrayIndex, keyOptions;
      if (this.hmacKeySet) {
        throw new Error("HMAC key already set");
      }
      if (this.finalized) {
        throw new Error("Cannot set HMAC key after finalizing hash");
      }
      if (this.updatedCalled) {
        throw new Error("Cannot set HMAC key after calling update");
      }
      keyOptions = options || {};
      this.utfType = keyOptions["encoding"] || "UTF8";
      keyConverterFunc = getStrConverter(inputFormat, this.utfType);
      convertRet = keyConverterFunc(key);
      keyBinLen = convertRet["binLen"];
      keyToUse = convertRet["value"];
      blockByteSize = this.letiantBlockSize >>> 3;
      lastArrayIndex = blockByteSize / 4 - 1;
      if (blockByteSize < keyBinLen / 8) {
        keyToUse = this.finalizeFunc(keyToUse, keyBinLen, 0, getH(this.shaletiant));
        while (keyToUse.length <= lastArrayIndex) {
          keyToUse.push(0);
        }
        keyToUse[lastArrayIndex] &= 4294967040;
      } else if (blockByteSize > keyBinLen / 8) {
        while (keyToUse.length <= lastArrayIndex) {
          keyToUse.push(0);
        }
        keyToUse[lastArrayIndex] &= 4294967040;
      }
      for (i = 0; i <= lastArrayIndex; i += 1) {
        this.keyWithIPad[i] = keyToUse[i] ^ 909522486;
        this.keyWithOPad[i] = keyToUse[i] ^ 1549556828;
      }
      this.intermediateH = this.roundFunc(this.keyWithIPad, this.intermediateH);
      this.processedLen = this.letiantBlockSize;
      this.hmacKeySet = true;
    }
    update(srcString) {
      let convertRet, chunkBinLen, chunkIntLen, chunk, i, updateProcessedLen = 0, letiantBlockIntInc = this.letiantBlockSize >>> 5;
      convertRet = this.converterFunc(srcString, this.remainder, this.remainderLen);
      chunkBinLen = convertRet["binLen"];
      chunk = convertRet["value"];
      chunkIntLen = chunkBinLen >>> 5;
      for (i = 0; i < chunkIntLen; i += letiantBlockIntInc) {
        if (updateProcessedLen + this.letiantBlockSize <= chunkBinLen) {
          this.intermediateH = this.roundFunc(chunk.slice(i, i + letiantBlockIntInc), this.intermediateH);
          updateProcessedLen += this.letiantBlockSize;
        }
      }
      this.processedLen += updateProcessedLen;
      this.remainder = chunk.slice(updateProcessedLen >>> 5);
      this.remainderLen = chunkBinLen % this.letiantBlockSize;
      this.updatedCalled = true;
    }
    getHMAC(format, options = {}) {
      let formatFunc, firstHash, outputOptions;
      if (!this.hmacKeySet) {
        throw new Error("Cannot call getHMAC without first setting HMAC key");
      }
      outputOptions = getOutputOpts(options);
      switch (format) {
        case "HEX":
          formatFunc = function(binarray) {
            return binb2hex(binarray, outputOptions);
          };
          break;
        case "B64":
          formatFunc = function(binarray) {
            return binb2b64(binarray, outputOptions);
          };
          break;
        case "BYTES":
          formatFunc = binb2bytes;
          break;
        default:
          throw new Error("outputFormat must be HEX, B64, or BYTES");
      }
      if (!this.finalized) {
        firstHash = this.finalizeFunc(this.remainder, this.remainderLen, this.processedLen, this.intermediateH);
        this.intermediateH = this.roundFunc(this.keyWithOPad, getH(this.shaletiant));
        this.intermediateH = this.finalizeFunc(firstHash, this.outputBinLen, this.letiantBlockSize, this.intermediateH);
      }
      this.finalized = true;
      return formatFunc(this.intermediateH);
    }
  };

  // src/handler.ts
  var urlp = /^(https?:\/\/)([0-9a-z.]+)/i;
  var html = `<!DOCTYPE html><html lang="en"><head><link href="https://cdn.jsdelivr.net/npm/daisyui@2.18.0/dist/full.css"rel="stylesheet"type="text/css"/><script src="https://cdn.tailwindcss.com"><\/script><script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"><\/script><script src="https://cdn.jsdelivr.net/npm/theme-change@2.0.2/index.js"><\/script><title>SURL</title></head><body><div class="hero min-h-screen bg-base-200"><div class="hero-content text-center w-full"><div class="card flex-shrink-0 w-full shadow-2xl bg-base-100"><div class="card-body"><h1 class="card-title text-4xl"><a href="https://github.com/Tualin14/SURL"target="_blank"><button class="btn btn-square btn-ghost"><svg viewBox="0 0 16 16"fill="currentColor"><path fill-rule="evenodd"d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg></button></a>SURL</h1><!--theme--><div class="card-actions justify-end"><button data-set-theme="corporate"data-act-class="ACTIVECLASS"class="btn btn-square btn-ghost"><svg xmlns="http://www.w3.org/2000/svg"viewBox="0 0 20 20"fill="currentColor"><path fillRule="evenodd"d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"clipRule="evenodd"/></svg></button><button data-set-theme="dark"data-act-class="ACTIVECLASS"class="btn btn-square btn-ghost"><svg xmlns="http://www.w3.org/2000/svg"viewBox="0 0 20 20"fill="currentColor"><path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"/></svg></button></div><div class="form-control"><label class="label"><span class="label-text">Data</span></label><input type="text"id="data"class="input input-bordered"/></div><div class="form-control"><label class="label"><span class="label-text">totp Token</span></label><div class="input-group"><input type="text"id="totpToken"class="input input-bordered w-full"/><button class="btn btn-primary w-40"onclick="getSurl()">Get SURL</button></div></div><div class="form-control"><label class="label"><span class="label-text">SURL</span></label><div class="input-group"><input type="text"id="copyInput"class="input input-bordered w-full"/><button class="btn w-40"id="copyButton"disabled="disabled"onclick='copyToClipboard()'>Copy!</button></div></div></div></div></div></div><script type="text/javascript">function getSurl(){let data=document.getElementById("data").value;let totpToken=document.getElementById("totpToken").value;let copyInput=document.getElementById("copyInput");let copyButton=document.getElementById("copyButton");copyButton.className="btn w-40";copyButton.setAttribute("disabled","disabled");axios.post("/",{data:data,totpToken:totpToken,}).then(function(res){let resData=res.data;copyInput.value=window.location.origin+res.data;copyButton.className+=" btn-success";copyButton.removeAttribute("disabled")}).catch(function(error){copyInput.value="No permission"})}function copyToClipboard(){let copyInput=document.getElementById("copyInput");navigator.clipboard.writeText(copyInput.value)}<\/script></body></html>`;
  async function handleRequest(request) {
    if (request.method == "POST") {
      let { data, totpToken } = await request.json();
      let totp = new Totp();
      console.log(totp.getOtp(TotpKey));
      console.log(totp.getOtp1(TotpKey));
      if (totpToken != totp.getOtp(TotpKey) && totpToken != totp.getOtp1(TotpKey)) {
        return new Response("No permission", { status: 403 });
      }
      let token2 = await tokenGenerate(data);
      let dataGet = await SURLKV.get(token2);
      while (dataGet) {
        if (data == dataGet) {
          return new Response(`/${token2}`);
        } else {
          data = `${data}#`;
          token2 = await tokenGenerate(data);
          dataGet = await SURLKV.get(token2);
        }
      }
      await SURLKV.put(token2, data);
      return new Response(`/${token2}`);
    }
    let path_get = new URL(request.url).pathname;
    let token = path_get.substring(1);
    if (token) {
      let dataGet = await SURLKV.get(token);
      if (dataGet) {
        if (urlp.test(dataGet)) {
          return Response.redirect(dataGet, 302);
        }
        return new Response(dataGet);
      }
      return new Response("No found", { status: 404 });
    }
    return new Response(html, {
      headers: {
        "content-type": "text/html;charset=UTF-8"
      }
    });
  }

  // src/index.ts
  addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
  });
})();
//# sourceMappingURL=index.js.map
