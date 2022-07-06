export default class Totp {
    expiry
    length

    constructor(expiry = 30, length = 6) {
        this.expiry = expiry;
        this.length = length;
        if (this.length > 8 || this.length < 6) {
            throw "Error: invalid code length";
        }
    }

    dec2hex(s: any) {
        return (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
    }

    hex2dec(s: any) {
        return parseInt(s, 16);
    }

    base32tohex(base32: any) {
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

    leftpad(str: any, len: any, pad: any) {
        if (len + 1 >= str.length) {
            str = Array(len + 1 - str.length).join(pad) + str;
        }
        return str;
    }

    getOtp(secret: any, now = new Date().getTime()) {
        let epoch, hmac, key, offset, otp, shaObj, time;
        key = this.base32tohex(secret);
        epoch = Math.round(now / 1000.0);
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

    getOtp1(secret: any, now = new Date().getTime() - 30000) {
        return this.getOtp(secret, now)
    }

};

let SUPPORTED_ALGS = 4 | 2 | 1;

class Int_64 {
    highOrder: any
    lowOrder: any

    constructor(msint_32: any, lsint_32: any) {
        this.highOrder = msint_32;
        this.lowOrder = lsint_32;
    }
}

function str2binb(str: any, utfType: any, existingBin: any = [0], existingBinLen: any = 0) {
    let bin = [], codePnt, binArr = [], byteCnt = 0, i, j, existingByteLen,
        intOffset, byteOffset;

    bin = existingBin || [0];
    existingBinLen = existingBinLen || 0;
    existingByteLen = existingBinLen >>> 3;

    if ("UTF8" === utfType) {
        for (i = 0; i < str.length; i += 1) {
            codePnt = str.charCodeAt(i);
            binArr = [];

            if (0x80 > codePnt) {
                binArr.push(codePnt);
            } else if (0x800 > codePnt) {
                binArr.push(0xC0 | (codePnt >>> 6));
                binArr.push(0x80 | (codePnt & 0x3F));
            } else if ((0xd800 > codePnt) || (0xe000 <= codePnt)) {
                binArr.push(
                    0xe0 | (codePnt >>> 12),
                    0x80 | ((codePnt >>> 6) & 0x3f),
                    0x80 | (codePnt & 0x3f)
                );
            } else {
                i += 1;
                codePnt = 0x10000 + (((codePnt & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
                binArr.push(
                    0xf0 | (codePnt >>> 18),
                    0x80 | ((codePnt >>> 12) & 0x3f),
                    0x80 | ((codePnt >>> 6) & 0x3f),
                    0x80 | (codePnt & 0x3f)
                );
            }

            for (j = 0; j < binArr.length; j += 1) {
                byteOffset = byteCnt + existingByteLen;
                intOffset = byteOffset >>> 2;
                while (bin.length <= intOffset) {
                    bin.push(0);
                }
                bin[intOffset] |= binArr[j] << (8 * (3 - (byteOffset % 4)));
                byteCnt += 1;
            }
        }
    } else if (("UTF16BE" === utfType) || "UTF16LE" === utfType) {
        for (i = 0; i < str.length; i += 1) {
            codePnt = str.charCodeAt(i);
            if ("UTF16LE" === utfType) {
                j = codePnt & 0xFF;
                codePnt = (j << 8) | (codePnt >>> 8);
            }
            byteOffset = byteCnt + existingByteLen;
            intOffset = byteOffset >>> 2;
            while (bin.length <= intOffset) {
                bin.push(0);
            }
            bin[intOffset] |= codePnt << (8 * (2 - (byteOffset % 4)));
            byteCnt += 2;
        }
    }
    return {"value": bin, "binLen": byteCnt * 8 + existingBinLen};
}

function hex2binb(str: any, existingBin: any, existingBinLen: any) {
    let bin, length = str.length, i, num, intOffset, byteOffset,
        existingByteLen;

    bin = existingBin || [0];
    existingBinLen = existingBinLen || 0;
    existingByteLen = existingBinLen >>> 3;

    if (0 !== (length % 2)) {
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
            bin[intOffset] |= num << 8 * (3 - (byteOffset % 4));
        } else {
            throw new Error("String of HEX type contains invalid characters");
        }
    }

    return {"value": bin, "binLen": length * 4 + existingBinLen};
}


function bytes2binb(str: any, existingBin: any, existingBinLen: any) {
    let bin = [], codePnt, i, existingByteLen, intOffset,
        byteOffset;

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
        bin[intOffset] |= codePnt << 8 * (3 - (byteOffset % 4));
    }
    return {"value": bin, "binLen": str.length * 8 + existingBinLen};
}


function b642binb(str: any, existingBin: any, existingBinLen: any) {
    let bin = [], byteCnt = 0, index, i, j, tmpInt, strPart, firstEqual,
        b64Tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        existingByteLen, intOffset, byteOffset;

    bin = existingBin || [0];
    existingBinLen = existingBinLen || 0;
    existingByteLen = existingBinLen >>> 3;

    if (-1 === str.search(/^[a-zA-Z0-9=+\/]+$/)) {
        throw new Error("Invalid character in base-64 string");
    }
    firstEqual = str.indexOf('=');
    str = str.replace(/\=/g, '');
    if ((-1 !== firstEqual) && (firstEqual < str.length)) {
        throw new Error("Invalid '=' found in base-64 string");
    }

    for (i = 0; i < str.length; i += 4) {
        strPart = str.substr(i, 4);
        tmpInt = 0;

        for (j = 0; j < strPart.length; j += 1) {
            index = b64Tab.indexOf(strPart[j]);
            tmpInt |= index << (18 - (6 * j));
        }

        for (j = 0; j < strPart.length - 1; j += 1) {
            byteOffset = byteCnt + existingByteLen;
            intOffset = byteOffset >>> 2;
            while (bin.length <= intOffset) {
                bin.push(0);
            }
            bin[intOffset] |= ((tmpInt >>> (16 - (j * 8))) & 0xFF) <<
                8 * (3 - (byteOffset % 4));
            byteCnt += 1;
        }
    }
    return {"value": bin, "binLen": byteCnt * 8 + existingBinLen};
}


function binb2hex(binarray: any, formatOpts: any) {
    let hex_tab = "0123456789abcdef", str = "",
        length = binarray.length * 4, i, srcByte;

    for (i = 0; i < length; i += 1) {
        /* The below is more than a byte but it gets taken care of later */
        srcByte = binarray[i >>> 2] >>> ((3 - (i % 4)) * 8);
        str += hex_tab.charAt((srcByte >>> 4) & 0xF) +
            hex_tab.charAt(srcByte & 0xF);
    }

    return (formatOpts["outputUpper"]) ? str.toUpperCase() : str;
}


function binb2b64(binarray: any, formatOpts: any) {
    let str = "", length = binarray.length * 4, i, j, triplet, offset, int1, int2,
        b64Tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for (i = 0; i < length; i += 3) {
        offset = (i + 1) >>> 2;
        int1 = (binarray.length <= offset) ? 0 : binarray[offset];
        offset = (i + 2) >>> 2;
        int2 = (binarray.length <= offset) ? 0 : binarray[offset];
        triplet = (((binarray[i >>> 2] >>> 8 * (3 - i % 4)) & 0xFF) << 16) |
            (((int1 >>> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8) |
            ((int2 >>> 8 * (3 - (i + 2) % 4)) & 0xFF);
        for (j = 0; j < 4; j += 1) {
            if (i * 8 + j * 6 <= binarray.length * 32) {
                str += b64Tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
            } else {
                str += formatOpts["b64Pad"];
            }
        }
    }
    return str;
}


function binb2bytes(binarray: any) {
    let str = "", length = binarray.length * 4, i, srcByte;

    for (i = 0; i < length; i += 1) {
        srcByte = (binarray[i >>> 2] >>> ((3 - (i % 4)) * 8)) & 0xFF;
        str += String.fromCharCode(srcByte);
    }

    return str;
}


function getOutputOpts(options: any = {}) {
    let retVal = {"outputUpper": false, "b64Pad": "="}, outputOptions;
    outputOptions = options || {};

    retVal["outputUpper"] = outputOptions["outputUpper"] || false;
    retVal["b64Pad"] = outputOptions["b64Pad"] || "=";

    if ("boolean" !== typeof (retVal["outputUpper"])) {
        throw new Error("Invalid outputUpper formatting option");
    }

    if ("string" !== typeof (retVal["b64Pad"])) {
        throw new Error("Invalid b64Pad formatting option");
    }

    return retVal;
}


function getStrConverter(format: any, utfType: any) {
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
            retVal = function (str: any, existingBin: any = [0], existingBinLen: any = 0) {
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


function rotl_32(x: any, n: any) {
    return (x << n) | (x >>> (32 - n));
}


function rotr_32(x: any, n: any) {
    return (x >>> n) | (x << (32 - n));
}


function rotr_64(x: any, n: any) {
    let retVal = null, tmp = new Int_64(x.highOrder, x.lowOrder);

    if (32 >= n) {
        retVal = new Int_64(
            (tmp.highOrder >>> n) | ((tmp.lowOrder << (32 - n)) & 0xFFFFFFFF),
            (tmp.lowOrder >>> n) | ((tmp.highOrder << (32 - n)) & 0xFFFFFFFF)
        );
    } else {
        retVal = new Int_64(
            (tmp.lowOrder >>> (n - 32)) | ((tmp.highOrder << (64 - n)) & 0xFFFFFFFF),
            (tmp.highOrder >>> (n - 32)) | ((tmp.lowOrder << (64 - n)) & 0xFFFFFFFF)
        );
    }

    return retVal;
}


function shr_32(x: any, n: any) {
    return x >>> n;
}

function shr_64(x: any, n: any) {
    let retVal = null;

    if (32 >= n) {
        retVal = new Int_64(
            x.highOrder >>> n,
            x.lowOrder >>> n | ((x.highOrder << (32 - n)) & 0xFFFFFFFF)
        );
    } else {
        retVal = new Int_64(
            0,
            x.highOrder >>> (n - 32)
        );
    }

    return retVal;
}

function parity_32(x: any, y: any, z: any) {
    return x ^ y ^ z;
}

function ch_32(x: any, y: any, z: any) {
    return (x & y) ^ (~x & z);
}

function ch_64(x: any, y: any, z: any) {
    return new Int_64(
        (x.highOrder & y.highOrder) ^ (~x.highOrder & z.highOrder),
        (x.lowOrder & y.lowOrder) ^ (~x.lowOrder & z.lowOrder)
    );
}


function maj_32(x: any, y: any, z: any) {
    return (x & y) ^ (x & z) ^ (y & z);
}


function maj_64(x: any, y: any, z: any) {
    return new Int_64(
        (x.highOrder & y.highOrder) ^
        (x.highOrder & z.highOrder) ^
        (y.highOrder & z.highOrder),
        (x.lowOrder & y.lowOrder) ^
        (x.lowOrder & z.lowOrder) ^
        (y.lowOrder & z.lowOrder)
    );
}

function sigma0_32(x: any) {
    return rotr_32(x, 2) ^ rotr_32(x, 13) ^ rotr_32(x, 22);
}


function sigma0_64(x: any) {
    let rotr28 = rotr_64(x, 28), rotr34 = rotr_64(x, 34),
        rotr39 = rotr_64(x, 39);

    return new Int_64(
        rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder,
        rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder);
}

function sigma1_32(x: any) {
    return rotr_32(x, 6) ^ rotr_32(x, 11) ^ rotr_32(x, 25);
}

function sigma1_64(x: any) {
    let rotr14 = rotr_64(x, 14), rotr18 = rotr_64(x, 18),
        rotr41 = rotr_64(x, 41);

    return new Int_64(
        rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder,
        rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder);
}


function gamma0_32(x: any) {
    return rotr_32(x, 7) ^ rotr_32(x, 18) ^ shr_32(x, 3);
}

function gamma0_64(x: any) {
    let rotr1 = rotr_64(x, 1), rotr8 = rotr_64(x, 8), shr7 = shr_64(x, 7);

    return new Int_64(
        rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder,
        rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder
    );
}


function gamma1_32(x: any) {
    return rotr_32(x, 17) ^ rotr_32(x, 19) ^ shr_32(x, 10);
}

function gamma1_64(x: any) {
    let rotr19 = rotr_64(x, 19), rotr61 = rotr_64(x, 61),
        shr6 = shr_64(x, 6);

    return new Int_64(
        rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder,
        rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder
    );
}

function safeAdd_32_2(a: any, b: any) {
    let lsw = (a & 0xFFFF) + (b & 0xFFFF),
        msw = (a >>> 16) + (b >>> 16) + (lsw >>> 16);

    return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
}

function safeAdd_32_4(a: any, b: any, c: any, d: any) {
    let lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF),
        msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) +
            (lsw >>> 16);

    return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
}

function safeAdd_32_5(a: any, b: any, c: any, d: any, e: any) {
    let lsw = (a & 0xFFFF) + (b & 0xFFFF) + (c & 0xFFFF) + (d & 0xFFFF) +
            (e & 0xFFFF),
        msw = (a >>> 16) + (b >>> 16) + (c >>> 16) + (d >>> 16) +
            (e >>> 16) + (lsw >>> 16);

    return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
}


function safeAdd_64_2(x: any, y: any) {
    let lsw, msw, lowOrder, highOrder;

    lsw = (x.lowOrder & 0xFFFF) + (y.lowOrder & 0xFFFF);
    msw = (x.lowOrder >>> 16) + (y.lowOrder >>> 16) + (lsw >>> 16);
    lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

    lsw = (x.highOrder & 0xFFFF) + (y.highOrder & 0xFFFF) + (msw >>> 16);
    msw = (x.highOrder >>> 16) + (y.highOrder >>> 16) + (lsw >>> 16);
    highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

    return new Int_64(highOrder, lowOrder);
}

function safeAdd_64_4(a: any, b: any, c: any, d: any) {
    let lsw, msw, lowOrder, highOrder;

    lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) +
        (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF);
    msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) +
        (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (lsw >>> 16);
    lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

    lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) +
        (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) + (msw >>> 16);
    msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) +
        (c.highOrder >>> 16) + (d.highOrder >>> 16) + (lsw >>> 16);
    highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

    return new Int_64(highOrder, lowOrder);
}

function safeAdd_64_5(a: any, b: any, c: any, d: any, e: any) {
    let lsw, msw, lowOrder, highOrder;

    lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) +
        (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF) +
        (e.lowOrder & 0xFFFF);
    msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) +
        (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (e.lowOrder >>> 16) +
        (lsw >>> 16);
    lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

    lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) +
        (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) +
        (e.highOrder & 0xFFFF) + (msw >>> 16);
    msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) +
        (c.highOrder >>> 16) + (d.highOrder >>> 16) +
        (e.highOrder >>> 16) + (lsw >>> 16);
    highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

    return new Int_64(highOrder, lowOrder);
}


function getH(letiant: any) {
    let retVal, H_trunc, H_full;

    if (("SHA-1" === letiant) && (1 & SUPPORTED_ALGS)) {
        retVal = [
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        ];
    } else if (6 & SUPPORTED_ALGS) {
        H_trunc = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        ];
        H_full = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
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
                    new Int_64(0xcbbb9d5d, H_trunc[0]),
                    new Int_64(0x0629a292a, H_trunc[1]),
                    new Int_64(0x9159015a, H_trunc[2]),
                    new Int_64(0x0152fecd8, H_trunc[3]),
                    new Int_64(0x67332667, H_trunc[4]),
                    new Int_64(0x98eb44a87, H_trunc[5]),
                    new Int_64(0xdb0c2e0d, H_trunc[6]),
                    new Int_64(0x047b5481d, H_trunc[7])
                ];
                break;
            case "SHA-512":
                retVal = [
                    new Int_64(H_full[0], 0xf3bcc908),
                    new Int_64(H_full[1], 0x84caa73b),
                    new Int_64(H_full[2], 0xfe94f82b),
                    new Int_64(H_full[3], 0x5f1d36f1),
                    new Int_64(H_full[4], 0xade682d1),
                    new Int_64(H_full[5], 0x2b3e6c1f),
                    new Int_64(H_full[6], 0xfb41bd6b),
                    new Int_64(H_full[7], 0x137e2179)
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


function roundSHA1(block: any, H: any) {
    let W: any[] = [], a, b, c, d, e, T, ch = ch_32, parity = parity_32,
        maj = maj_32, rotl = rotl_32, safeAdd_2 = safeAdd_32_2, t,
        safeAdd_5 = safeAdd_32_5;

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
            T = safeAdd_5(rotl(a, 5), ch(b, c, d), e, 0x5a827999, W[t]);
        } else if (t < 40) {
            T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 0x6ed9eba1, W[t]);
        } else if (t < 60) {
            T = safeAdd_5(rotl(a, 5), maj(b, c, d), e, 0x8f1bbcdc, W[t]);
        } else {
            T = safeAdd_5(rotl(a, 5), parity(b, c, d), e, 0xca62c1d6, W[t]);
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


function finalizeSHA1(remainder: any, remainderBinLen: any, processedBinLen: any, H: any) {
    let i, appendedMessageLength, offset;
    offset = (((remainderBinLen + 65) >>> 9) << 4) + 15;
    while (remainder.length <= offset) {
        remainder.push(0);
    }
    remainder[remainderBinLen >>> 5] |= 0x80 << (24 - (remainderBinLen % 32));
    remainder[offset] = remainderBinLen + processedBinLen;

    appendedMessageLength = remainder.length;

    for (i = 0; i < appendedMessageLength; i += 16) {
        H = roundSHA1(remainder.slice(i, i + 16), H);
    }

    return H;
}

let K_sha2: any, K_sha512: any;
if (6 & SUPPORTED_ALGS) {
    K_sha2 = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    ];

    if (4 & SUPPORTED_ALGS) {
        K_sha512 = [
            new Int_64(K_sha2[0], 0xd728ae22), new Int_64(K_sha2[1], 0x23ef65cd),
            new Int_64(K_sha2[2], 0xec4d3b2f), new Int_64(K_sha2[3], 0x8189dbbc),
            new Int_64(K_sha2[4], 0xf348b538), new Int_64(K_sha2[5], 0xb605d019),
            new Int_64(K_sha2[6], 0xaf194f9b), new Int_64(K_sha2[7], 0xda6d8118),
            new Int_64(K_sha2[8], 0xa3030242), new Int_64(K_sha2[9], 0x45706fbe),
            new Int_64(K_sha2[10], 0x4ee4b28c), new Int_64(K_sha2[11], 0xd5ffb4e2),
            new Int_64(K_sha2[12], 0xf27b896f), new Int_64(K_sha2[13], 0x3b1696b1),
            new Int_64(K_sha2[14], 0x25c71235), new Int_64(K_sha2[15], 0xcf692694),
            new Int_64(K_sha2[16], 0x9ef14ad2), new Int_64(K_sha2[17], 0x384f25e3),
            new Int_64(K_sha2[18], 0x8b8cd5b5), new Int_64(K_sha2[19], 0x77ac9c65),
            new Int_64(K_sha2[20], 0x592b0275), new Int_64(K_sha2[21], 0x6ea6e483),
            new Int_64(K_sha2[22], 0xbd41fbd4), new Int_64(K_sha2[23], 0x831153b5),
            new Int_64(K_sha2[24], 0xee66dfab), new Int_64(K_sha2[25], 0x2db43210),
            new Int_64(K_sha2[26], 0x98fb213f), new Int_64(K_sha2[27], 0xbeef0ee4),
            new Int_64(K_sha2[28], 0x3da88fc2), new Int_64(K_sha2[29], 0x930aa725),
            new Int_64(K_sha2[30], 0xe003826f), new Int_64(K_sha2[31], 0x0a0e6e70),
            new Int_64(K_sha2[32], 0x46d22ffc), new Int_64(K_sha2[33], 0x5c26c926),
            new Int_64(K_sha2[34], 0x5ac42aed), new Int_64(K_sha2[35], 0x9d95b3df),
            new Int_64(K_sha2[36], 0x8baf63de), new Int_64(K_sha2[37], 0x3c77b2a8),
            new Int_64(K_sha2[38], 0x47edaee6), new Int_64(K_sha2[39], 0x1482353b),
            new Int_64(K_sha2[40], 0x4cf10364), new Int_64(K_sha2[41], 0xbc423001),
            new Int_64(K_sha2[42], 0xd0f89791), new Int_64(K_sha2[43], 0x0654be30),
            new Int_64(K_sha2[44], 0xd6ef5218), new Int_64(K_sha2[45], 0x5565a910),
            new Int_64(K_sha2[46], 0x5771202a), new Int_64(K_sha2[47], 0x32bbd1b8),
            new Int_64(K_sha2[48], 0xb8d2d0c8), new Int_64(K_sha2[49], 0x5141ab53),
            new Int_64(K_sha2[50], 0xdf8eeb99), new Int_64(K_sha2[51], 0xe19b48a8),
            new Int_64(K_sha2[52], 0xc5c95a63), new Int_64(K_sha2[53], 0xe3418acb),
            new Int_64(K_sha2[54], 0x7763e373), new Int_64(K_sha2[55], 0xd6b2b8a3),
            new Int_64(K_sha2[56], 0x5defb2fc), new Int_64(K_sha2[57], 0x43172f60),
            new Int_64(K_sha2[58], 0xa1f0ab72), new Int_64(K_sha2[59], 0x1a6439ec),
            new Int_64(K_sha2[60], 0x23631e28), new Int_64(K_sha2[61], 0xde82bde9),
            new Int_64(K_sha2[62], 0xb2c67915), new Int_64(K_sha2[63], 0xe372532b),
            new Int_64(0xca273ece, 0xea26619c), new Int_64(0xd186b8c7, 0x21c0c207),
            new Int_64(0xeada7dd6, 0xcde0eb1e), new Int_64(0xf57d4f7f, 0xee6ed178),
            new Int_64(0x06f067aa, 0x72176fba), new Int_64(0x0a637dc5, 0xa2c898a6),
            new Int_64(0x113f9804, 0xbef90dae), new Int_64(0x1b710b35, 0x131c471b),
            new Int_64(0x28db77f5, 0x23047d84), new Int_64(0x32caab7b, 0x40c72493),
            new Int_64(0x3c9ebe0a, 0x15c9bebc), new Int_64(0x431d67c4, 0x9c100d4c),
            new Int_64(0x4cc5d4be, 0xcb3e42b6), new Int_64(0x597f299c, 0xfc657e2a),
            new Int_64(0x5fcb6fab, 0x3ad6faec), new Int_64(0x6c44198c, 0x4a475817)
        ];
    }
}

function roundSHA2(block: any, H: any, letiant: any) {
    let a, b, c, d, e, f, g, h, T1, T2, numRounds, t, binaryStringMult,
        safeAdd_2, safeAdd_4, safeAdd_5, gamma0, gamma1, sigma0, sigma1,
        ch, maj, Int, W: any[] = [], int1, int2, offset, K;

    if ((letiant === "SHA-224" || letiant === "SHA-256") &&
        (2 & SUPPORTED_ALGS)) {
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
    } else if ((letiant === "SHA-384" || letiant === "SHA-512") &&
        (4 & SUPPORTED_ALGS)) {
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
            int1 = (block.length <= offset) ? 0 : block[offset];
            int2 = (block.length <= offset + 1) ? 0 : block[offset + 1];
            /* Bit of a hack - for 32-bit, the second term is ignored */
            W[t] = new Int(int1, int2);
        } else {
            W[t] = safeAdd_4(
                gamma1(W[t - 2]), W[t - 7],
                gamma0(W[t - 15]), W[t - 16]
            );
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

function finalizeSHA2(remainder: any, remainderBinLen: any, processedBinLen: any, H: any, letiant: any) {
    let i, appendedMessageLength, offset, retVal, binaryStringInc;

    if ((letiant === "SHA-224" || letiant === "SHA-256") &&
        (2 & SUPPORTED_ALGS)) {
        offset = (((remainderBinLen + 65) >>> 9) << 4) + 15;

        binaryStringInc = 16;
    } else if ((letiant === "SHA-384" || letiant === "SHA-512") &&
        (4 & SUPPORTED_ALGS)) {
        offset = (((remainderBinLen + 129) >>> 10) << 5) + 31;
        binaryStringInc = 32;
    } else {
        throw new Error("Unexpected error in SHA-2 implementation");
    }

    while (remainder.length <= offset) {
        remainder.push(0);
    }
    remainder[remainderBinLen >>> 5] |= 0x80 << (24 - remainderBinLen % 32);
    remainder[offset] = remainderBinLen + processedBinLen;

    appendedMessageLength = remainder.length;

    for (i = 0; i < appendedMessageLength; i += binaryStringInc) {
        H = roundSHA2(remainder.slice(i, i + binaryStringInc), H, letiant);
    }

    if (("SHA-224" === letiant) && (2 & SUPPORTED_ALGS)) {
        retVal = [
            H[0], H[1], H[2], H[3],
            H[4], H[5], H[6]
        ];
    } else if (("SHA-256" === letiant) && (2 & SUPPORTED_ALGS)) {
        retVal = H;
    } else if (("SHA-384" === letiant) && (4 & SUPPORTED_ALGS)) {
        retVal = [
            H[0].highOrder, H[0].lowOrder,
            H[1].highOrder, H[1].lowOrder,
            H[2].highOrder, H[2].lowOrder,
            H[3].highOrder, H[3].lowOrder,
            H[4].highOrder, H[4].lowOrder,
            H[5].highOrder, H[5].lowOrder
        ];
    } else if (("SHA-512" === letiant) && (4 & SUPPORTED_ALGS)) {
        retVal = [
            H[0].highOrder, H[0].lowOrder,
            H[1].highOrder, H[1].lowOrder,
            H[2].highOrder, H[2].lowOrder,
            H[3].highOrder, H[3].lowOrder,
            H[4].highOrder, H[4].lowOrder,
            H[5].highOrder, H[5].lowOrder,
            H[6].highOrder, H[6].lowOrder,
            H[7].highOrder, H[7].lowOrder
        ];
    } else {
        throw new Error("Unexpected error in SHA-2 implementation");
    }

    return retVal;
}

class jsSHA {
    processedLen = 0
    remainder: any = []
    remainderLen = 0
    utfType
    intermediateH: any
    converterFunc: any
    shaletiant: any
    outputBinLen: any
    letiantBlockSize: any
    roundFunc: any
    finalizeFunc: any
    finalized = false
    hmacKeySet = false
    keyWithIPad: any = []
    keyWithOPad: any = []
    numRounds: any
    updatedCalled = false
    inputOptions

    constructor(letiant: any, inputFormat: any, options: any = {}) {
        this.inputOptions = options || {};
        this.utfType = this.inputOptions["encoding"] || "UTF8";
        this.numRounds = this.inputOptions["numRounds"] || 1;
        this.shaletiant = letiant
        this.converterFunc = getStrConverter(inputFormat, this.utfType);

        if ((this.numRounds !== parseInt(this.numRounds, 10)) || (1 > this.numRounds)) {
            throw new Error("numRounds must a integer >= 1");
        }

        if (("SHA-1" === this.shaletiant) && (1 & SUPPORTED_ALGS)) {
            this.letiantBlockSize = 512;
            this.roundFunc = roundSHA1;
            this.finalizeFunc = finalizeSHA1;
            this.outputBinLen = 160;
        } else {
            if (6 & SUPPORTED_ALGS) {
                this.roundFunc = function (block: any, H: any) {
                    return roundSHA2(block, H, this.shaletiant);
                };
                this.finalizeFunc = function (remainder: any, remainderBinLen: any, processedBinLen: any, H: any) {
                    return finalizeSHA2(remainder, remainderBinLen, processedBinLen, H, this.shaletiant);
                };
            }

            if (("SHA-224" === this.shaletiant) && (2 & SUPPORTED_ALGS)) {
                this.letiantBlockSize = 512;
                this.outputBinLen = 224;
            } else if (("SHA-256" === this.shaletiant) && (2 & SUPPORTED_ALGS)) {
                this.letiantBlockSize = 512;
                this.outputBinLen = 256;
            } else if (("SHA-384" === this.shaletiant) && (4 & SUPPORTED_ALGS)) {
                this.letiantBlockSize = 1024;
                this.outputBinLen = 384;
            } else if (("SHA-512" === this.shaletiant) && (4 & SUPPORTED_ALGS)) {
                this.letiantBlockSize = 1024;
                this.outputBinLen = 512;
            } else {
                throw new Error("Chosen SHA letiant is not supported");
            }
        }

        this.intermediateH = getH(this.shaletiant);
    }

    setHMACKey(key: any, inputFormat: any, options: any = {}) {
        let keyConverterFunc, convertRet, keyBinLen, keyToUse, blockByteSize,
            i, lastArrayIndex, keyOptions;

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

        lastArrayIndex = (blockByteSize / 4) - 1;

        if (blockByteSize < (keyBinLen / 8)) {
            keyToUse = this.finalizeFunc(keyToUse, keyBinLen, 0, getH(this.shaletiant));

            while (keyToUse.length <= lastArrayIndex) {
                keyToUse.push(0);
            }
            keyToUse[lastArrayIndex] &= 0xFFFFFF00;
        } else if (blockByteSize > (keyBinLen / 8)) {
            while (keyToUse.length <= lastArrayIndex) {
                keyToUse.push(0);
            }
            keyToUse[lastArrayIndex] &= 0xFFFFFF00;
        }

        for (i = 0; i <= lastArrayIndex; i += 1) {
            this.keyWithIPad[i] = keyToUse[i] ^ 0x36363636;
            this.keyWithOPad[i] = keyToUse[i] ^ 0x5C5C5C5C;
        }

        this.intermediateH = this.roundFunc(this.keyWithIPad, this.intermediateH);
        this.processedLen = this.letiantBlockSize;

        this.hmacKeySet = true;
    };

    update(srcString: any) {
        let convertRet, chunkBinLen, chunkIntLen, chunk, i, updateProcessedLen = 0,
            letiantBlockIntInc = this.letiantBlockSize >>> 5;

        convertRet = this.converterFunc(srcString, this.remainder, this.remainderLen);
        chunkBinLen = convertRet["binLen"];
        chunk = convertRet["value"];

        chunkIntLen = chunkBinLen >>> 5;
        for (i = 0; i < chunkIntLen; i += letiantBlockIntInc) {
            if (updateProcessedLen + this.letiantBlockSize <= chunkBinLen) {
                this.intermediateH = this.roundFunc(
                    chunk.slice(i, i + letiantBlockIntInc),
                    this.intermediateH
                );
                updateProcessedLen += this.letiantBlockSize;
            }
        }
        this.processedLen += updateProcessedLen;
        this.remainder = chunk.slice(updateProcessedLen >>> 5);
        this.remainderLen = chunkBinLen % this.letiantBlockSize;
        this.updatedCalled = true;
    };

    getHMAC(format: any, options: any = {}) {
        let formatFunc, firstHash, outputOptions: any;

        if (!this.hmacKeySet) {
            throw new Error("Cannot call getHMAC without first setting HMAC key");
        }

        outputOptions = getOutputOpts(options);

        switch (format) {
            case "HEX":
                formatFunc = function (binarray: any) {
                    return binb2hex(binarray, outputOptions);
                };
                break;
            case "B64":
                formatFunc = function (binarray: any) {
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
    };

};
