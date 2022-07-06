export default async function hmacSHA1(k: any, d: any, _p = '=', _z = 8) {

    function _f(t: any, b: any, c: any, d: any) {
        if (t < 20) {
            return (b & c) | ((~b) & d);
        }
        if (t < 40) {
            return b ^ c ^ d;
        }
        if (t < 60) {
            return (b & c) | (b & d) | (c & d);
        }
        return b ^ c ^ d;
    }

    function _k(t: any) {
        return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 : (t < 60) ? -1894007588 : -899497514;
    }

    function _s(x: any, y: any) {
        let l = (x & 0xFFFF) + (y & 0xFFFF), m = (x >> 16) + (y >> 16) + (l >> 16);
        return (m << 16) | (l & 0xFFFF);
    }

    function _r(n: any, c: any) {
        return (n << c) | (n >>> (32 - c));
    }

    function _c(x: any, l: any) {
        x[l >> 5] |= 0x80 << (24 - l % 32);
        x[((l + 64 >> 9) << 4) + 15] = l;
        let w = [80], a = 1732584193, b = -271733879, c = -1732584194, d = 271733878, e = -1009589776;
        for (let i = 0; i < x.length; i += 16) {
            let o = a, p = b, q = c, r = d, s = e;
            for (let j = 0; j < 80; j++) {
                if (j < 16) {
                    w[j] = x[i + j];
                } else {
                    w[j] = _r(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                }
                let t = _s(_s(_r(a, 5), _f(j, b, c, d)), _s(_s(e, w[j]), _k(j)));
                e = d;
                d = c;
                c = _r(b, 30);
                b = a;
                a = t;
            }
            a = _s(a, o);
            b = _s(b, p);
            c = _s(c, q);
            d = _s(d, r);
            e = _s(e, s);
        }
        return [a, b, c, d, e];
    }

    function _b(s: any) {
        let b: any[] = [], m = (1 << _z) - 1;
        for (let i = 0; i < s.length * _z; i += _z) {
            b[i >> 5] |= (s.charCodeAt(i / 8) & m) << (32 - _z - i % 32);
        }
        return b;
    }

    function _h(k: any, d: any) {
        let b = _b(k);
        if (b.length > 16) {
            b = _c(b, k.length * _z);
        }
        let p = [16], o = [16];
        for (let i = 0; i < 16; i++) {
            p[i] = b[i] ^ 0x36363636;
            o[i] = b[i] ^ 0x5C5C5C5C;
        }
        let h = _c(p.concat(_b(d)), 512 + d.length * _z);
        return _c(o.concat(h), 512 + 160);
    }

    function _n(b: any) {
        let t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", s = '';
        for (let i = 0; i < b.length * 4; i += 3) {
            let r = (((b[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16) | (((b[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8) | ((b[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
            for (let j = 0; j < 4; j++) {
                if (i * 8 + j * 6 > b.length * 32) {
                    s += _p;
                } else {
                    s += t.charAt((r >> 6 * (3 - j)) & 0x3F);
                }
            }
        }
        return s;
    }

    function _x(k: any, d: any) {
        return _n(_h(k, d));
    }

    return _x(k, d);
}