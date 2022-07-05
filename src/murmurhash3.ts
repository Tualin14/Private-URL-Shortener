export function hash32(key: string, seed = 0) {

    let i;
    let remainder = key.length % 4;
    let bytes = key.length - remainder;

    let h1 = seed;

    let k1 = 0;

    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;

    for (i = 0; i < bytes; i = i + 4) {
        k1 = ((key.charCodeAt(i) & 0xff)) | ((key.charCodeAt(i + 1) & 0xff) << 8) | ((key.charCodeAt(i + 2) & 0xff) << 16) | ((key.charCodeAt(i + 3) & 0xff) << 24);

        k1 = _x86Multiply(k1, c1);
        k1 = _x86Rotl(k1, 15);
        k1 = _x86Multiply(k1, c2);

        h1 ^= k1;
        h1 = _x86Rotl(h1, 13);
        h1 = _x86Multiply(h1, 5) + 0xe6546b64;
    }

    k1 = 0;

    switch (remainder) {
        case 3:
            k1 ^= (key.charCodeAt(i + 2) & 0xff) << 16;
            break
        case 2:
            k1 ^= (key.charCodeAt(i + 1) & 0xff) << 8;
            break
        case 1:
            k1 ^= (key.charCodeAt(i) & 0xff);
            k1 = _x86Multiply(k1, c1);
            k1 = _x86Rotl(k1, 15);
            k1 = _x86Multiply(k1, c2);
            h1 ^= k1;
    }

    h1 ^= key.length;
    h1 = _x86Fmix(h1);

    return h1 >>> 0;
}

function _x86Multiply(m: any, n: any) {
    return ((m & 0xffff) * n) + ((((m >>> 16) * n) & 0xffff) << 16);
}

function _x86Rotl(m: any, n: any) {
    return (m << n) | (m >>> (32 - n));
}

function _x86Fmix(h: any) {
    h ^= h >>> 16;
    h = _x86Multiply(h, 0x85ebca6b);
    h ^= h >>> 13;
    h = _x86Multiply(h, 0xc2b2ae35);
    h ^= h >>> 16;

    return h;
}