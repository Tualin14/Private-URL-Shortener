import {hash32} from "./murmurhash3"

export async function tokenGenerate(lurl: string): Promise<string> {
    let num = hash32(lurl, SEED)

    let token = to58(num)
    return token
}

async function to58(num: number) {
    const s58 = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
    let token = ''
    while (num) {
        token = s58.charAt(num % 58) + token
        num = Math.floor(num / 58)
    }
    return token
}