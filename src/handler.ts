import {tokenGenerate} from "./token";

import Totp from './totp'

export async function handleRequest(request: Request): Promise<Response> {

    // POST
    if (request.method == 'POST') {
        let {data, totpToken} = await request.json()

        let totp = new Totp();

        console.log(totp.getOtp(TotpKey))
        console.log(totp.getOtp1(TotpKey))

        if (totpToken != totp.getOtp(TotpKey) && totpToken != totp.getOtp1(TotpKey)) {
            return new Response('No permission')
        }

        let token = await tokenGenerate(data)
        let dataGet = await SURLKV.get(token)

        while (dataGet) {
            if (data == dataGet) {
                return new Response(`/${token}`)
            } else {
                data = `${data}#`
                token = await tokenGenerate(data)
                dataGet = await SURLKV.get(token)
            }
        }

        await SURLKV.put(token, data)

        return new Response(`/${token}`)
    }

    // GET
    let path_get = (new URL(request.url)).pathname

    let token = path_get.substring(1)

    if (token) {
        let dataGet = await SURLKV.get(token)

        // !!!Temp
        if (dataGet.indexOf('http') === 0) {
            return Response.redirect(dataGet, 302)
        }
        return new Response(dataGet)
    }

    let urlIndex = 'https://istatic.dza.vin/SURL/index.html'
    const init = {
        headers: {
            'content-type': 'text/html;charset=UTF-8',
        },
    };
    const response = await fetch(urlIndex, init);
    return new Response(await response.text(), init)
}
