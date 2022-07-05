import {setting} from "./setting";
import {tokenGenerate} from "./token";

export async function handleRequest(request: Request): Promise<Response> {

    // POST
    if (request.method == 'POST') {
        let {data, totpToken} = await request.json()

        // !!!Temp
        if (totpToken != setting.s) {
            return new Response('No permission')
        }

        let path_post = (new URL(request.url)).pathname
        switch (path_post.substring(1, 2)) {
            // /L
            case 'L':
                return new Response('List')

            // /
            default:
                let token = await tokenGenerate(data)
                let dataGet = await SURLKV.get(token)

                while (dataGet) {
                    if (data == dataGet) {
                        return new Response(`get /T${token}`)
                    } else {
                        data = `${data}#`
                        token = await tokenGenerate(data)
                        dataGet = await SURLKV.get(token)
                    }
                }

                await SURLKV.put(token, data)

                return new Response(`/T${token}`)
        }
    }

    // GET
    let path_get = (new URL(request.url)).pathname
    switch (path_get.substring(1, 2)) {

        // /T{token}
        case 'T':
            let token = path_get.substring(2)
            let dataGet = await SURLKV.get(token)

            // !!!Temp
            if (dataGet.indexOf('http') === 0) {
                return Response.redirect(dataGet, 302)
            }
            return new Response(dataGet)

        // /L
        case 'L':
            //
            return new Response('L')

        // /
        default:
            let url = 'https://istatic.dza.vin/SURL/index.html'
            const init = {
                headers: {
                    'content-type': 'text/html;charset=UTF-8',
                },
            };
            const response = await fetch(url, init);
            return new Response(response.text(), init)
    }
}
