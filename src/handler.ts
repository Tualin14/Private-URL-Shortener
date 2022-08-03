import { tokenGenerate } from "./token";

import Totp from "./totp";

const urlp = /^(https?:\/\/)([0-9a-z.]+)/i;

const html = `<!DOCTYPE html><html lang="en"><head><link href="https://cdn.jsdelivr.net/npm/daisyui@2.18.0/dist/full.css"rel="stylesheet"type="text/css"/><script src="https://cdn.tailwindcss.com"></script><script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script><script src="https://cdn.jsdelivr.net/npm/theme-change@2.0.2/index.js"></script><title>SURL</title></head><body><div class="hero min-h-screen bg-base-200"><div class="hero-content text-center w-full"><div class="card flex-shrink-0 w-full shadow-2xl bg-base-100"><div class="card-body"><h1 class="card-title text-4xl"><a href="https://github.com/Tualin14/SURL"target="_blank"><button class="btn btn-square btn-ghost"><svg viewBox="0 0 16 16"fill="currentColor"><path fill-rule="evenodd"d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg></button></a>SURL</h1><!--theme--><div class="card-actions justify-end"><button data-set-theme="corporate"data-act-class="ACTIVECLASS"class="btn btn-square btn-ghost"><svg xmlns="http://www.w3.org/2000/svg"viewBox="0 0 20 20"fill="currentColor"><path fillRule="evenodd"d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"clipRule="evenodd"/></svg></button><button data-set-theme="dark"data-act-class="ACTIVECLASS"class="btn btn-square btn-ghost"><svg xmlns="http://www.w3.org/2000/svg"viewBox="0 0 20 20"fill="currentColor"><path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"/></svg></button></div><div class="form-control"><label class="label"><span class="label-text">Data</span></label><input type="text"id="data"class="input input-bordered"/></div><div class="form-control"><label class="label"><span class="label-text">totp Token</span></label><div class="input-group"><input type="text"id="totpToken"class="input input-bordered w-full"/><button class="btn btn-primary w-40"onclick="getSurl()">Get SURL</button></div></div><div class="form-control"><label class="label"><span class="label-text">SURL</span></label><div class="input-group"><input type="text"id="copyInput"class="input input-bordered w-full"/><button class="btn w-40"id="copyButton"disabled="disabled"onclick='copyToClipboard()'>Copy!</button></div></div></div></div></div></div><script type="text/javascript">function getSurl(){let data=document.getElementById("data").value;let totpToken=document.getElementById("totpToken").value;let copyInput=document.getElementById("copyInput");let copyButton=document.getElementById("copyButton");copyButton.className="btn w-40";copyButton.setAttribute("disabled","disabled");axios.post("/",{data:data,totpToken:totpToken,}).then(function(res){let resData=res.data;copyInput.value=window.location.origin+res.data;copyButton.className+=" btn-success";copyButton.removeAttribute("disabled")}).catch(function(error){copyInput.value="No permission"})}function copyToClipboard(){let copyInput=document.getElementById("copyInput");navigator.clipboard.writeText(copyInput.value)}</script></body></html>`;

export async function handleRequest(request: Request): Promise<Response> {
  // POST
  if (request.method == "POST") {
    let { data, totpToken } = await request.json();

    let totp = new Totp();

    console.log(totp.getOtp(TotpKey));
    console.log(totp.getOtp1(TotpKey));

    if (
      totpToken != totp.getOtp(TotpKey) &&
      totpToken != totp.getOtp1(TotpKey)
    ) {
      return new Response("No permission", { status: 403 });
    }

    let token = await tokenGenerate(data);
    let dataGet = await SURLKV.get(token);

    while (dataGet) {
      if (data == dataGet) {
        return new Response(`/${token}`);
      } else {
        data = `${data}#`;
        token = await tokenGenerate(data);
        dataGet = await SURLKV.get(token);
      }
    }

    await SURLKV.put(token, data);

    return new Response(`/${token}`);
  }

  // GET
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
      "content-type": "text/html;charset=UTF-8",
    },
  });
}