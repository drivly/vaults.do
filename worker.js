export default {
  fetch: async (req, env) => {
    const jwk = JSON.parse(env.JWK)
    const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-512" }, true, ["decrypt"])
    const publicKey = await crypto.subtle.importKey("jwk", {
      key_ops: ["encrypt"], ext: jwk.ext, kty: jwk.kty, n: jwk.n, e: jwk.e, alg: jwk.alg
    }, { name: "RSA-OAEP", hash: "SHA-512" }, true, ["encrypt"])
    const { user, origin, pathname, url, hostname, query } = await env.CTX.fetch(req).then(res => res.json())
    if (!user.authenticated) return Response.redirect(origin + "/login?redirect_uri=" + url)
    const encoder = new TextEncoder()
    const keys = query.length && await Promise.all(Object.entries(query)
      .filter(key => key !== "apikey")
      .map(async (key, value) => { key, await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, encoder.encode(value)) })) || []
    const values = keys.length && Object.fromEntries(keys) || {}
    const id = env.VAULT.idFromName(hostname + pathname + user.profile.id.toString())
    const stub = env.VAULT.get(id)
    const decoder = new TextDecoder()
    let vault = await stub.fetch(new Request(url, { body: values && JSON.stringify(values), method: 'POST' })).then(res => res.json())
    let secrets = await Promise.all(Object.entries(vault).map(async (k, v) => ({ k, v: decoder.decode(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, v)) })))
    vault = Object.fromEntries(secrets)
    const retval = {
      api: {
        icon: '🏰',
        name: 'vaults.do',
        description: 'A Durable Object for managing API credentials',
        url: 'https://vaults.do',
        endpoints: {
          vault: 'https://vaults.do/:key',
        },
        memberOf: 'https://apis.do/core',
        login: origin + '/login',
        logout: origin + '/logout',
        repo: 'https://github.com/drivly/vaults.do',
      },
      vault,
      user,
    }

    return new Response(JSON.stringify(retval, null, 2), { headers: { 'content-type': 'application/json;charset=utf-8' } })
  },
}

export class Vault {
  constructor(state) {
    this.state = state
  }

  async fetch(req) {
    const values = await req.json()
    await Promise.all(Object.keys(values).map(k => this.state.storage.put(k, values[k])))
    return new Response(JSON.stringify({ ...Object.fromEntries(await this.state.storage.list()), ...values } || {}))
  }
}
