export default {
  fetch: async (req, env) => {
    const privateKey = await crypto.subtle.importKey("jwk", env.JWK, { name: "RSA-OAEP", hash: "SHA-512" }, true, ["decrypt"])
    const publicKey = await crypto.subtle.importKey("jwk", {
      key_ops: ["encrypt"], ext: env.JWK.ext, kty: env.JWK.kty, n: env.JWK.n, e: env.JWK.e, alg: env.JWK.alg
    }, { name: "RSA-OAEP", hash: "SHA-512" }, true, ["encrypt"])
    const { user, origin, pathname, url, hostname, query } = await env.CTX.fetch(req).then(res => res.json())
    if (!user.authenticated) return Response.redirect(origin + "/login?redirect_uri=" + url)
    const encoder = new TextEncoder()
    const values = query.length && Object.fromEntries(await Promise.all(Object.entries(query)
      .filter(key => key !== "apikey")
      .map(async (key, value) => { key, await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, encoder.encode(value)) }))
    )
    const id = env.VAULT.idFromName(hostname + pathname + user.profile.id.toString())
    const stub = env.VAULT.get(id)
    const decoder = new TextDecoder()
    let vault = await stub.fetch(new Request(url, { body: values && JSON.stringify(values) })).then(JSON.parse)
    vault = Object.fromEntries(Promise.all(Object.entries(vault).map(async (k, v) => ({ k, v: decoder.decode(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, v)) }))))
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
    await Promise.all(
      req.json()
        .then(values =>
          Object.keys(values)
            .map(k => this.state.storage.put(k, values[k]))
        ).catch())

    const vault = Object.fromEntries(await this.state.storage.list())
    return new Response(JSON.stringify(vault))
  }
}
