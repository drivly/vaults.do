export default {
  fetch: async (req, env) => {
    const { user, origin, pathname, url, hostname } = await env.CTX.fetch(req).then(res => res.json())
    if (!user.authenticated) return Response.redirect(origin + "/login?redirect_uri=" + url)
    const [instance, operation] = pathname.slice(1).split('/')
    req.user = user
    req.instance = instance
    req.operation = operation
    const id = env.VAULT.idFromName(hostname + instance + user.profile.id.toString())
    const stub = env.VAULT.get(id)
    return stub.fetch(req)
  },
}

export class Vault {
  constructor(state, env) {
    this.state = state
    this.env = env
  }

  async fetch(req) {
    const origin = new URL(req.url).origin
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
      instance: req.instance,
      operation: req.operation,
      user: req.user,
    }

    return new Response(JSON.stringify(retval, null, 2), { headers: { 'content-type': 'application/json' } })
  }
}
