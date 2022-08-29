export default {
  fetch: (req, env) => {
    const { hostname, pathname } = new URL(req.url)
    const [_, instance] = pathname.split('/')
    const id = env.VAULT.idFromName(hostname + instance)
    const stub = env.VAULT.get(id)
    return stub.fetch(req)
  },
}

export class Vault {
  constructor(state, env) {
    this.state = state
  }

  async fetch(req) {
    const { url } = req
    const { pathname, search, searchParams } = new URL(url)
    const [_, instance, operation] = pathname.split('/')
    const id = req.headers.get('cf-ray') + '-' + req.cf.colo
    const ts = Date.now()

    const retval = {
      id,
      doId: this.state.id.toString(),
      ts,
      search,
      searchParams,
      instance,
      operation,
    }

    return new Response(JSON.stringify(retval, null, 2), { headers: { 'content-type': 'application/json' } })
  }
}
