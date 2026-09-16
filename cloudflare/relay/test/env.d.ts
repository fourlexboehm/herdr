declare module "cloudflare:workers" {
  // Cloudflare's test runtime uses interface merging for generated bindings.
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface ProvidedEnv extends Env {}
}

export {};
