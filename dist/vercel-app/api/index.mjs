import { createVercelHandler } from '../deploy/vercel/handler.mjs';

const handler = createVercelHandler(process.env);

export default async function vercelEntrypoint(req, res) {
  return handler(req, res);
}
