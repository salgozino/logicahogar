// Protects the quote builder (/presupuestos) with HTTP Basic Auth.
// Credentials come from the PRESUPUESTOS_USER and PRESUPUESTOS_PASSWORD
// environment variables configured in Netlify. If they are missing, access is denied.

declare const Netlify: { env: { get(key: string): string | undefined } };

interface EdgeContext {
  next(): Promise<Response>;
}

const REALM = "LogicaHogar Presupuestos";
const PRIVATE_HEADERS = {
  "Cache-Control": "no-store",
  "X-Robots-Tag": "noindex, nofollow",
};

function safeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  }
  return diff === 0;
}

function unauthorized(): Response {
  return new Response("Autenticación requerida", {
    status: 401,
    headers: {
      ...PRIVATE_HEADERS,
      "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"`,
    },
  });
}

function decodeCredentials(header: string): { user: string; password: string } | null {
  const [scheme, encoded] = header.split(" ");
  if (scheme?.toLowerCase() !== "basic" || !encoded) return null;

  try {
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    const decoded = new TextDecoder().decode(bytes);
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    return { user: decoded.slice(0, separator), password: decoded.slice(separator + 1) };
  } catch {
    return null;
  }
}

export default async (request: Request, context: EdgeContext): Promise<Response> => {
  const expectedUser = Netlify.env.get("PRESUPUESTOS_USER");
  const expectedPassword = Netlify.env.get("PRESUPUESTOS_PASSWORD");
  if (!expectedUser || !expectedPassword) {
    return new Response("Acceso no configurado", { status: 503, headers: PRIVATE_HEADERS });
  }

  const credentials = decodeCredentials(request.headers.get("authorization") ?? "");
  if (!credentials) return unauthorized();

  const userOk = safeEqual(credentials.user, expectedUser);
  const passwordOk = safeEqual(credentials.password, expectedPassword);
  if (!userOk || !passwordOk) return unauthorized();

  const response = await context.next();
  for (const [key, value] of Object.entries(PRIVATE_HEADERS)) {
    response.headers.set(key, value);
  }
  return response;
};

export const config = {
  path: ["/presupuestos", "/presupuestos/*"],
};
