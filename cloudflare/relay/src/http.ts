export interface RelayHttpError {
  error: {
    code: string;
    message: string;
  };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  headers?: HeadersInit,
): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("Cache-Control", "no-store");

  return Response.json(
    {
      error: {
        code,
        message,
      },
    } satisfies RelayHttpError,
    {
      status,
      headers: responseHeaders,
    },
  );
}

