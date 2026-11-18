
exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" })
    };
  }

  const clientId = process.env.DERIV_CLIENT_ID;
  const redirectUri = process.env.DERIV_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Server configuration missing" })
    };
  }

  try {
    const { code, code_verifier } = JSON.parse(event.body || "{}");

    if (
      typeof code !== "string" ||
      typeof code_verifier !== "string" ||
      code_verifier.length < 43 ||
      code_verifier.length > 128
    ) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Invalid authorization details" })
      };
    }

    const response = await fetch(
      "https://auth.deriv.com/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          code,
          code_verifier,
          redirect_uri: redirectUri
        })
      }
    );

    const data = await response.json();

    if (!response.ok || !data.access_token) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Deriv authorization failed" })
      };
    }

    const maxAge = Math.max(
      0,
      Math.min(Number(data.expires_in) || 0, 2592000)
    );

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Set-Cookie":
          `protick_session=${encodeURIComponent(data.access_token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`
      },
      body: JSON.stringify({
        connected: true,
        message: "Deriv account connected successfully"
      })
    };

  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Connection could not be completed" })
    };
  }
};

export default async (request) => {
  if (request.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "Method not allowed" }),
      { status: 405 }
    );
  }

  const clientId = Netlify.env.get("DERIV_CLIENT_ID");
  const redirectUri = Netlify.env.get("DERIV_REDIRECT_URI");

  if (!clientId || !redirectUri) {
    return new Response(
      JSON.stringify({ error: "Server configuration is incomplete" }),
      { status: 500 }
    );
  }

  try {
    const { code, code_verifier } = await request.json();

    if (
      typeof code !== "string" ||
      typeof code_verifier !== "string" ||
      code_verifier.length < 43 ||
      code_verifier.length > 128
    ) {
      return new Response(
        JSON.stringify({ error: "Invalid authorization details" }),
        { status: 400 }
      );
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      code_verifier,
      redirect_uri: redirectUri
    });

    const result = await fetch(
      "https://auth.deriv.com/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body
      }
    );

    const data = await result.json();

    if (!result.ok || !data.access_token) {
      return new Response(
        JSON.stringify({ error: "Deriv authorization failed" }),
        { status: 400 }
      );
    }

    return new Response(
      JSON.stringify({
        access_token: data.access_token,
        expires_in: data.expires_in,
        token_type: data.token_type
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" }
      }
    );
  } catch {
    return new Response(
      JSON.stringify({ error: "Unable to complete connection" }),
      { status: 500 }
    );
  }
};
