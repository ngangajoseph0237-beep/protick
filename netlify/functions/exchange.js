
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
