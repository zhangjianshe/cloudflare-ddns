export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Parse HTTP Basic Authentication from the Gateway
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Basic ")) {
      return new Response("Unauthorized: Missing Basic Auth Header", { 
        status: 401, 
        headers: { "WWW-Authenticate": 'Basic realm="DDNS Update"' } 
      });
    }

    // Decode Base64 username:password
    const base64Credentials = authHeader.split(" ")[1];
    const credentials = atob(base64Credentials);
    const [username, password] = credentials.split(":");

    // Verify credentials against your environment variables
    if (username !== env.DDNS_USER || password !== env.DDNS_PASSWORD) {
      return new Response("Unauthorized: Invalid Username or Password", { status: 401 });
    }

    // 2. Automatically detect incoming IP and Domain Name
    // Most routers append parameters like ?ip=... or ?hostname=... 
    // We will check common query parameters, otherwise fallback to the connecting IP.
    const newIp = url.searchParams.get("ip") || 
                  url.searchParams.get("myip") || 
                  request.headers.get("CF-Connecting-IP");
                  
    const domainName = url.searchParams.get("hostname") || 
                       url.searchParams.get("domain") || 
                       env.RECORD_NAME; // Fallback to env default

    if (!newIp) {
      return new Response("Error: IP address not detected", { status: 400 });
    }

    // 3. Update Cloudflare DNS via API
    const cfApiUrl = `https://api.cloudflare.com/client/v4/zones/${env.ZONE_ID}/dns_records/${env.RECORD_ID}`;
    
    const updatePayload = {
      type: "A",
      name: domainName,
      content: newIp,
      ttl: 60,
      proxied: false
    };

    try {
      const response = await fetch(cfApiUrl, {
        method: "PUT",
        headers: {
          "Authorization": `Bearer ${env.CF_API_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(updatePayload)
      });

      const result = await response.json();

      if (result.success) {
        return new Response("good", { status: 200 }); // "good" or "nochg" is standard for DDNS clients
      } else {
        return new Response(`Cloudflare Error: ${JSON.stringify(result.errors)}`, { status: 500 });
      }
    } catch (error) {
      return new Response(`Worker Error: ${error.message}`, { status: 500 });
    }
  }
};
