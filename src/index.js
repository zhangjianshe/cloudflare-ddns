export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Basic Security: Check for a custom secret token passed via headers or query parameters
    const authToken = request.headers.get("Authorization") || url.searchParams.get("token");
    if (!authToken || authToken !== `Bearer ${env.SECRET_TOKEN}`) {
      return new Response("Unauthorized", { status: 401 });
    }

    // 2. Determine the new IP address
    // It can be manually passed via a query parameter (?ip=1.2.3.4), 
    // otherwise default to the client's connecting IP address.
    const newIp = url.searchParams.get("ip") || request.headers.get("CF-Connecting-IP");
    
    if (!newIp) {
      return new Response("IP address not found", { status: 400 });
    }

    // Environmental variables bound to your worker
    const zoneId = env.ZONE_ID;
    const recordId = env.RECORD_ID;
    const recordName = env.RECORD_NAME; // e.g., "home.yourdomain.com"
    const apiToken = env.CF_API_TOKEN;

    // 3. Construct the payload for Cloudflare API
    const updatePayload = {
      type: "A", // Use "AAAA" if you are strictly tracking IPv6 addresses
      name: recordName,
      content: newIp,
      ttl: 60,   // Low TTL for rapid DDNS updates
      proxied: false // Set to true if you want Cloudflare's CDN/proxy turned on
    };

    // 4. Send PUT request to Cloudflare API to overwrite the record
    const cfApiUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${recordId}`;
    
    try {
      const response = await fetch(cfApiUrl, {
        method: "PUT",
        headers: {
          "Authorization": `Bearer ${apiToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(updatePayload)
      });

      const result = await response.json();

      if (result.success) {
        return new Response(`Success: DNS updated to ${newIp}`, { status: 200 });
      } else {
        return new Response(`Cloudflare API Error: ${JSON.stringify(result.errors)}`, { status: 500 });
      }
    } catch (error) {
      return new Response(`Worker Error: ${error.message}`, { status: 500 });
    }
  }
};
