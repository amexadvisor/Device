import crypto from 'crypto';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { is_multi_account, fingerprint, initData } = req.body;
    
    const BOT_TOKEN = process.env.BOT_TOKEN;
    const targetWebhook = process.env.WEBHOOK_URL;

    if (!BOT_TOKEN || !targetWebhook) {
      return res.status(500).json({ error: "Server configuration error: missing environment variables" });
    }

    if (!initData || typeof initData !== 'string') {
      return res.status(401).json({ error: "Unauthorized: Missing Telegram WebApp security context" });
    }

    let targetUserId = null;

    // Cryptographic validation identical to your ads bot
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');

    if (!hash) return res.status(401).json({ error: "Unauthorized: Missing signature hash" });

    params.delete('hash');
    params.sort();

    const dataCheckArr = [];
    for (const [key, value] of params.entries()) {
      dataCheckArr.push(`${key}=${value}`);
    }
    const dataCheckString = dataCheckArr.join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

    if (calculatedHash !== hash) {
      return res.status(403).json({ error: "Forbidden: Invalid Telegram signature" });
    }

    const userStr = params.get('user');
    if (userStr) {
      const parsed = JSON.parse(userStr);
      if (parsed && parsed.id) {
        targetUserId = parsed.id;
      }
    }

    if (!targetUserId) {
      return res.status(400).json({ error: "Missing user identification within validated context" });
    }

    let payloadStatus = "success";
    let payloadTitle = "Verification Successful";
    let payloadMessage = "Your device is verified and safe.";

    if (is_multi_account) {
      payloadStatus = "error";
      payloadTitle = "Multi-Account Detected";
      payloadMessage = "You cannot verify multiple accounts from the same device.";
    } else {
      const clientIp = req.headers['x-forwarded-for'] || '127.0.0.1';
      let isVpn = 'N';
      try {
        const vpnCheckResponse = await fetch(`https://blackbox.ipinfo.app/lookup/${clientIp}`);
        isVpn = await vpnCheckResponse.text();
      } catch (e) {
        isVpn = 'N'; 
      }

      if (isVpn.trim() === 'Y') {
        payloadStatus = "error";
        payloadTitle = "VPN Detected";
        payloadMessage = "VPN, Proxy, or Tor network detected. Please disable it and try again.";
      }
    }

    await fetch(targetWebhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: String(targetUserId),
        status: payloadStatus,
        title: payloadTitle,
        message: payloadMessage,
        fingerprint: fingerprint
      })
    });

    return res.status(200).json({ 
      success: payloadStatus === "success", 
      message: payloadMessage 
    });

  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
