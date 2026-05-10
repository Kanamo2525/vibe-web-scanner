import express from 'express';
import { URL } from 'url';
import tls from 'tls';

const app = express();
const port = 5174;

function sanitizeHeaderValue(value) {
  return value ? value.trim() : '';
}

async function fetchTlsInfo(hostname, port = 443, servername) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername,
        rejectUnauthorized: false,
        timeout: 5000,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        const authorizationError = socket.authorizationError || null;
        const valid = cert && cert.valid_from && cert.valid_to
          ? new Date(cert.valid_from) <= new Date() && new Date() <= new Date(cert.valid_to)
          : false;

        socket.end();
        resolve({
          valid,
          authorized,
          authorizationError,
          subject: cert.subject || {},
          issuer: cert.issuer || {},
          validFrom: cert.valid_from || '',
          validTo: cert.valid_to || '',
          fingerprint: cert.fingerprint || '',
          subjectAltName: cert.subjectaltname || '',
        });
      }
    );

    socket.on('error', () => {
      resolve(null);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

function calculateScore(issues, tlsInfo) {
  let score = 100;
  score -= issues.length * 10;

  if (tlsInfo) {
    if (!tlsInfo.authorized) score -= 20;
    if (!tlsInfo.valid) score -= 20;
  }

  return Math.max(0, score);
}

function detectVibe(headers, html) {
  const evidence = [];

  if (headers['x-powered-by']?.toLowerCase().includes('vibe')) {
    evidence.push('En-tête X-Powered-By indique Vibe.');
  }

  if (/data-vibe|vibe-theme|vibe-app|from-vibe|\/vibe\//i.test(html)) {
    evidence.push('Marqueurs Vibe trouvés dans le HTML.');
  }

  if (/<script[^>]+src=["'][^"']*vibe[^"']*["']/i.test(html)) {
    evidence.push('Script source contenant Vibe détecté.');
  }

  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(html);
  if (generator && /vibe/i.test(generator[1])) {
    evidence.push('Meta generator indique Vibe.');
  }

  return {
    detected: evidence.length > 0,
    evidence,
  };
}

function buildSecurityIssues(url, headers, html, tlsInfo) {
  const issues = [];

  if (url.protocol !== 'https:') {
    issues.push('Le site n\'utilise pas HTTPS sécurisé.');
  }

  if (!headers['strict-transport-security']) {
    issues.push('HSTS absent.');
  }
  if (!headers['content-security-policy']) {
    issues.push('CSP absent.');
  }
  if (!headers['x-content-type-options']) {
    issues.push('X-Content-Type-Options absent.');
  }
  if (!headers['x-frame-options'] && !headers['frame-options']) {
    issues.push('X-Frame-Options absent.');
  }
  if (!headers['referrer-policy']) {
    issues.push('Referrer-Policy absent.');
  }
  if (!headers['permissions-policy']) {
    issues.push('Permissions-Policy absent.');
  }
  if (!headers['cache-control']) {
    issues.push('Cache-Control absent.');
  }

  const hasInlineScript = /<script\b[^>]*>([\s\S]*?)<\/script>/i.test(html) && !/<script\b[^>]*src=/i.test(html);
  if (hasInlineScript) {
    issues.push('Scripts inline détectés dans le HTML, risque XSS.');
  }

  const hasUnsafeCsp = /unsafe-inline|unsafe-eval/i.test(headers['content-security-policy'] || '');
  if (hasUnsafeCsp) {
    issues.push('CSP contient unsafe-inline ou unsafe-eval.');
  }

  if (/http-equiv=["']?refresh["']?/i.test(html)) {
    issues.push('Meta refresh détecté.');
  }

  if (tlsInfo) {
    if (!tlsInfo.valid) {
      issues.push('Certificat TLS invalide ou expiré.');
    }
    if (!tlsInfo.authorized) {
      issues.push(`Certificat TLS non autorisé : ${tlsInfo.authorizationError || 'inconnu'}.`);
    }
  }

  return issues;
}

app.get('/api/scan', async (req, res) => {
  const rawUrl = String(req.query.url || '');
  if (!rawUrl) {
    return res.status(400).json({ error: 'URL manquante.' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch (error) {
    return res.status(400).json({ error: 'URL invalide.' });
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return res.status(400).json({ error: 'Le protocole doit être http ou https.' });
  }

  try {
    const response = await fetch(parsedUrl.href, {
      redirect: 'follow',
    });

    const rawHtml = await response.text();
    const headers = {};

    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = sanitizeHeaderValue(value);
    });

    const tlsInfo = parsedUrl.protocol === 'https:'
      ? await fetchTlsInfo(parsedUrl.hostname, parsedUrl.port ? Number(parsedUrl.port) : 443, parsedUrl.hostname)
      : null;

    const vibe = detectVibe(headers, rawHtml);
    const issues = buildSecurityIssues(parsedUrl, headers, rawHtml, tlsInfo);
    const score = calculateScore(issues, tlsInfo);

    return res.json({
      url: parsedUrl.href,
      status: response.status,
      statusText: response.statusText,
      score,
      issues,
      headers,
      tls: tlsInfo,
      vibe,
    });
  } catch (error) {
    return res.status(500).json({
      error: 'Échec de la récupération du site. Vérifiez que l\'URL est accessible depuis le serveur.',
    });
  }
});

app.listen(port, () => {
  console.log(`Server de scan démarré sur http://127.0.0.1:${port}`);
});
