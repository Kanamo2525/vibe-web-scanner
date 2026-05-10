import { useState } from 'react';

type TlsInfo = {
  valid: boolean;
  authorized: boolean;
  authorizationError: string | null;
  subject: Record<string, string>;
  issuer: Record<string, string>;
  validFrom: string;
  validTo: string;
  fingerprint: string;
  subjectAltName: string;
};

type VibeScan = {
  detected: boolean;
  evidence: string[];
};

type ScanResult = {
  url: string;
  status: number;
  statusText: string;
  score: number;
  issues: string[];
  headers: Record<string, string>;
  tls: TlsInfo | null;
  vibe: VibeScan;
};

function App() {
  const [siteUrl, setSiteUrl] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const scanWebsite = async () => {
    setError('');
    setScanResult(null);

    const trimmedUrl = siteUrl.trim();
    if (!trimmedUrl) {
      setError('Veuillez saisir l’URL du site web.');
      return;
    }

    try {
      setLoading(true);
      const response = await fetch(`/api/scan?url=${encodeURIComponent(trimmedUrl)}`);
      const json = await response.json();

      if (!response.ok) {
        setError(json.error || 'Erreur lors de la vérification.');
        return;
      }

      setScanResult(json);
    } catch (err) {
      setError('Impossible de scanner le site. Vérifiez votre connexion et l’URL.');
    } finally {
      setLoading(false);
    }
  };

  const downloadJson = () => {
    if (!scanResult) return;
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'scan-report.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const downloadCsv = () => {
    if (!scanResult) return;
    const rows: string[] = [];
    const escape = (value: string) => `"${value.replace(/"/g, '""')}"`;

    rows.push(`${escape('URL')},${escape(scanResult.url)}`);
    rows.push(`${escape('Statut HTTP')},${escape(`${scanResult.status} ${scanResult.statusText}`)}`);
    rows.push(`${escape('Score')},${escape(String(scanResult.score))}`);
    rows.push(`${escape('Vibe détecté')},${escape(String(scanResult.vibe.detected))}`);
    rows.push('');
    rows.push(`${escape('Issue')},${escape('Détail')}`);
    scanResult.issues.forEach((issue) => rows.push(`${escape(issue)},${escape('')}`));
    rows.push('');
    rows.push(`${escape('Nom d’en-tête')},${escape('Valeur')}`);
    Object.entries(scanResult.headers).forEach(([name, value]) => rows.push(`${escape(name)},${escape(value || 'absent')}`));
    rows.push('');

    if (scanResult.tls) {
      rows.push(`${escape('TLS Subject')},${escape(JSON.stringify(scanResult.tls.subject))}`);
      rows.push(`${escape('TLS Issuer')},${escape(JSON.stringify(scanResult.tls.issuer))}`);
      rows.push(`${escape('Valid From')},${escape(scanResult.tls.validFrom)}`);
      rows.push(`${escape('Valid To')},${escape(scanResult.tls.validTo)}`);
      rows.push(`${escape('TLS Autorisé')},${escape(String(scanResult.tls.authorized))}`);
      rows.push(`${escape('Erreur d’autorisation')},${escape(scanResult.tls.authorizationError || '')}`);
    }

    const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'scan-report.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page">
      <div className="card">
        <h1>Scanner de vulnérabilité web</h1>
        <p>Analyse complète d'un site web Vibe : HTTP, TLS, sécurité des en-têtes et détection technologique.</p>

        <label>
          URL du site
          <input
            value={siteUrl}
            onChange={(event) => setSiteUrl(event.target.value)}
            placeholder="https://example.com"
          />
        </label>

        <button onClick={scanWebsite} disabled={loading}>
          {loading ? 'Analyse en cours...' : 'Lancer le scan'}
        </button>

        {error && <div className="message error">{error}</div>}

        {scanResult && (
          <div className="message result">
            <div className="result-actions">
              <button className="small" onClick={downloadJson}>
                Exporter JSON
              </button>
              <button className="small" onClick={downloadCsv}>
                Exporter CSV
              </button>
            </div>

            <h2>Résultat du scan</h2>
            <p>
              <strong>{scanResult.url}</strong> — {scanResult.status} {scanResult.statusText}
            </p>
            <p>Score de sécurité : {scanResult.score}/100</p>

            <h3>Technologie détectée</h3>
            <p>
              {scanResult.vibe.detected
                ? 'Vibe détecté dans le site web.'
                : 'Aucun signe Vibe explicite détecté.'}
            </p>
            {scanResult.vibe.evidence.length > 0 && (
              <ul>
                {scanResult.vibe.evidence.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )}

            {scanResult.issues.length > 0 ? (
              <>
                <h3>Points à améliorer</h3>
                <ul>
                  {scanResult.issues.map((issue) => (
                    <li key={issue}>{issue}</li>
                  ))}
                </ul>
              </>
            ) : (
              <p>Aucun problème critique détecté.</p>
            )}

            <h3>En-têtes de sécurité</h3>
            <ul>
              {Object.entries(scanResult.headers).map(([name, value]) => (
                <li key={name}>
                  <strong>{name}</strong>: {value || 'absent'}
                </li>
              ))}
            </ul>

            {scanResult.tls ? (
              <>
                <h3>Informations TLS</h3>
                <p>Certificat valide : {scanResult.tls.valid ? 'Oui' : 'Non'}</p>
                <p>Autorisé : {scanResult.tls.authorized ? 'Oui' : 'Non'}</p>
                {scanResult.tls.authorizationError && <p>Erreur TLS : {scanResult.tls.authorizationError}</p>}
                <p>Validité : {scanResult.tls.validFrom} → {scanResult.tls.validTo}</p>
                <p>Émetteur : {scanResult.tls.issuer.CN || JSON.stringify(scanResult.tls.issuer)}</p>
              </>
            ) : (
              <p>Analyse TLS non disponible pour ce site.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
