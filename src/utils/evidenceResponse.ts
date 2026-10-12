/** Evidence is untrusted content, including MIME metadata from legacy records. */
export function evidenceResponseHeaders(filename: string, contentType: string | null) {
  const mime = contentType?.split(';')[0].trim().toLowerCase() || 'application/octet-stream';
  const inline = ['image/jpeg', 'image/png', 'image/webp', 'image/tiff', 'application/pdf'].includes(mime);
  const type = inline || ['text/csv', 'application/json'].includes(mime) ? mime : 'application/octet-stream';
  const safeName = filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_') || 'evidence';
  return {
    'Content-Type': type,
    'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="${safeName}"`,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    // Never framed by another page. A download is also a sandboxed, script-less
    // document if a browser ever renders it despite `attachment`; inline image/PDF
    // types keep the browser's own viewer, which a sandbox would disable.
    'Content-Security-Policy': inline ? "frame-ancestors 'none'" : "sandbox; default-src 'none'; frame-ancestors 'none'",
    'Cross-Origin-Resource-Policy': 'same-origin',
  };
}
