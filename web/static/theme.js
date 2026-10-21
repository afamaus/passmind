// Gewähltes Design vor dem ersten Zeichnen setzen (kein Aufblitzen). Standard ist dunkel.
try {
  if (localStorage.getItem('pm-theme') === 'light') document.documentElement.dataset.theme = 'light';
} catch { /* Speicher nicht verfügbar */ }
