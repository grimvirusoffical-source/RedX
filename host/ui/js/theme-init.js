// Runs synchronously from <head> (before first paint) so the page never flashes the wrong theme.
// Classic script, no imports: the CSP allows 'self' scripts only. Keep the logic in sync with js/state.js.
(function () {
  var pref = 'dark';
  try {
    var v = localStorage.getItem('redx.theme');
    if (v === 'auto') v = 'system'; // older builds stored "auto"
    if (v === 'dark' || v === 'light' || v === 'system') pref = v;
  } catch (e) { /* private mode: keep the default (dark) */ }
  var light = pref === 'light' || (pref === 'system' && window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches);
  var root = document.documentElement;
  root.setAttribute('data-theme', light ? 'light' : 'dark');
  root.setAttribute('data-theme-pref', pref);
  var m = document.querySelector('meta[name=theme-color]');
  if (m) m.setAttribute('content', light ? '#f7f3f2' : '#0f0809');
})();
