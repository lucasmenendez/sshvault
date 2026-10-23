(() => {
  const themeKey = 'sshvault-theme';
  const root = document.documentElement;
  const select = document.getElementById('theme-select');
  let stored = '';
  try { stored = localStorage.getItem(themeKey) || ''; } catch { /* storage unavailable */ }
  if (stored) root.dataset.theme = stored;
  if (select) {
    select.value = stored;
    select.addEventListener('change', () => {
      const value = select.value;
      if (value) root.dataset.theme = value;
      else delete root.dataset.theme;
      try { localStorage.setItem(themeKey, value); } catch { /* storage unavailable */ }
    });
  }
})();

(() => {
  const buttons = document.querySelectorAll('[data-copy]');

  for (const button of buttons) {
    button.addEventListener('click', async () => {
      const target = document.querySelector(button.dataset.copy);
      if (!target) return;
      const text = target.textContent.trim();
      const original = button.textContent;

      try {
        await navigator.clipboard.writeText(text);
        button.textContent = 'Copied';
        button.classList.add('copied');
        setTimeout(() => {
          button.textContent = original;
          button.classList.remove('copied');
        }, 1600);
      } catch {
        button.textContent = 'Select & copy';
        setTimeout(() => {
          button.textContent = original;
        }, 2200);
      }
    });
  }
})();
