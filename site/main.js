(() => {
  const themeKey = 'sshvault-theme';
  const root = document.documentElement;
  const menu = document.getElementById('theme-menu');
  const label = document.getElementById('theme-label');
  const icon = document.getElementById('theme-icon');
  const options = [...document.querySelectorAll('.theme-option')];
  const names = { '': 'System', light: 'Light', dark: 'Dark' };
  const icons = { '': '#i-monitor', light: '#i-sun', dark: '#i-moon' };
  let stored = '';
  try { stored = localStorage.getItem(themeKey) || ''; } catch { /* storage unavailable */ }
  if (!Object.hasOwn(names, stored)) stored = '';

  const update = (value) => {
    if (value) root.dataset.theme = value;
    else delete root.dataset.theme;
    if (label) label.textContent = names[value];
    if (icon) icon.setAttribute('href', icons[value]);
    if (menu?.querySelector('summary')) menu.querySelector('summary').setAttribute('aria-label', `Theme: ${names[value]}`);
    for (const option of options) {
      const active = option.dataset.themeValue === value;
      option.setAttribute('aria-pressed', active ? 'true' : 'false');
    }
  };

  update(stored);

  for (const option of options) {
    option.addEventListener('click', () => {
      const value = option.dataset.themeValue || '';
      update(value);
      try { localStorage.setItem(themeKey, value); } catch { /* storage unavailable */ }
      if (menu) menu.open = false;
    });
  }

  document.addEventListener('click', (event) => {
    if (menu?.open && !menu.contains(event.target)) menu.open = false;
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && menu?.open) menu.open = false;
  });
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
