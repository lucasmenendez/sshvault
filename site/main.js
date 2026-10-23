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
