(() => {
  const dialog = document.getElementById('approval-dialog');
  const content = document.getElementById('approval-content');
  const feedback = document.getElementById('approval-feedback');
  let loading, saving = false;
  document.addEventListener('click', async event => {
    const close = event.target.closest('[data-approval-close]');
    if (close && dialog.contains(close)) {
      if (!saving) dialog.close();
      return;
    }
    const link = event.target.closest('[data-approval-form]');
    if (!link) return;
    event.preventDefault();
    loading?.abort();
    loading = new AbortController();
    content.textContent = 'Loading approval details…';
    feedback.textContent = '';
    dialog.showModal();
    try {
      const response = await fetch(link.dataset.approvalForm, {cache:'no-store', signal:loading.signal});
      if (!response.ok || response.redirected) throw new Error('Could not load approval details. Close this dialog and try again, or sign in again.');
      const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
      if (!doc.querySelector('form input[name="from_finding"]')) throw new Error('Approval details are unavailable.');
      if (!dialog.open) return;
      content.replaceChildren(...doc.body.childNodes);
      content.querySelector('input[name="name"]').focus();
    } catch (error) {
      if (error.name !== 'AbortError' && dialog.open) content.textContent = error.message;
    }
  });
  dialog.addEventListener('cancel', event => { if (saving) event.preventDefault(); });
  dialog.addEventListener('close', () => loading?.abort());
  dialog.addEventListener('submit', async event => {
    event.preventDefault();
    if (saving) return;
    const form = event.target;
    const errorBox = form.querySelector('[data-approval-error]');
    errorBox.hidden = true;
    const data = new FormData(form);
    saving = true;
    dialog.querySelectorAll('button').forEach(button => button.disabled = true);
    try {
      const response = await fetch(form.action, {method:'POST', body:data, headers:{Accept:'application/json'}});
      if (response.redirected) throw new Error('Your session has expired. Sign in again before saving.');
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Could not save approval. Check the fields and try again.');
      dialog.close();
      feedback.textContent = 'Approval saved.';
      if (typeof refreshLive === 'function') await refreshLive(true);
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.hidden = false;
    } finally {
      saving = false;
      dialog.querySelectorAll('button').forEach(button => button.disabled = false);
    }
  });
})();
