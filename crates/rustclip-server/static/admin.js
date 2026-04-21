// Minimal behaviour for the admin portal.
// - Close any open <details.action-menu> when you click outside it.
// - Wire the "Reset password" row action into the <dialog> modal.
(function () {
  'use strict';

  function closeAllMenus(except) {
    document.querySelectorAll('details.action-menu[open]').forEach(function (m) {
      if (m !== except) m.removeAttribute('open');
    });
  }

  document.addEventListener('click', function (evt) {
    var inMenu = evt.target.closest('details.action-menu');
    closeAllMenus(inMenu);
  });

  document.addEventListener('keydown', function (evt) {
    if (evt.key === 'Escape') closeAllMenus(null);
  });

  var dialog = document.getElementById('reset-password-dialog');
  if (!dialog) return;
  var form = dialog.querySelector('#reset-password-form');
  var usernameEl = dialog.querySelector('[data-field="username"]');
  var pwInput = form.querySelector('input[name="new_password"]');

  document.querySelectorAll('[data-action="reset-password"]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      form.action = '/admin/users/' + btn.dataset.userId + '/reset-password';
      usernameEl.textContent = btn.dataset.username || '';
      pwInput.value = '';
      if (typeof dialog.showModal === 'function') {
        dialog.showModal();
      } else {
        dialog.setAttribute('open', '');
      }
      closeAllMenus(null);
      // Defer focus so the browser doesn't scroll the dialog off screen.
      requestAnimationFrame(function () { pwInput.focus(); });
    });
  });

  dialog.querySelectorAll('[data-close]').forEach(function (el) {
    el.addEventListener('click', function () { dialog.close(); });
  });

  // Click outside the card dismisses it — <dialog> reports the click on the
  // backdrop as landing on the dialog element itself.
  dialog.addEventListener('click', function (evt) {
    if (evt.target === dialog) dialog.close();
  });
})();
