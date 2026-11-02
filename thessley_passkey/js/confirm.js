/** "Confirm with the app" page: draws the QR and polls until approved. */
(function (Drupal, drupalSettings) {
  'use strict';

  Drupal.behaviors.thessleyPasskeyConfirm = {
    attach: function () {
      var cfg = drupalSettings.thessleyPasskey;
      var qr = document.getElementById('thessley-pk-confirm-qr');
      if (!cfg || !qr || qr.getAttribute('data-thessley-ready')) { return; }
      qr.setAttribute('data-thessley-ready', '1');

      ThessleyQR.render(qr, cfg.appLink, 340);
      var statusEl = document.getElementById('thessley-pk-confirm-status');
      var poll = setInterval(function () {
        fetch(cfg.status, { credentials: 'same-origin' })
          .then(function (r) { return r.json(); })
          .then(function (s) {
            if (s.status === 'approved') { clearInterval(poll); window.location.href = s.redirect_to; }
            if (s.status === 'denied' || s.status === 'expired') {
              clearInterval(poll);
              statusEl.textContent = '';
              statusEl.appendChild(document.createTextNode(Drupal.t('Request @status — ', { '@status': s.status })));
              var a = document.createElement('a');
              a.href = cfg.login;
              a.textContent = Drupal.t('log in again to retry');
              statusEl.appendChild(a);
            }
          });
      }, 1500);
    }
  };
})(Drupal, drupalSettings);
