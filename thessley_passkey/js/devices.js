/** Passkey devices list + "Add a device" on /user/{uid}/passkey. Text only, never innerHTML. */
(function (Drupal, drupalSettings) {
  'use strict';

  var SECURITY = {
    strongbox: ['good', Drupal.t('StrongBox hardware')],
    tee: ['good', Drupal.t('TEE hardware')],
    software: ['warn', Drupal.t('Software only')],
    unverified: ['quiet', Drupal.t('Unverified')]
  };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text != null) { n.textContent = text; }
    return n;
  }
  function when(ts, withTime) {
    if (!ts) { return '—'; }
    var d = new Date(ts * 1000);
    return withTime ? d.toLocaleString() : d.toLocaleDateString();
  }

  Drupal.behaviors.thessleyPasskeyDevices = {
    attach: function () {
      var cfg = drupalSettings.thessleyPasskey;
      var wrap = document.getElementById('thessley-pk-devices-wrap');
      if (!cfg || !wrap || wrap.getAttribute('data-thessley-ready')) { return; }
      wrap.setAttribute('data-thessley-ready', '1');

      var token = null;
      function csrf() {
        if (token) { return Promise.resolve(token); }
        return fetch(cfg.urls.token, { credentials: 'same-origin' }).then(function (r) { return r.text(); }).then(function (t) { token = t; return t; });
      }

      function render(devices) {
        wrap.textContent = '';
        if (!devices.length) { wrap.appendChild(el('p', 'thessley-pk-desc', Drupal.t('No devices enrolled yet.'))); return; }
        var table = el('table', 'thessley-pk-table');
        var head = el('tr');
        [Drupal.t('Label'), Drupal.t('Added'), Drupal.t('Last used'), Drupal.t('Status'), Drupal.t('Security'), ''].forEach(function (h) { head.appendChild(el('th', null, h)); });
        table.appendChild(el('thead')).appendChild(head);
        var body = el('tbody');
        devices.forEach(function (d) {
          var tr = el('tr');
          tr.appendChild(el('td', null, d.label || Drupal.t('Unnamed device')));
          tr.appendChild(el('td', null, when(d.created, false)));
          tr.appendChild(el('td', null, when(d.last_used, true)));
          var st = el('td'); st.appendChild(el('span', 'thessley-pk-badge thessley-pk-' + (d.revoked ? 'bad' : 'good'), d.revoked ? Drupal.t('Revoked') : Drupal.t('Active'))); tr.appendChild(st);
          var sec = SECURITY[d.security] || SECURITY.unverified;
          var sc = el('td'); sc.appendChild(el('span', 'thessley-pk-badge thessley-pk-' + sec[0], sec[1])); tr.appendChild(sc);
          var act = el('td');
          if (!d.revoked) {
            var b = el('button', 'button button--small', Drupal.t('Revoke'));
            b.type = 'button';
            b.addEventListener('click', function () { revoke(d.id, b); });
            act.appendChild(b);
          }
          tr.appendChild(act);
          body.appendChild(tr);
        });
        table.appendChild(body);
        wrap.appendChild(table);
      }

      function refresh() {
        return fetch(cfg.urls.devices + '?uid=' + cfg.uid, { credentials: 'same-origin' })
          .then(function (r) { return r.json(); })
          .then(function (data) { if (data && data.devices) { render(data.devices); } });
      }

      function revoke(id, btn) {
        btn.disabled = true;
        csrf().then(function (t) {
          return fetch(cfg.urls.revoke.replace('/0/revoke', '/' + id + '/revoke'), { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': t } });
        }).then(refresh).catch(function () { btn.disabled = false; });
      }

      render(cfg.devices || []);

      var start = document.getElementById('thessley-pk-enroll-start');
      if (!start) { return; }
      var hint = document.getElementById('thessley-pk-enroll-hint');
      var status = document.getElementById('thessley-pk-enroll-status');
      var qrBox = document.getElementById('thessley-pk-enroll-qr');

      start.addEventListener('click', function () {
        start.disabled = true;
        hint.textContent = Drupal.t('Starting…');
        csrf().then(function (t) {
          return fetch(cfg.urls.enrollStart, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': t } });
        }).then(function (r) { return r.json(); }).then(function (data) {
          if (!data || !data.app_link) {
            hint.textContent = Drupal.t('Could not start enrollment: @why', { '@why': data && data.message ? data.message : Drupal.t('no response from the server.') });
            start.disabled = false;
            return;
          }
          start.style.display = 'none';
          hint.textContent = Drupal.t("Scan this with the device you're enrolling, or tap the link below on that same device.");
          qrBox.style.display = 'inline-block';
          qrBox.textContent = '';
          ThessleyQR.render(qrBox, data.app_link, 236);
          var open = el('a', 'button button--primary thessley-pk-open', Drupal.t('Open on this device'));
          open.href = data.app_link;
          status.textContent = '';
          status.appendChild(open);

          var poll = setInterval(function () {
            fetch(cfg.urls.enrollStatus.replace('__ID__', encodeURIComponent(data.request_id)), { credentials: 'same-origin' })
              .then(function (r) { return r.json(); }).then(function (s) {
                if (s.status === 'approved') {
                  clearInterval(poll);
                  qrBox.style.display = 'none';
                  status.textContent = '';
                  hint.textContent = Drupal.t('Added "@label".', { '@label': s.label || Drupal.t('device') });
                  refresh();
                } else if (s.status === 'expired') {
                  clearInterval(poll);
                  qrBox.style.display = 'none';
                  hint.textContent = Drupal.t('Request expired — try again.');
                  status.textContent = '';
                  start.style.display = '';
                  start.disabled = false;
                }
              });
          }, 1500);
        }).catch(function (err) {
          hint.textContent = Drupal.t('Network error starting enrollment: @e', { '@e': err.message });
          start.disabled = false;
        });
      });
    }
  };
})(Drupal, drupalSettings);
