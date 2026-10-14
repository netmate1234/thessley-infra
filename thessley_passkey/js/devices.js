/** Passkey devices list + "Add a device" on /user/{uid}/passkey. Text only, never innerHTML. */
(function (Drupal, drupalSettings) {
  'use strict';

  // [tone, label, icon] — same icons as the WordPress plugin's device list.
  // Security score (0-100) from what the site could verify about the device's key
  // at enrolment; the same values as the WordPress module. It does not know how
  // the app protects the key (PIN, security key), only where the key lives.
  var SCORE = { strongbox: 100, tpm: 95, tee: 85, software: 40, unverified: 20 };

  var SECURITY = {
    tpm: ['good', Drupal.t('TPM 2.0 hardware'), 'chip'],
    strongbox: ['good', Drupal.t('StrongBox hardware'), 'shield-check'],
    tee: ['good', Drupal.t('TEE hardware'), 'lock'],
    software: ['warn', Drupal.t('Software only'), 'shield-alert'],
    unverified: ['quiet', Drupal.t('Unverified'), 'help']
  };

  // Small outline icons drawn with SVG DOM calls (no innerHTML, no icon font),
  // inheriting the badge's colour.
  var SVG_NS = 'http://www.w3.org/2000/svg';
  var ICONS = {
    'check-circle': [['circle', { cx: 8, cy: 8, r: 6.5 }], ['path', { d: 'M5 8.3l2.2 2.2L11 6' }]],
    'x-circle': [['circle', { cx: 8, cy: 8, r: 6.5 }], ['path', { d: 'M5.8 5.8l4.4 4.4M10.2 5.8l-4.4 4.4' }]],
    'lock': [['rect', { x: 3.5, y: 7, width: 9, height: 6.5, rx: 1.2 }], ['path', { d: 'M5.5 7V5.2a2.5 2.5 0 015 0V7' }]],
    'shield-check': [['path', { d: 'M8 1.8l5 1.8v4c0 3-2.1 5-5 6.4C5.1 12.6 3 10.6 3 7.6v-4z' }], ['path', { d: 'M5.8 8l1.6 1.6L10.4 6.4' }]],
    'shield-alert': [['path', { d: 'M8 1.8l5 1.8v4c0 3-2.1 5-5 6.4C5.1 12.6 3 10.6 3 7.6v-4z' }], ['path', { d: 'M8 5.6v3M8 10.4v.2' }]],
    'chip': [['rect', { x: 4, y: 4, width: 8, height: 8, rx: 1 }], ['path', { d: 'M6.5 1.8v2.2M9.5 1.8v2.2M6.5 12v2.2M9.5 12v2.2M1.8 6.5H4M1.8 9.5H4M12 6.5h2.2M12 9.5h2.2' }]],
    'help': [['circle', { cx: 8, cy: 8, r: 6.5 }], ['path', { d: 'M6.2 6.3a1.9 1.9 0 013.6.7c0 1.2-1.8 1.4-1.8 2.5M8 11.4v.2' }]]
  };
  function icon(name) {
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '14');
    svg.setAttribute('height', '14');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.6');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    (ICONS[name] || []).forEach(function (part) {
      var n = document.createElementNS(SVG_NS, part[0]);
      Object.keys(part[1]).forEach(function (k) { n.setAttribute(k, part[1][k]); });
      svg.appendChild(n);
    });
    return svg;
  }
  function badge(tone, label, iconName) {
    var b = document.createElement('span');
    b.className = 'thessley-pk-badge thessley-pk-' + tone;
    b.appendChild(icon(iconName));
    b.appendChild(document.createTextNode(label));
    return b;
  }

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
        // One table on wide screens; the stylesheet turns each row into a card
        // on narrow ones, using each cell's data-label as its caption.
        var table = el('table', 'thessley-pk-table');
        var head = el('tr');
        [Drupal.t('Label'), Drupal.t('Added'), Drupal.t('Last used'), Drupal.t('Status'), Drupal.t('Security'), Drupal.t('Score'), ''].forEach(function (h) { head.appendChild(el('th', null, h)); });
        table.appendChild(el('thead')).appendChild(head);
        var body = el('tbody');
        function cell(label, content) {
          var td = el('td');
          td.setAttribute('data-label', label);
          if (typeof content === 'string') { td.textContent = content; } else if (content) { td.appendChild(content); }
          return td;
        }
        devices.forEach(function (d) {
          var tr = el('tr', d.revoked ? 'thessley-pk-revoked' : '');
          tr.appendChild(cell(Drupal.t('Label'), d.label || Drupal.t('Unnamed device')));
          tr.appendChild(cell(Drupal.t('Added'), when(d.created, false)));
          tr.appendChild(cell(Drupal.t('Last used'), when(d.last_used, true)));
          tr.appendChild(cell(Drupal.t('Status'), d.revoked ? badge('bad', Drupal.t('Revoked'), 'x-circle') : badge('good', Drupal.t('Active'), 'check-circle')));
          var sec = SECURITY[d.security] || SECURITY.unverified;
          tr.appendChild(cell(Drupal.t('Security'), badge(sec[0], sec[1], sec[2])));
          var score = SCORE[SECURITY[d.security] ? d.security : 'unverified'];
          tr.appendChild(cell(Drupal.t('Score'), d.revoked ? '\u2014' : score + ' / 100'));
          var act = cell('', null);
          act.className = 'thessley-pk-actions';
          if (!d.revoked) {
            var b = el('button', 'button button--small', Drupal.t('Revoke'));
            b.type = 'button';
            b.addEventListener('click', function () {
              if (window.confirm(Drupal.t('Are you sure you want to revoke "@label"? It will no longer be able to approve logins.', { '@label': d.label || Drupal.t('this device') }))) {
                revoke(d.id, b);
              }
            });
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
          hint.textContent = Drupal.t("Scan this with the Thessley Passkey app on the device you're enrolling, or tap the link below on that same device.");
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
