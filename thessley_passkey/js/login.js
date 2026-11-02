/**
 * Passkey Login on /user/login.
 *
 * Without the username prompt it starts a request on load and shows the QR.
 * With it there are two steps: (1) a username box, (2) the QR for that
 * account, plus — for "Password or the app" — the normal password form with
 * the username filled in. A wrong password reloads the page with the
 * username kept in the form, which carries straight on to step 2.
 */
(function (Drupal, drupalSettings) {
  'use strict';

  Drupal.behaviors.thessleyPasskeyLogin = {
    attach: function (context) {
      var box = document.getElementById('thessley-passkey-box');
      var cfg = drupalSettings.thessleyPasskeyLogin;
      if (!box || !cfg || box.getAttribute('data-thessley-ready')) { return; }
      box.setAttribute('data-thessley-ready', '1');

      var root     = document.documentElement;
      var qrEl     = document.getElementById('thessley-passkey-qr');
      var linkEl   = document.getElementById('thessley-passkey-link');
      var wrap     = document.getElementById('thessley-passkey-qrwrap');
      var userIn   = document.getElementById('thessley-passkey-username');
      var goBtn    = document.getElementById('thessley-passkey-continue');
      var changeEl = document.getElementById('thessley-passkey-change');
      var idBox    = document.getElementById('thessley-passkey-id');
      var msg      = document.getElementById('thessley-passkey-msg');
      var poll = null, lastName = '', gen = 0;

      // The typed name is also remembered for this tab and used only to carry
      // on after a failed login (Drupal keeps it in the form for a real
      // account; this covers the rest). Cleared as soon as it is not needed.
      var KEY = 'thessleyPkUser';
      function remember(n) { try { sessionStorage.setItem(KEY, n); } catch (e) {} }
      function recall() { try { return sessionStorage.getItem(KEY) || ''; } catch (e) { return ''; } }
      function forget() { try { sessionStorage.removeItem(KEY); } catch (e) {} }

      function stop() { if (poll) { clearInterval(poll); poll = null; } }
      function say(text) { msg.textContent = text || ''; }

      function stepOne() {
        gen++; stop(); say(''); forget();
        qrEl.innerHTML = '';
        wrap.style.display = 'none';
        idBox.style.display = '';
        if (cfg.optional) { root.classList.add('thessley-pk-step1'); }
        userIn.focus();
      }

      function stepTwo(name) {
        remember(name);
        idBox.style.display = 'none';
        wrap.style.display = '';
        if (cfg.optional) {
          root.classList.remove('thessley-pk-step1');
          var login = document.getElementById('edit-name');
          var pass = document.getElementById('edit-pass');
          if (login) { login.value = name; }
          if (pass) { pass.focus(); }
        }
      }

      function ended(status) {
        stop();
        qrEl.innerHTML = '';
        say('Request ' + status + '. ');
        var again = document.createElement('a');
        again.href = '#';
        again.textContent = Drupal.t('Get a new code');
        again.addEventListener('click', function (e) { e.preventDefault(); begin(lastName); });
        msg.appendChild(again);
      }

      function begin(name) {
        var my = ++gen;
        stop(); say('');
        lastName = name || '';

        var opts = { method: 'POST', credentials: 'same-origin' };
        if (cfg.identify) {
          opts.headers = { 'Content-Type': 'application/json' };
          opts.body = JSON.stringify({ username: name });
        }

        fetch(cfg.start, opts).then(function (r) { return r.json(); }).then(function (data) {
          if (my !== gen) { return; }
          if (!data || !data.app_link) {
            var why = data && data.message ? data.message : Drupal.t('Could not start the Thessley Passkey app login. Try again.');
            if (cfg.identify) { stepOne(); }
            say(why);
            return;
          }

          qrEl.innerHTML = '';
          ThessleyQR.render(qrEl, data.app_link, 340);
          linkEl.href = data.app_link;
          if (cfg.identify) { stepTwo(name); }

          poll = setInterval(function () {
            fetch(cfg.status.replace('__ID__', encodeURIComponent(data.request_id)), { credentials: 'same-origin' })
              .then(function (r) { return r.json(); })
              .then(function (s) {
                if (my !== gen) { return; }
                if (s.status === 'approved') { stop(); forget(); window.location.href = s.redirect_to; }
                else if (s.status === 'denied' || s.status === 'expired') { ended(s.status); }
              });
          }, 1500);
        }).catch(function () {
          if (my === gen) { say(Drupal.t('Network error. Try again.')); }
        });
      }

      if (cfg.identify) {
        function submitName() {
          var name = userIn.value.trim();
          if (name) { begin(name); }
        }
        goBtn.addEventListener('click', submitName);
        userIn.addEventListener('keydown', function (e) {
          if (e.key === 'Enter') { e.preventDefault(); submitName(); }
        });
        changeEl.addEventListener('click', function (e) { e.preventDefault(); stepOne(); });

        var typed = document.getElementById('edit-name');
        var failed = document.querySelector('.messages--error, .messages.error, [data-drupal-messages] [role="alert"]');
        var carried = (typed && typed.value.trim()) || (failed ? recall() : '');
        if (carried) {
          userIn.value = carried;
          begin(carried);
        } else {
          forget();
        }
      } else {
        begin('');
      }
    }
  };
})(Drupal, drupalSettings);
