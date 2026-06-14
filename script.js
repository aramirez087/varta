/* ============================================================
   Varta Landing Page — Script
   Scroll reveal, counter animation, clipboard copy, nav scroll.
   ============================================================ */

(function () {
  'use strict';

  var prefersReducedMotion = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // --- Nav scroll effect (rAF-throttled) ---
  var nav = document.getElementById('nav');
  var scrollThreshold = 40;
  var scrollTicking = false;

  function applyScrollState() {
    if (window.scrollY > scrollThreshold) {
      nav.classList.add('scrolled');
    } else {
      nav.classList.remove('scrolled');
    }
    scrollTicking = false;
  }

  function onScroll() {
    if (scrollTicking) return;
    scrollTicking = true;
    window.requestAnimationFrame(applyScrollState);
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  applyScrollState();

  // --- Scroll reveal ---
  var revealSections = document.querySelectorAll('.section');

  if ('IntersectionObserver' in window) {
    revealSections.forEach(function (el) {
      el.classList.add('reveal');
    });

    var revealObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            revealObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15 }
    );

    revealSections.forEach(function (el) {
      revealObserver.observe(el);
    });
  }

  // --- Counter animation ---
  var counters = document.querySelectorAll('.counter');

  function setCounterValue(el) {
    var target = parseFloat(el.getAttribute('data-target'));
    var suffix = el.getAttribute('data-suffix') || '';
    var decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
    el.textContent = (decimals > 0 ? target.toFixed(decimals) : String(target)) + suffix;
  }

  function animateCounter(el) {
    if (prefersReducedMotion) {
      setCounterValue(el);
      return;
    }
    var target = parseFloat(el.getAttribute('data-target'));
    var suffix = el.getAttribute('data-suffix') || '';
    var decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
    var duration = 1200;
    var startTime = null;

    function step(timestamp) {
      if (!startTime) startTime = timestamp;
      var progress = Math.min((timestamp - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      var current = target * eased;

      if (decimals > 0) {
        el.textContent = current.toFixed(decimals) + suffix;
      } else {
        el.textContent = Math.round(current) + suffix;
      }

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        setCounterValue(el);
      }
    }

    requestAnimationFrame(step);
  }

  function zeroCounter(el) {
    var suffix = el.getAttribute('data-suffix') || '';
    var decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
    el.textContent = (decimals > 0 ? (0).toFixed(decimals) : '0') + suffix;
  }

  if ('IntersectionObserver' in window && !prefersReducedMotion) {
    // Counters carry their real value in the HTML so no-JS / reduced-motion /
    // crawlers see the truth. We only zero them here — off-screen, before the
    // count-up animation — so a real visitor never sees a flash.
    counters.forEach(zeroCounter);

    var counterObserver = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            animateCounter(entry.target);
            counterObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.5 }
    );

    counters.forEach(function (el) {
      counterObserver.observe(el);
    });
  }

  // --- Clipboard copy ---
  var copyBtn = document.getElementById('copy-cargo');
  var copyHint = copyBtn ? copyBtn.querySelector('.cta-hint') : null;
  var copyStatus = copyBtn ? copyBtn.querySelector('#copy-status') : null;
  var copyResetTimer = null;

  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var text = copyBtn.getAttribute('data-copy');

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          function () { showCopied(true); },
          function () { fallbackCopy(text); }
        );
      } else {
        fallbackCopy(text);
      }
    });
  }

  function fallbackCopy(text) {
    try {
      var textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(textarea);
      showCopied(ok);
    } catch (e) {
      showCopied(false);
    }
  }

  function showCopied(ok) {
    copyBtn.classList.add('copied');
    var msg = ok ? 'copied!' : 'copy failed';
    if (copyHint) copyHint.textContent = msg;
    if (copyStatus) copyStatus.textContent = msg;
    if (copyResetTimer) clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(function () {
      copyBtn.classList.remove('copied');
      if (copyHint) copyHint.textContent = 'click to copy';
      if (copyStatus) copyStatus.textContent = '';
      copyResetTimer = null;
    }, 2000);
  }
  // --- Terminal Simulation ---
  var terminalBody = document.getElementById('terminal-body');
  var terminalOutput = document.getElementById('terminal-output');

  if (terminalBody && terminalOutput) {
    // Clear static fallback content if JavaScript is enabled
    terminalOutput.innerHTML = '';

    // Helper to create a terminal line element
    function createLine(htmlContent, isCursorLine) {
      var div = document.createElement('div');
      div.className = 'terminal-line' + (isCursorLine ? ' terminal-line--cursor' : '');
      div.innerHTML = htmlContent;
      return div;
    }

    function appendAndScroll(htmlContent, isCursorLine) {
      terminalOutput.appendChild(createLine(htmlContent, isCursorLine));
      terminalBody.scrollTop = terminalBody.scrollHeight;
    }

    var command = 'varta-watch --socket /tmp/varta.sock --udp-port 9000 --key-file /tmp/varta.key';
    var commandColored = '<span class="t-cmd">varta-watch</span> <span class="t-flag">--socket</span> <span class="t-path">/tmp/varta.sock</span> <span class="t-flag">--udp-port</span> <span class="t-num">9000</span> <span class="t-flag">--key-file</span> <span class="t-path">/tmp/varta.key</span>';
    var listeningHTML = '<span class="t-info">&bull;</span> listening on <span class="t-path">/tmp/varta.sock</span> &amp; <span class="t-path">0.0.0.0:9000 (secure UDP)</span>';
    function beatLine(ms) {
      return '<span class="t-info">&bull;</span> pid <span class="t-num">4821</span> &mdash; status: <span class="t-ok">Ok</span> &mdash; last beat: <span class="t-num">' + ms + 'ms</span> ago';
    }
    var stallHTML = '<span class="t-warn">&bull;</span> pid <span class="t-num">4821</span> &mdash; <span class="t-warn">STALL DETECTED</span> &mdash; silence: <span class="t-num">2104ms</span>';
    var recoveryHTML = '<span class="t-warn">&rarr;</span> running recovery: <span class="t-cmd">systemctl restart my-agent</span>';
    var metricsHTML = '<span class="t-info">&bull;</span> metrics &rarr; <span class="t-path">http://127.0.0.1:9100/metrics</span>';

    var simulationActive = true;
    var pendingTimers = [];
    function safeTimeout(fn, delay) {
      if (document.hidden) {
        // Skip the artificial pacing when the tab is backgrounded;
        // schedule at next visibility flip instead of firing setTimeouts blindly.
        var onVisible = function () {
          document.removeEventListener('visibilitychange', onVisible);
          safeTimeout(fn, 0);
        };
        document.addEventListener('visibilitychange', onVisible, { once: true });
        return null;
      }
      var id = setTimeout(function () {
        pendingTimers = pendingTimers.filter(function (t) { return t !== id; });
        fn();
      }, delay);
      pendingTimers.push(id);
      return id;
    }
    function clearPendingTimers() {
      pendingTimers.forEach(function (id) { clearTimeout(id); });
      pendingTimers = [];
    }

    function startTerminalSimulation() {
      if (!simulationActive) return;
      clearPendingTimers();
      terminalOutput.innerHTML = '';

      if (prefersReducedMotion) {
        // Show the final composed state immediately, no animation.
        appendAndScroll('<span class="t-prompt">$</span> ' + commandColored);
        appendAndScroll(listeningHTML);
        appendAndScroll(beatLine(12));
        appendAndScroll(beatLine(8));
        appendAndScroll(stallHTML);
        appendAndScroll(recoveryHTML);
        appendAndScroll(beatLine(6));
        appendAndScroll(metricsHTML);
        appendAndScroll('<span class="t-prompt">$</span> <span class="t-cursor">_</span>', true);
        safeTimeout(function () {
          if (!simulationActive) return;
          startTerminalSimulation();
        }, 6000);
        return;
      }

      // 1. Print command line with prompt
      var promptLine = createLine('<span class="t-prompt">$</span> <span class="t-cmd"></span><span class="t-cursor">_</span>', false);
      terminalOutput.appendChild(promptLine);

      var cmdSpan = promptLine.querySelector('.t-cmd');
      var cursorSpan = promptLine.querySelector('.t-cursor');

      var charIndex = 0;
      function typeCommand() {
        if (!simulationActive) return;
        if (charIndex < command.length) {
          var text = command.substring(0, charIndex + 1);

          // Color text flags and paths
          var colored = text
            .replace('--socket', '<span class="t-flag">--socket</span>')
            .replace('--udp-port', '<span class="t-flag">--udp-port</span>')
            .replace('--key-file', '<span class="t-flag">--key-file</span>')
            .replace('/tmp/varta.sock', '<span class="t-path">/tmp/varta.sock</span>')
            .replace('9000', '<span class="t-num">9000</span>')
            .replace('/tmp/varta.key', '<span class="t-path">/tmp/varta.key</span>');

          cmdSpan.innerHTML = colored;
          charIndex++;
          safeTimeout(typeCommand, 30 + Math.random() * 20);
        } else {
          if (cursorSpan) cursorSpan.remove();
          safeTimeout(printListening, 400);
        }
      }

      function printListening() {
        if (!simulationActive) return;
        appendAndScroll(listeningHTML);
        safeTimeout(startHeartbeats, 600);
      }

      var beatIndex = 0;
      var beatTimings = [12, 8];
      function startHeartbeats() {
        if (!simulationActive) return;
        function printBeat() {
          if (!simulationActive) return;
          if (beatIndex < beatTimings.length) {
            appendAndScroll(beatLine(beatTimings[beatIndex]));
            beatIndex++;
            safeTimeout(printBeat, 800 + Math.random() * 200);
          } else {
            safeTimeout(triggerStall, 800);
          }
        }
        printBeat();
      }

      function triggerStall() {
        if (!simulationActive) return;
        appendAndScroll(stallHTML);
        safeTimeout(runRecovery, 1200);
      }

      function runRecovery() {
        if (!simulationActive) return;
        appendAndScroll(recoveryHTML);
        safeTimeout(printRecoveredBeat, 1200);
      }

      function printRecoveredBeat() {
        if (!simulationActive) return;
        appendAndScroll(beatLine(6));
        safeTimeout(printMetrics, 800);
      }

      function printMetrics() {
        if (!simulationActive) return;
        appendAndScroll(metricsHTML);
        appendAndScroll('<span class="t-prompt">$</span> <span class="t-cursor">_</span>', true);

        // Loop back after a delay
        safeTimeout(function () {
          if (!simulationActive) return;
          beatIndex = 0;
          startTerminalSimulation();
        }, 5000);
      }

      typeCommand();
    }

    startTerminalSimulation();
  }

  // --- Mobile nav drawer ---
  var navToggle = document.getElementById('nav-toggle');
  var navMenu = document.getElementById('nav-menu');

  if (navToggle && navMenu) {
    function closeMenu() {
      navMenu.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
    }

    navToggle.addEventListener('click', function () {
      var isOpen = navMenu.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });

    navMenu.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', closeMenu);
    });

    window.addEventListener('resize', function () {
      if (window.innerWidth > 640) closeMenu();
    });
  }
})();
