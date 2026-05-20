/* ============================================================
   Varta Landing Page — Script
   Scroll reveal, counter animation, clipboard copy, nav scroll.
   ============================================================ */

(function () {
  'use strict';

  // --- Nav scroll effect ---
  var nav = document.getElementById('nav');
  var scrollThreshold = 40;

  function onScroll() {
    if (window.scrollY > scrollThreshold) {
      nav.classList.add('scrolled');
    } else {
      nav.classList.remove('scrolled');
    }
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

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

  function animateCounter(el) {
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
        if (decimals > 0) {
          el.textContent = target.toFixed(decimals) + suffix;
        } else {
          el.textContent = target + suffix;
        }
      }
    }

    requestAnimationFrame(step);
  }

  if ('IntersectionObserver' in window) {
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

  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      var text = copyBtn.getAttribute('data-copy');

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(showCopied);
      } else {
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try { document.execCommand('copy'); showCopied(); } catch (e) {}
        document.body.removeChild(textarea);
      }
    });
  }

  function showCopied() {
    copyBtn.classList.add('copied');
    if (copyHint) {
      copyHint.textContent = 'copied!';
    }
    setTimeout(function () {
      copyBtn.classList.remove('copied');
      if (copyHint) {
        copyHint.textContent = 'click to copy';
      }
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

    var command = 'varta-watch --socket /tmp/varta.sock --udp-port 9000 --key-file /tmp/varta.key';
    var simulationActive = true;

    function startTerminalSimulation() {
      if (!simulationActive) return;
      terminalOutput.innerHTML = '';

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
          setTimeout(typeCommand, 30 + Math.random() * 20);
        } else {
          if (cursorSpan) cursorSpan.remove();
          setTimeout(printListening, 400);
        }
      }
      
      function printListening() {
        if (!simulationActive) return;
        var listeningLine = createLine('<span class="t-info">&bull;</span> listening on <span class="t-path">/tmp/varta.sock</span> &amp; <span class="t-path">0.0.0.0:9000 (secure UDP)</span>');
        terminalOutput.appendChild(listeningLine);
        terminalBody.scrollTop = terminalBody.scrollHeight;
        setTimeout(startHeartbeats, 600);
      }
      
      var beatCount = 0;
      function startHeartbeats() {
        if (!simulationActive) return;
        function printBeat() {
          if (!simulationActive) return;
          if (beatCount < 2) {
            var ms = [12, 8][beatCount];
            var line = createLine('<span class="t-info">&bull;</span> pid <span class="t-num">4821</span> &mdash; status: <span class="t-ok">Ok</span> &mdash; last beat: <span class="t-num">' + ms + 'ms</span> ago');
            terminalOutput.appendChild(line);
            terminalBody.scrollTop = terminalBody.scrollHeight;
            
            beatCount++;
            setTimeout(printBeat, 800 + Math.random() * 200);
          } else {
            setTimeout(triggerStall, 800);
          }
        }
        printBeat();
      }
      
      function triggerStall() {
        if (!simulationActive) return;
        var stallLine = createLine('<span class="t-warn">&bull;</span> pid <span class="t-num">4821</span> &mdash; <span class="t-warn">STALL DETECTED</span> &mdash; silence: <span class="t-num">2104ms</span>');
        terminalOutput.appendChild(stallLine);
        terminalBody.scrollTop = terminalBody.scrollHeight;
        
        setTimeout(runRecovery, 1200);
      }
      
      function runRecovery() {
        if (!simulationActive) return;
        var recoveryLine = createLine('<span class="t-warn">&rarr;</span> running recovery: <span class="t-cmd">systemctl restart my-agent</span>');
        terminalOutput.appendChild(recoveryLine);
        terminalBody.scrollTop = terminalBody.scrollHeight;
        
        setTimeout(printMetrics, 1200);
      }
      
      function printMetrics() {
        if (!simulationActive) return;
        var metricsLine = createLine('<span class="t-info">&bull;</span> metrics &rarr; <span class="t-path">http://127.0.0.1:9100/metrics</span>');
        terminalOutput.appendChild(metricsLine);
        
        var nextPromptLine = createLine('<span class="t-prompt">$</span> <span class="t-cursor">_</span>', true);
        terminalOutput.appendChild(nextPromptLine);
        terminalBody.scrollTop = terminalBody.scrollHeight;
        
        // Loop back after a delay
        setTimeout(function() {
          if (!simulationActive) return;
          beatCount = 0;
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
