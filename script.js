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
    setTimeout(function () {
      copyBtn.classList.remove('copied');
    }, 2000);
  }
})();
