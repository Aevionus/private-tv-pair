# Private TV: pair a TV

The phone page for approving a TV to sync with a Private TV account. The TV shows a QR code that
opens this page; you sign in, check that the code here matches the TV, and enter the sync passphrase.

- It's static: there's no server of its own, and it keeps nothing.
- Everything secret happens in the phone's browser, with WebCrypto. The sync key is unlocked with the
  passphrase and sealed to the TV's one-time key before it leaves the phone.
- The TV's request travels in the address's `#` part, which browsers never send to a server.
- The project address and publishable key in `index.html` are public by design; the account's data is
  protected by row-level security and by encryption on each device.

Built from `pair-page/` in the Private TV Windows repository by `scripts/build-pair-page.js`.
