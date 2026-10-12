// OpenPGP logs caught, expected decryption failures when NODE_ENV=development.
// Searching hidden-recipient envelopes (including privacy-padding decoys) must
// fail for envelopes addressed to other keys. Next's dev overlay treats those
// console errors as crashes even though Vera catches them and checks access.
// Disable only this library's diagnostic flag, as its production bundle does.
// Do not change decryption, signature verification, exceptions or app logging.
module.exports = function openpgpBrowserDebug(source) {
  this.cacheable?.();
  if (!/[\\/]node_modules[\\/]openpgp[\\/]dist[\\/]openpgp(?:\.min)?\.m?js$/.test(this.resourcePath)) {
    throw new Error('OpenPGP debug loader must only process the browser bundle');
  }
  const flag = /process\.env\.NODE_ENV\s*===\s*(['"])development\1|(['"])development\2\s*===\s*process\.env\.NODE_ENV/g;
  if (Array.from(source.matchAll(flag)).length !== 1) {
    throw new Error('OpenPGP debug flag changed; review the browser logging integration');
  }
  // Parentheses preserve token boundaries in the minified `return"..."` form.
  return source.replace(flag, '(false)');
};
