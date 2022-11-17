export default async function dynamic_ffjavascript() {
  let isBrowser;
  let lib;
  try {
    if (window) isBrowser = true;
    else isBrowser = false;
  } catch (err) {
    isBrowser = false;
  }
  if (isBrowser) {
    lib = await import('ffjavascript-browser');
    window.ff = lib;
  } else {
    lib = await import('ffjavascript');
    global.ff = lib;
  }
}
