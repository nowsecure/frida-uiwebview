# frida-uiwebview

Inspect and manipulate UIWebView-hosted GUIs through [Frida](http://frida.re).

## Example

```js
const ui = require('frida-uikit');
const web = require('frida-uiwebview');

const webView = yield ui.get(node => node.type === 'UIWebView');

const loginButton = yield web.get(webView, node => node.text === 'Log in to Spotify');
loginButton.click();
```
