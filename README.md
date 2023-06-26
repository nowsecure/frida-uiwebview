# frida-uiwebview

Inspect and manipulate UIWebView-hosted GUIs through [Frida](https://www.frida.re).

## Example

```js
import ui from 'frida-uikit';
import web from 'frida-uiwebview';

const webView = await ui.get(node => node.type === 'UIWebView');

const loginButton = await web.get(webView, node => node.text === 'Log in to Spotify');
loginButton.click();
```
