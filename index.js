let DUMP_DOM_SCRIPT, SET_ELEMENT_TEXT_SCRIPT, CLICK_ELEMENT_SCRIPT, TAP_ELEMENT_SCRIPT, GET_ELEMENT_RECT_SCRIPT, IS_ELEMENT_VISIBLE_SCRIPT;
const pendingBlocks = new Set();
const MAX_RETRIES = 3;
const RETRY_DELAY = 300;

export function get(webViewNode, predicate, options) {
  return new Promise(function (resolve, reject) {
    let tries = 0;
    async function tryResolve() {
      const layout = await WebNode.fromWebView(webViewNode.instance, options);
      if (layout !== null) {
        const node = layout.find(predicate);
        if (node !== null) {
          resolve(node);
          return;
        }
      }

      // TODO: configurable timeout and retry interval
      tries++;
      if (tries < 40) {
        setTimeout(tryResolve, 500);
      } else {
        reject(new Error('Timed out'));
      }
    }
    return tryResolve();
  });
}

export function WebNode(data, webView, options) {
  this._webView = webView;
  this._options = getOptions(options);

  for (let key in data) {
    if (data.hasOwnProperty(key) && key !== 'children') {
      this[key] = data[key];
    }
  }

  this.children = data.children.map(childData => {
    return new WebNode(childData, webView, options);
  });
}

WebNode.fromWebView = async function (webView, options) {
  const mergedOptions = getOptions(options);
  const result = await perform(webView, DUMP_DOM_SCRIPT, mergedOptions);
  return new WebNode(result, webView, mergedOptions);
};

function getOptions(options) {
  const merged = {
    enableJavascript: false
  };

  Object.assign(merged, options);

  return merged;
}

WebNode.prototype = {
  forEach(fn) {
    fn(this);
    this.children.forEach(child => child.forEach(fn));
  },
  find(predicate) {
    if (predicate(this)) {
      return this;
    }

    const children = this.children;
    for (let i = 0; i !== children.length; i++) {
      const child = children[i].find(predicate);
      if (child !== null) {
        return child;
      }
    }

    return null;
  },
  async setText(text) {
    return perform(this._webView, SET_ELEMENT_TEXT_SCRIPT, this._options, {
      ref: this.ref,
      text: text
    });
  },
  async click() {
    return perform(this._webView, CLICK_ELEMENT_SCRIPT, this._options, {
      ref: this.ref
    });
  },
  async tap() {
    return perform(this._webView, TAP_ELEMENT_SCRIPT, this._options, {
      ref: this.ref
    });
  },
  async getRect() {
    const result = await perform(this._webView, GET_ELEMENT_RECT_SCRIPT, this._options, {
      ref: this.ref
    });
    return result.rect;
  },
  async isVisible() {
    const result = await perform(this._webView, IS_ELEMENT_VISIBLE_SCRIPT, this._options, {
      ref: this.ref
    });
    return result.visible;
  }
};

function perform(webView, script, options, params) {
  const paramsString = (params !== undefined) ? `, ${JSON.stringify(params)}` : '';
  const scriptString = `JSON.stringify((${script}).call(this${paramsString}));`;

  if ('evaluateJavaScript_completionHandler_' in webView &&
      'configuration' in webView) {
    // WKWebView
    return new Promise((resolve, reject) => {
      const completionHandler = new ObjC.Block({
        retType: 'void',
        argTypes: ['object', 'pointer'],
        implementation: function (rawResult, error) {
          pendingBlocks.delete(completionHandler);

          if (!error.isNull()) {
            const err = new ObjC.Object(error);
            reject(new Error(err.toString()));
            return;
          }
          try {
            const result = parseResult(rawResult);
            resolve(result);
          } catch (e) {
            reject(e);
          }
        }
      });
      pendingBlocks.add(completionHandler);
      if (isMainThread()) {
        fireEvaluation();
      } else {
        ObjC.schedule(ObjC.mainQueue, fireEvaluation);
      }

      function fireEvaluation (retries = MAX_RETRIES) {
        if (webView.isLoading()) {
          if (retries - 1 <= 0) {
            pendingBlocks.delete(completionHandler);
            reject(new Error('WKWebView not ready'));
          } else {
            setTimeout(() => {
              ObjC.schedule(ObjC.mainQueue, () => fireEvaluation(retries - 1));
            }, RETRY_DELAY);
          }
          return;
        }
        if (options.enableJavascript) {
          webView.configuration().preferences().setJavaScriptEnabled_(true);
        }
        webView.evaluateJavaScript_completionHandler_(scriptString, completionHandler);
      }
    });
  } else if ('stringByEvaluatingJavaScriptFromString_' in webView) {
    // UIWebView
    return new Promise((resolve, reject) => {
      if (isMainThread()) {
        evaluateJavascript();
      } else {
        ObjC.schedule(ObjC.mainQueue, () => {
          evaluateJavascript();
        });
      }

      function evaluateJavascript() {
        const rawResult = webView.stringByEvaluatingJavaScriptFromString_(scriptString);
        try {
          const result = parseResult(rawResult);
          resolve(result);
        } catch (e) {
          reject(e);
        }
      }
    });
  } else {
    throw new Error(`Unsupported kind of webview: ${webView.$className}`);
  }
}

function isMainThread() {
  return ObjC.classes.NSThread.isMainThread();
}

function parseResult(rawResult) {
  const strResult = rawResult.toString();
  if (strResult.length === 0) {
    throw new Error('UIWebView not ready');
  }
  const result = JSON.parse(strResult);
  if (result.error) {
    const e = result.error;
    throw new Error(e.message + ' at: ' + e.stack);
  }
  return result;
}

DUMP_DOM_SCRIPT = `function dumpDom() {
  var elementByRef = {};
  var nextRef = 1;
  var ignoredElementNames = {
    'link': true,
    'meta': true,
    'script': true,
    'style': true,
    'title': true
  };

  window._fridaElementByRef = elementByRef;

  try {
    return dumpElement(document.documentElement);
  } catch (e) {
    return {
      error: {
        message: e.message,
        stack: e.stack
      }
    };
  }

  function dumpElement(element) {
    var ref = nextRef++;
    elementByRef[ref] = element;

    var name = element.localName;

    var data = {
      ref: ref,
      name: name,
      className: element.className,
      children: []
    };

    if (element.id) {
      data.id = element.id;
    }

    if (name === 'input') {
      data.type = element.type || 'text';
      data.fieldName = element.name;
    }

    if (name === 'input' || name === 'button') {
      data.enabled = !element.disabled;
    }

    if (name === 'input' && element.placeholder) {
      data.placeholder = element.placeholder;
    }

    var i;

    var childNodes = element.childNodes;
    for (i = 0; i !== childNodes.length; i++) {
      var childNode = childNodes[i];
      if (childNode.nodeType === Node.TEXT_NODE) {
        var text = data.text || '';
        text += childNode.wholeText;
        data.text = text;
      }
    }

    var childElements = element.children;
    if (childElements !== undefined) {
      var children = data.children;
      for (i = 0; i !== childElements.length; i++) {
        var childElement = childElements[i];
        if (!ignoredElementNames[childElement.localName]) {
          children.push(dumpElement(childElement));
        }
      }
    }

    return data;
  }
}`;

SET_ELEMENT_TEXT_SCRIPT = `function setElementText(params) {
  try {
    var element = window._fridaElementByRef[params.ref];
    element.value = params.text;
    var changeEvent = new Event('change');
    var inputEvent = new Event('input');
    element.dispatchEvent(changeEvent);
    element.dispatchEvent(inputEvent);
    return {};
  } catch (e) {
    return {
      error: {
        message: e.message,
        stack: e.stack
      }
    };
  }
}`;

CLICK_ELEMENT_SCRIPT = `function clickElement(params) {
  try {
    var element = window._fridaElementByRef[params.ref];
    element.disabled = false;
    element.click();
    return {};
  } catch (e) {
    return {
      error: {
        message: e.message,
        stack: e.stack
      }
    };
  }
}`;

TAP_ELEMENT_SCRIPT = `function tapElement(params) {
  try {
    var element = window._fridaElementByRef[params.ref];
    element.disabled = false;
    var identifier = Date.now();
    fire(element, 'touchstart', identifier);
    fire(element, 'touchend', identifier);
    return {};
  } catch (e) {
    return {
      error: {
        message: e.message,
        stack: e.stack
      }
    };
  }

  function fire(element, type, identifier) {
    var touch = document.createTouch(window, element, identifier, 0, 0, 0, 0);

    var touches = document.createTouchList(touch);
    var targetTouches = document.createTouchList(touch);
    var changedTouches = document.createTouchList(touch);

    var event = document.createEvent('TouchEvent');
    event.initTouchEvent(type, true, true, window, null, 0, 0, 0, 0, false, false, false, false, touches, targetTouches, changedTouches, 1, 0);
    element.dispatchEvent(event);
  }
}`;

GET_ELEMENT_RECT_SCRIPT = `function getElementRect(params) {
  var element = window._fridaElementByRef[params.ref];
  var rect = element.getBoundingClientRect();
  return {
    rect: [[rect.left, rect.top], [rect.width, rect.height]]
  };
}`;

/*
 * Adapted from: http://stackoverflow.com/a/15203639/5418401
 */
IS_ELEMENT_VISIBLE_SCRIPT = `function isElementVisible(params) {
  var element = window._fridaElementByRef[params.ref];
  var rect = element.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) {
    return {
      visible: false
    };
  }

  var vWidth = window.innerWidth || document.documentElement.clientWidth;
  var vHeight = window.innerHeight || document.documentElement.clientHeight;
  if (rect.right < 0 || rect.bottom < 0 || rect.left > vWidth || rect.top > vHeight) {
    return {
      visible: false
    };
  }

  var efp = function(x, y) {
    return document.elementFromPoint(x, y)
  };

  var rcx = rect.left + rect.width / 2;
  var rcy = rect.top + rect.height / 2;

  var elementsAround = [
    efp(rect.left, rect.top),
    efp(rect.right, rect.top),
    efp(rect.right, rect.bottom),
    efp(rect.left, rect.bottom),
    efp(rcx, rcy)
  ];

  var anyCornerVisible = false;

  elementsAround.forEach(function (testElement) {
    if (testElement === null) {
      return;
    }

    anyCornerVisible = anyCornerVisible ||
      element.contains(testElement) ||
      testElement.contains(element);
  });

  return {
    visible: anyCornerVisible
  };
}`;
