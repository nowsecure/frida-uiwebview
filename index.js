'use strict';

let DUMP_DOM_SCRIPT, SET_ELEMENT_TEXT_SCRIPT, CLICK_ELEMENT_SCRIPT, TAP_ELEMENT_SCRIPT, GET_ELEMENT_RECT_SCRIPT, IS_ELEMENT_VISIBLE_SCRIPT;

function get(webViewNode, predicate) {
  return new Promise(function (resolve, reject) {
    let tries = 0;
    function tryResolve() {
      const layout = WebNode.fromWebView(webViewNode.instance);
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
    tryResolve();
  });
}

function WebNode(data, webView) {
  this._webView = webView;

  for (let key in data) {
    if (data.hasOwnProperty(key) && key !== 'children') {
      this[key] = data[key];
    }
  }

  this.children = data.children.map(childData => {
    return new WebNode(childData, webView);
  });
}

WebNode.fromWebView = function (webView) {
  const rawResult = webView.stringByEvaluatingJavaScriptFromString_('JSON.stringify((' + DUMP_DOM_SCRIPT + ').call(this));').toString();
  if (rawResult.length === 0)
    throw new Error('UIWebView not ready');
  const result = JSON.parse(rawResult);
  if (result.error) {
    const e = result.error;
    throw new Error(e.message + ' at: ' + e.stack);
  }
  return new WebNode(result, webView);
};

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
  setText(text) {
    perform(this._webView, SET_ELEMENT_TEXT_SCRIPT, {
      ref: this.ref,
      text: text
    });
  },
  click() {
    perform(this._webView, CLICK_ELEMENT_SCRIPT, {
      ref: this.ref
    });
  },
  tap() {
    perform(this._webView, TAP_ELEMENT_SCRIPT, {
      ref: this.ref
    });
  },
  getRect() {
    return perform(this._webView, GET_ELEMENT_RECT_SCRIPT, {
      ref: this.ref
    }).rect;
  },
  isVisible() {
    return perform(this._webView, IS_ELEMENT_VISIBLE_SCRIPT, {
      ref: this.ref
    }).visible;
  }
};

function perform(webView, script, params) {
  const rawResult = webView.stringByEvaluatingJavaScriptFromString_('JSON.stringify((' + script + ').call(this, ' + JSON.stringify(params) + '));');
  const result = JSON.parse(rawResult.toString());
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
    var ev = new Event('change');
    element.dispatchEvent(ev);
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

  var vWidth = window.innerWidth || doc.documentElement.clientWidth;
  var vHeight = window.innerHeight || doc.documentElement.clientHeight;
  if (rect.right < 0 || rect.bottom < 0 || rect.left > vWidth || rect.top > vHeight) {
    return {
      visible: false
    };
  }

  var efp = function(x, y) {
    return document.elementFromPoint(x, y)
  };

  // Return true if any of its four corners are visible
  return {
    visible: (
      element.contains(efp(rect.left, rect.top)) ||
      element.contains(efp(rect.right, rect.top)) ||
      element.contains(efp(rect.right, rect.bottom)) ||
      element.contains(efp(rect.left, rect.bottom))
    )
  };
}`;

module.exports = {
  get: get,
  WebNode: WebNode
};
