/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "platform/mac/webview_file_input_bridge.h"

#include "base/assertion.h"
#include "base/platform/mac/base_utilities_mac.h"
#include "core/mac_protected_path_access.h"

#include <WebKit/WebKit.h>
#include <objc/runtime.h>

namespace {

using OpenPanelImplementation
	= void (*)(id, SEL, WKWebView *, WKOpenPanelParameters *, WKFrameInfo *,
			   void (^)(NSArray<NSURL *> *));

OpenPanelImplementation OriginalOpenPanelImplementation = nullptr;

void GuardedOpenPanel(id target, SEL selector, WKWebView *webView,
					  WKOpenPanelParameters *parameters, WKFrameInfo *frame,
					  void (^completionHandler)(NSArray<NSURL *> *)) {
	Expects(OriginalOpenPanelImplementation != nullptr);
	auto guardedCompletion = ^(NSArray<NSURL *> *urls) {
	  if (!urls) {
		  completionHandler(nil);
		  return;
	  }
	  auto validSelection = true;
	  auto paths = QStringList();
	  for (NSURL *url in urls) {
		  const auto path = [url path];
		  if (!url || ![url isFileURL] || !path) {
			  validSelection = false;
			  continue;
		  }
		  const auto localPath = Platform::NS2QString(path);
		  if (localPath.isEmpty()) {
			  validSelection = false;
			  continue;
		  }
		  paths.push_back(localPath);
	  }
	  const auto completed
		  = Core::MacProtectedPath::CompleteWebViewFileInputSelectionIfAllowed(
			  paths,
			  [](const QString &path) {
				  return Core::MacProtectedPath::CheckExternalPathForUse(
					  Core::MacProtectedPath::Operation::Read, path,
					  "webview.html-file-input");
			  },
			  [&](const QStringList &) {
				  if (validSelection) {
					  completionHandler(urls);
				  }
			  });
	  if (!validSelection || !completed) {
		  completionHandler(nil);
	  }
	};
	OriginalOpenPanelImplementation(target, selector, webView, parameters,
									frame, guardedCompletion);
}

} // namespace

void Platform::Mac::InstallWebViewFileInputBridge() {
	if (OriginalOpenPanelImplementation) {
		return;
	}
	const auto handler = objc_getClass("Handler");
	Expects(handler != nil);
	Expects(class_conformsToProtocol(handler, @protocol(WKUIDelegate)));
	const auto selector
		= sel_registerName("webView:runOpenPanelWithParameters:"
						   "initiatedByFrame:completionHandler:");
	const auto method = class_getInstanceMethod(handler, selector);
	Expects(method != nullptr);
	OriginalOpenPanelImplementation
		= reinterpret_cast<OpenPanelImplementation>(method_setImplementation(
			method, reinterpret_cast<IMP>(&GuardedOpenPanel)));
	Expects(OriginalOpenPanelImplementation != nullptr);
}
