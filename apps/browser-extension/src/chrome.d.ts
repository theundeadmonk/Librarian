declare namespace chrome {
  namespace runtime {
    interface MessageSender {
      readonly id?: string;
      readonly tab?: tabs.Tab;
      readonly frameId?: number;
      readonly documentId?: string;
      readonly documentLifecycle?: string;
      readonly url?: string;
      readonly origin?: string;
    }
    interface Port {
      readonly name: string;
      readonly sender?: MessageSender;
      readonly onMessage: {
        addListener(listener: (message: unknown) => void): void;
      };
      readonly onDisconnect: {
        addListener(listener: () => void): void;
      };
      postMessage(message: unknown): void;
      disconnect(): void;
    }

    interface RuntimeEvent {
      addListener(listener: () => void): void;
    }

    const onInstalled: RuntimeEvent;
    const onStartup: RuntimeEvent;
    const lastError: { readonly message?: string } | undefined;
    const id: string;
    const onConnect: { addListener(listener: (port: Port) => void): void };
    const onMessage: { addListener(listener: (message: unknown, sender: MessageSender,
      sendResponse: (response: unknown) => void) => void): void };

    function connectNative(application: string): Port;
    function connect(details: { readonly name: string }): Port;
  }

  namespace action {
    const onClicked: { addListener(listener: (tab: tabs.Tab) => void): void };

    function setBadgeText(details: { readonly text: string; readonly tabId?: number }): Promise<void>;
    function setBadgeBackgroundColor(details: {
      readonly color: string;
      readonly tabId?: number;
    }): Promise<void>;
    function setTitle(details: { readonly title: string; readonly tabId?: number }): Promise<void>;
  }

  namespace tabs {
    interface Tab { readonly id?: number; readonly url?: string; readonly active?: boolean }
    const onRemoved: { addListener(listener: (tabId: number) => void): void };
    function sendMessage(tabId: number, message: unknown, options: { readonly documentId: string }): Promise<unknown>;
  }

  namespace webNavigation {
    interface Frame {
      readonly documentId?: string;
      readonly documentLifecycle?: string;
      readonly frameType?: string;
      readonly parentFrameId?: number;
      readonly errorOccurred?: boolean;
      readonly url?: string;
    }
    interface NavigationEvent { addListener(listener: (details: { readonly tabId: number; readonly frameId: number }) => void): void }
    function getFrame(details: { readonly tabId: number; readonly frameId: number }): Promise<Frame | undefined>;
    const onBeforeNavigate: NavigationEvent;
    const onCommitted: NavigationEvent;
    const onHistoryStateUpdated: NavigationEvent;
    const onReferenceFragmentUpdated: NavigationEvent;
  }

  namespace permissions {
    function contains(details: { readonly origins: readonly string[] }): Promise<boolean>;
    const onRemoved: runtime.RuntimeEvent;
  }
}
