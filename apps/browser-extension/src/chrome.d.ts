declare namespace chrome {
  namespace runtime {
    interface Port {
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

    function connectNative(application: string): Port;
  }

  namespace action {
    const onClicked: runtime.RuntimeEvent;

    function setBadgeText(details: { readonly text: string }): Promise<void>;
    function setBadgeBackgroundColor(details: {
      readonly color: string;
    }): Promise<void>;
    function setTitle(details: { readonly title: string }): Promise<void>;
  }
}
