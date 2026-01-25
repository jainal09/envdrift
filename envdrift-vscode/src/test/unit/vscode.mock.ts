// Mock vscode module for unit testing outside of VS Code
export const workspace = {
    getConfiguration: () => ({
        get: (key: string, defaultValue: unknown) => defaultValue,
        update: async () => {},
    }),
};

export const window = {
    showInformationMessage: async () => undefined,
    showErrorMessage: async () => undefined,
    showWarningMessage: async () => undefined,
    createStatusBarItem: () => ({
        text: '',
        tooltip: '',
        command: '',
        show: () => {},
        hide: () => {},
        dispose: () => {},
    }),
};

export const StatusBarAlignment = {
    Left: 1,
    Right: 2,
};

export const ConfigurationTarget = {
    Global: 1,
    Workspace: 2,
    WorkspaceFolder: 3,
};

export class ThemeColor {
    constructor(public id: string) {}
}

export const commands = {
    registerCommand: () => ({ dispose: () => {} }),
    getCommands: async () => [],
};

export const extensions = {
    getExtension: () => null,
};

export const env = {
    clipboard: {
        writeText: async () => {},
    },
    openExternal: async () => false,
};

export class Uri {
    static parse(value: string): Uri {
        return new Uri(value);
    }
    constructor(public readonly fsPath: string) {}
}
