import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Extension Test Suite', () => {
    vscode.window.showInformationMessage('Start all tests.');

    test('Extension should be present', () => {
        assert.ok(vscode.extensions.getExtension('envdrift.envdrift-vscode'));
    });

    test('Extension should activate', async () => {
        const ext = vscode.extensions.getExtension('envdrift.envdrift-vscode');
        assert.ok(ext, 'Extension should be present');
        await ext.activate();
        assert.strictEqual(ext.isActive, true);
    });

    test('Commands should be registered', async () => {
        const commands = await vscode.commands.getCommands(true);

        assert.ok(commands.includes('envdrift.enable'), 'envdrift.enable command should be registered');
        assert.ok(commands.includes('envdrift.disable'), 'envdrift.disable command should be registered');
        assert.ok(commands.includes('envdrift.encryptNow'), 'envdrift.encryptNow command should be registered');
        assert.ok(commands.includes('envdrift.showStatus'), 'envdrift.showStatus command should be registered');
    });

    test('Configuration should have default values', () => {
        const config = vscode.workspace.getConfiguration('envdrift');

        assert.strictEqual(config.get('enabled'), true, 'enabled should default to true');
        assert.deepStrictEqual(config.get('patterns'), ['.env*'], 'patterns should default to [".env*"]');
        assert.ok(Array.isArray(config.get('exclude')), 'exclude should be an array');
        assert.strictEqual(config.get('showNotifications'), true, 'showNotifications should default to true');
    });
});
