import * as assert from 'assert';
import { pickConfigTargetScope } from '../../utils';

// Regression tests for issue #482: the enable/disable toggle always wrote the
// GLOBAL setting, so with a workspace-level `envdrift.enabled` the announced
// state change never took effect. The toggle must write to the scope that
// defines the value (per `WorkspaceConfiguration.inspect()` precedence).
suite('pickConfigTargetScope writes where the value is defined (#482)', () => {
    test('no override anywhere -> global', () => {
        assert.strictEqual(pickConfigTargetScope(undefined), 'global');
        assert.strictEqual(pickConfigTargetScope({}), 'global');
        assert.strictEqual(pickConfigTargetScope({ globalValue: true }), 'global');
    });

    test('workspace-defined value -> workspace (the #482 toggle regression)', () => {
        assert.strictEqual(pickConfigTargetScope({ workspaceValue: false }), 'workspace');
        assert.strictEqual(
            pickConfigTargetScope({ globalValue: true, workspaceValue: false }),
            'workspace'
        );
    });

    test('workspace-folder value wins over workspace and global', () => {
        assert.strictEqual(
            pickConfigTargetScope({
                globalValue: true,
                workspaceValue: false,
                workspaceFolderValue: true,
            }),
            'workspaceFolder'
        );
        assert.strictEqual(
            pickConfigTargetScope({ workspaceFolderValue: false }),
            'workspaceFolder'
        );
    });

    test('a defined false value counts as defined (booleans are the whole point)', () => {
        assert.strictEqual(pickConfigTargetScope({ workspaceValue: false }), 'workspace');
        assert.strictEqual(pickConfigTargetScope({ globalValue: false }), 'global');
    });
});
