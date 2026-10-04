/**
 * NoireBox — Flight Recorder for VSCode.
 *
 * Integration = glue, the core stays single (docs/ROADMAP-PLUGINS.md):
 * every command shells out to the installed `noirebox` CLI, which resolves
 * the journal through the ADR 013 convention (NOIREBOX_DB > nearest
 * .noirebox/ > ./.noirebox/journal.db). The extension never invents a
 * journal of its own — custody follows the working tree, exactly like the
 * Agent and Claude plugins.
 */
const vscode = require("vscode");
const { execFile } = require("child_process");

function cli(args, cwd) {
  const config = vscode.workspace.getConfiguration("noirebox");
  const env = Object.assign({}, process.env);
  const db = config.get("db");
  if (db) { env.NOIREBOX_DB = db; }
  return new Promise((resolve, reject) => {
    execFile("noirebox", args, { cwd, env }, (error, stdout, stderr) => {
      if (error) { reject(new Error(stderr || error.message)); }
      else { resolve(stdout.trim()); }
    });
  });
}

function workspaceRoot() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) { throw new Error("No workspace folder open — the journal follows the working tree."); }
  return folders[0].uri.fsPath;
}

async function run(args, label) {
  try {
    const out = await cli(args, workspaceRoot());
    vscode.window.showInformationMessage(`NoireBox ${label}: ${out.split("\n")[0]}`);
    return out;
  } catch (err) {
    vscode.window.showErrorMessage(`NoireBox ${label} failed: ${err.message}`);
    return undefined;
  }
}

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand("noirebox.verify", async () => {
      const out = await run(["verify"], "verify");
      if (out !== undefined) { vscode.window.showInformationMessage(out.split("\n").slice(0, 2).join("  ")); }
    }),
    vscode.commands.registerCommand("noirebox.sealNote", async () => {
      const note = await vscode.window.showInputBox({
        prompt: "Decision to seal into the journal (digests and short facts — never raw secrets)",
      });
      if (!note) { return; }
      await run(["seal", "decision", JSON.stringify({ note, source: "vscode" })], "seal");
    }),
    vscode.commands.registerCommand("noirebox.auditPack", async () => {
      const out = await run(["audit-pack", "audit"], "audit-pack");
      if (out !== undefined) { vscode.window.showInformationMessage(out.split("\n").slice(-1)[0]); }
    }),
    vscode.commands.registerCommand("noirebox.locate", async () => {
      const out = await run(["locate"], "locate");
      if (out !== undefined) { vscode.window.showInformationMessage(`Journal: ${out}`); }
    })
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
