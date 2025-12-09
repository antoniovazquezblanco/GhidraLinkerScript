/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package linkerscript;

import java.io.File;

import javax.swing.SwingConstants;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskLauncher;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Import information form linker scripts (LD).",
	description = "This plugin manages the import of information fron linker scripts (LD extension)."
)
//@formatter:on
public class LinkerScriptPlugin extends ProgramPlugin {

	public LinkerScriptPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	private void createActions() {
		new ActionBuilder("Load LD Script", this.getName()).withContext(ProgramActionContext.class)
				.validContextWhen(pac -> pac.getProgram() != null).menuPath(ToolConstants.MENU_FILE, "Load LD Script...")
				.menuGroup("Import PDB", "5").onAction(pac -> loadLd(pac)).buildAndInstall(tool);
	}

	private void loadLd(ProgramActionContext pac) {
		Program program = pac.getProgram();
		AutoAnalysisManager currentAutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program);
		if (currentAutoAnalysisManager.isAnalyzing()) {
			Msg.showWarn(getClass(), null, "Load LD", "Unable to load LD file while analysis is running.");
			return;
		}

		tool.setStatusInfo("Loading LD file.");

		File file = LdFileDialog.getLdFileFromDialog(pac.getComponentProvider().getComponent());
		if (file == null) {
			tool.setStatusInfo("LD loading was cancelled.");
			return;
		}

		tool.setStatusInfo("Loading symbols from LD file...");
		LdLoadTask loadTask = new LdLoadTask(program, file);
		TaskBuilder.withTask(loadTask).setStatusTextAlignment(SwingConstants.LEADING).setLaunchDelay(0);
		new TaskLauncher(loadTask);

		tool.setStatusInfo("LD loader finished.");
	}
}
