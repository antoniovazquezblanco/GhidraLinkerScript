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
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import io.ldparser.Command;
import io.ldparser.LDParser;
import io.ldparser.ProvideCommand;
import io.ldparser.Script;

public class LdLoadTask extends Task {

    private Program program;
    private File ldFile;

    public LdLoadTask(Program program, File ldFile) {
        super("Loading LD symbols", true, false, false);
        this.program = program;
        this.ldFile = ldFile;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
		Script script;
		try {
			script = LDParser.parse(ldFile);
		} catch (IOException e) {
			Msg.showError(getClass(), null, "Load LD", "Unable to parse LD file.", e);
			return;
		}

		Map<String, Long> symbols = new HashMap<>();
        for (Command cmd : script.getCommands()) {
        	monitor.checkCancelled();
            if (cmd instanceof ProvideCommand) {
                ProvideCommand pc = (ProvideCommand) cmd;
                symbols.put(pc.getSymbolName(), pc.getExpression().getNumericalValue());
            }
        }
    	
        SymbolTable symbolTable = program.getSymbolTable();
        for (Map.Entry<String, Long> entry : symbols.entrySet()) {
        	monitor.checkCancelled();
            String name = entry.getKey();
            long addrValue = entry.getValue();

            try {
                Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addrValue);
                Msg.info(getClass(), String.format("Creating label %s at %s.", name, addr.toString()));
                symbolTable.createLabel(addr, name, SourceType.IMPORTED);
            } catch (Exception e) {
                // Skip invalid addresses or other errors
            }
        }
    }
}