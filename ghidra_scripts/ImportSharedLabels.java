// Import the repository's shared/ labels (functions, data, optional types) into the current program.
// Import the function names and global variable names (optionally structs) under the repository's shared/ into the current Ghidra program.
//
// Headless:
//   analyzeHeadless <project> <name> -process EDF.dll -scriptPath ghidra_scripts \
//       -postScript ImportSharedLabels.java <shared-dir> [types] [strict]
// Arguments (any order after the first):
//   <shared-dir>  path to shared/ (default: ../shared next to this script)
//   types         also create /shared/<Type> structures from shared/types/*.tsv
//   strict        throw when the program's SHA-256 is not listed in shared/builds.tsv
// The build is chosen by matching the program's executable SHA-256 against shared/builds.tsv; rows for
// other builds are ignored. On a conflict the shared table wins and the old name is logged.
//@category EDF6

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.WideCharDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.app.util.NamespaceUtils;

public class ImportSharedLabels extends GhidraScript {
    private static final String BEGIN = "[shared-labels]";
    private static final String END = "[/shared-labels]";

    private int created, renamed, unchanged, conflicts, failures, dataLabels, structures;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Path shared = null;
        boolean withTypes = false, strict = false;
        for (String arg : args) {
            if (arg.equalsIgnoreCase("types")) withTypes = true;
            else if (arg.equalsIgnoreCase("strict")) strict = true;
            else if (shared == null) shared = Path.of(arg);
            else throw new IllegalArgumentException("Unexpected argument: " + arg);
        }
        if (shared == null) shared = getSourceFile().getFile(false).toPath().getParent().resolveSibling("shared");
        shared = shared.toAbsolutePath().normalize();
        String module = currentProgram.getName();
        String sha256 = currentProgram.getExecutableSHA256();
        String build = findBuild(shared.resolve("builds.tsv"), module, sha256);
        if (build == null) {
            String message = "No build in " + shared.resolve("builds.tsv") + " matches " + module + " sha256 " + sha256;
            if (strict) throw new IllegalStateException(message);
            log(message + "; nothing imported.");
            return;
        }
        log("Importing shared labels for " + module + " build " + build + " from " + shared);
        // Headless post-scripts normally run inside a transaction already; open one only when needed.
        int transaction = currentProgram.getCurrentTransactionInfo() == null
                ? currentProgram.startTransaction("Import shared labels") : -1;
        boolean committed = false;
        try {
            importFunctions(shared.resolve("functions").resolve(module + ".tsv"), build);
            importData(shared.resolve("data").resolve(module + ".tsv"), build);
            if (withTypes) importTypes(shared.resolve("types"), build);
            committed = true;
        } finally {
            if (transaction >= 0) currentProgram.endTransaction(transaction, committed);
        }
        log(String.format(Locale.ROOT,
                "Done: %d functions created, %d renamed, %d unchanged, %d conflicts (shared won), %d failures, "
                        + "%d data labels, %d structures.",
                created, renamed, unchanged, conflicts, failures, dataLabels, structures));
    }

    private void log(String message) {
        println("[ImportSharedLabels] " + message);
    }

    /** Read a shared TSV: skips blank and '#' lines, the first remaining line is the header. */
    private static List<Map<String, String>> readTable(Path path) throws IOException {
        List<Map<String, String>> rows = new ArrayList<>();
        if (!Files.isRegularFile(path)) return rows;
        String[] header = null;
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] cells = line.split("\t", -1);
            if (header == null) {
                header = cells;
                continue;
            }
            if (cells.length != header.length) {
                throw new IOException(path + ": expected " + header.length + " columns: " + line);
            }
            Map<String, String> row = new HashMap<>();
            for (int i = 0; i < header.length; i++) row.put(header[i], cells[i]);
            rows.add(row);
        }
        return rows;
    }

    private static String findBuild(Path builds, String module, String sha256) throws IOException {
        for (Map<String, String> row : readTable(builds)) {
            if (row.get("module").equalsIgnoreCase(module) && row.get("sha256").equalsIgnoreCase(sha256)) {
                return row.get("build");
            }
        }
        return null;
    }

    private Address at(String rva) {
        return currentProgram.getImageBase().add(Long.parseLong(rva.substring(2), 16));
    }

    private Namespace namespaceFor(String qualified) throws Exception {
        int split = qualified.lastIndexOf("::");
        if (split < 0) return currentProgram.getGlobalNamespace();
        return NamespaceUtils.createNamespaceHierarchy(qualified.substring(0, split),
                currentProgram.getGlobalNamespace(), currentProgram, SourceType.USER_DEFINED);
    }

    private static String simpleName(String qualified) {
        int split = qualified.lastIndexOf("::");
        return split < 0 ? qualified : qualified.substring(split + 2);
    }

    private static String block(Map<String, String> row) {
        StringBuilder text = new StringBuilder(BEGIN).append('\n');
        text.append(row.get("name")).append("  [").append(row.get("confidence")).append("]\n");
        text.append("evidence: ").append(row.get("evidence")).append('\n');
        String notes = row.getOrDefault("notes", "");
        if (!notes.isEmpty()) text.append("notes: ").append(notes).append('\n');
        return text.append(END).toString();
    }

    /** Replace our previous block (if any) and keep whatever else the comment held. */
    private static String merge(String existing, String block) {
        if (existing == null || existing.isEmpty()) return block;
        int begin = existing.indexOf(BEGIN);
        int end = existing.indexOf(END);
        String rest = existing;
        if (begin >= 0 && end > begin) {
            rest = (existing.substring(0, begin) + existing.substring(end + END.length())).strip();
        }
        return rest.isEmpty() ? block : block + "\n" + rest;
    }

    private void importFunctions(Path table, String build) throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        for (Map<String, String> row : readTable(table)) {
            if (!build.equals(row.get("build"))) continue;
            String rva = row.get("rva");
            String name = row.get("name");
            try {
                Address address = at(rva);
                Function function = functions.getFunctionAt(address);
                if (function == null) {
                    Function owner = functions.getFunctionContaining(address);
                    if (owner != null) {
                        conflicts++;
                        log("CONFLICT " + rva + " " + name + " lies inside " + owner.getName(true) + " at "
                                + owner.getEntryPoint() + "; creating a separate function (shared table wins)");
                    }
                    if (getInstructionAt(address) == null) disassemble(address);
                    function = createFunction(address, null);
                    if (function == null) {
                        failures++;
                        log("FAILED " + rva + " " + name + ": could not create a function");
                        continue;
                    }
                    created++;
                }
                String signature = row.getOrDefault("signature", "");
                if (!signature.isEmpty()) applySignature(function, signature, rva);
                Symbol symbol = function.getSymbol();
                String before = function.getName(true);
                if (before.equals(name)) {
                    unchanged++;
                } else {
                    if (symbol.getSource() == SourceType.USER_DEFINED || symbol.getSource() == SourceType.IMPORTED) {
                        conflicts++;
                        log("CONFLICT " + rva + " was " + before + ", now " + name + " (shared table wins)");
                    }
                    symbol.setNameAndNamespace(simpleName(name), namespaceFor(name), SourceType.USER_DEFINED);
                    renamed++;
                }
                setPlateComment(address, merge(getPlateComment(address), block(row)));
            } catch (Exception error) {
                failures++;
                log("FAILED " + rva + " " + name + ": " + error);
            }
        }
    }

    private void applySignature(Function function, String signature, String rva) {
        try {
            FunctionSignatureParser parser = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
            FunctionDefinitionDataType definition = parser.parse(function.getSignature(), signature);
            new ApplyFunctionSignatureCmd(function.getEntryPoint(), definition, SourceType.USER_DEFINED)
                    .applyTo(currentProgram, monitor);
        } catch (Exception error) {
            failures++;
            log("SIGNATURE " + rva + " not applied (" + signature + "): " + error.getMessage());
        }
    }

    private void importData(Path table, String build) throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (Map<String, String> row : readTable(table)) {
            if (!build.equals(row.get("build"))) continue;
            String rva = row.get("rva");
            String name = row.get("name");
            try {
                Address address = at(rva);
                Symbol primary = symbols.getPrimarySymbol(address);
                if (primary != null && !primary.getName(true).equals(name)
                        && primary.getSource() == SourceType.USER_DEFINED) {
                    conflicts++;
                    log("CONFLICT " + rva + " was " + primary.getName(true) + ", now " + name + " (shared table wins)");
                }
                createLabel(address, simpleName(name), namespaceFor(name), true, SourceType.USER_DEFINED);
                setPreComment(address, merge(getPreComment(address), block(row)));
                dataLabels++;
            } catch (Exception error) {
                failures++;
                log("FAILED " + rva + " " + name + ": " + error);
            }
        }
    }

    private static DataType primitive(String type, Integer size) {
        String t = type.toLowerCase(Locale.ROOT).replace(" ", "");
        if (t.endsWith("*") || t.equals("ptr") || t.equals("hwnd")) return new PointerDataType();
        switch (t) {
            case "u8": case "uint8_t": case "bool": return new ByteDataType();
            case "i8": case "int8_t": return new SignedByteDataType();
            case "char": return new CharDataType();
            case "wchar_t": return new WideCharDataType();
            case "u16": case "uint16_t": return new UnsignedShortDataType();
            case "i16": case "int16_t": case "short": return new ShortDataType();
            case "u32": case "uint32_t": case "uint": return new UnsignedIntegerDataType();
            case "i32": case "int32_t": case "int": return new IntegerDataType();
            case "u64": case "uint64_t": return new UnsignedLongLongDataType();
            case "i64": case "int64_t": return new LongLongDataType();
            case "float": return new FloatDataType();
            case "double": return new DoubleDataType();
            case "vec4": case "float4": return new ArrayDataType(new FloatDataType(), 4, 4);
            case "mat4": return new ArrayDataType(new FloatDataType(), 16, 4);
            default: break;
        }
        if (size == null) return null;
        return size <= 8 ? Undefined.getUndefinedDataType(size) : new ArrayDataType(new ByteDataType(), size, 1);
    }

    private void importTypes(Path folder, String build) throws Exception {
        if (!Files.isDirectory(folder)) return;
        DataTypeManager manager = currentProgram.getDataTypeManager();
        CategoryPath category = new CategoryPath("/shared");
        List<Path> files;
        try (Stream<Path> listing = Files.list(folder)) {
            files = listing.filter(p -> p.getFileName().toString().endsWith(".tsv")).sorted().toList();
        }
        for (Path file : files) {
            String typeName = file.getFileName().toString().replaceFirst("\\.tsv$", "").replace("::", "_");
            TreeMap<Long, Map<String, String>> fields = new TreeMap<>();
            for (Map<String, String> row : readTable(file)) {
                if (build.equals(row.get("build"))) fields.put(Long.parseLong(row.get("offset").substring(2), 16), row);
            }
            if (fields.isEmpty()) continue;
            // Resolve every field first so the structure can be created at its final length.
            List<Object[]> resolved = new ArrayList<>();
            int total = 0;
            for (Map.Entry<Long, Map<String, String>> entry : fields.entrySet()) {
                Map<String, String> row = entry.getValue();
                String sizeText = row.get("size");
                Integer size = sizeText.equals("?") ? null : Integer.decode(sizeText);
                DataType type = primitive(row.get("type"), size);
                if (type == null) {
                    log("TYPE " + typeName + "+" + row.get("offset") + " " + row.get("name")
                            + " skipped: unknown size for type " + row.get("type"));
                    continue;
                }
                int length = size != null ? size : type.getLength();
                if (type.getLength() > 0 && type.getLength() != length) {
                    type = length <= 8 ? Undefined.getUndefinedDataType(length)
                            : new ArrayDataType(new ByteDataType(), length, 1);
                }
                int offset = entry.getKey().intValue();
                resolved.add(new Object[] {offset, type, length, row});
                total = Math.max(total, offset + length);
            }
            if (resolved.isEmpty()) continue;
            StructureDataType structure = new StructureDataType(category, typeName, total, manager);
            structure.setDescription("Imported from shared/types/" + file.getFileName() + " (" + build
                    + "); unknown bytes stay undefined");
            for (Object[] field : resolved) {
                @SuppressWarnings("unchecked")
                Map<String, String> row = (Map<String, String>) field[3];
                String comment = "[" + row.get("confidence") + "] " + row.get("type") + "; " + row.get("evidence");
                structure.replaceAtOffset((Integer) field[0], (DataType) field[1], (Integer) field[2],
                        row.get("name"), comment);
            }
            manager.addDataType(structure, DataTypeConflictHandler.REPLACE_HANDLER);
            structures++;
        }
    }
}
