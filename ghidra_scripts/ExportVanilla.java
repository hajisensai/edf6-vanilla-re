// Export the functions in a locally analyzed Windows PE as RVA-indexed C pseudocode.
// @category EDF6

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.ChunkingParallelDecompiler;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public class ExportVanilla extends GhidraScript {
    private record Result(long rva, String name, String code, String diagnostic) {}

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 3 || (args.length == 3 && !Set.of("unwind", "retry", "candidates").contains(args[2]))) {
            throw new IllegalArgumentException("Use: ExportVanilla.java output-directory [address-list.txt [unwind|retry|candidates]]");
        }
        String sha256 = currentProgram.getExecutableSHA256();
        String expected = System.getProperty("edf6.export.sha256");
        if (expected != null && !expected.equalsIgnoreCase(sha256)) {
            throw new IllegalArgumentException("The Ghidra project and the installed PE have different SHA-256 values.");
        }
        Path out = Path.of(args[0], currentProgram.getName());
        Files.createDirectories(out);
        long base = currentProgram.getImageBase().getOffset();
        Set<Long> priority = new HashSet<>();
        if (args.length >= 2) {
            for (String line : Files.readAllLines(Path.of(args[1]))) {
                if (!line.isBlank()) {
                    priority.add(Long.decode(line.strip()));
                }
            }
        }
        boolean retry = args.length == 3 && args[2].equals("retry");
        List<Function> functions = switch (args.length == 3 ? args[2] : "") {
            case "unwind" -> seedUnwind(out);
            case "candidates" -> seedCandidates(out, priority);
            default -> existingFunctions();
        };
        if (retry) {
            functions.removeIf(f -> !priority.contains(f.getEntryPoint().getOffset() - base));
            if (functions.size() != priority.size()) {
                throw new IllegalArgumentException("Some retry RVAs are missing from the Ghidra project");
            }
        }
        // Stable sort preserves address order inside each group.
        functions.sort(Comparator.comparing(f -> !priority.contains(f.getEntryPoint().getOffset() - base)));

        DecompilerCallback<Result> callback = new DecompilerCallback<>(currentProgram, decompiler -> {
            String simplification = System.getProperty("edf6.export.simplification");
            if (simplification != null) {
                decompiler.setSimplificationStyle(simplification);
            }
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(false);
        }) {
            @Override
            public Result process(DecompileResults result, TaskMonitor task) {
                Function f = result.getFunction();
                String code = result.getDecompiledFunction() == null ? null : result.getDecompiledFunction().getC();
                return new Result(f.getEntryPoint().getOffset() - base, f.getName(), code,
                    result.getErrorMessage());
            }
        };
        callback.setTimeout(Integer.getInteger("edf6.export.timeout", retry ? 45 : 10));
        ChunkingParallelDecompiler<Result> decompiler = ParallelDecompiler.createChunkingParallelDecompiler(callback, monitor);
        int count = 0;
        int succeeded = 0;
        Path indexPath = out.resolve("functions.tsv");
        println("Exporting " + functions.size() + " functions to " + out);
        try (BufferedWriter index = Files.newBufferedWriter(indexPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW)) {
            index.write("rva\tname\tfile\tline\tstatus\tdiagnostic\n");
            for (int start = 0; start < functions.size(); start += 512) {
                monitor.checkCancelled();
                int end = Math.min(start + 512, functions.size());
                List<Result> results = decompiler.decompileFunctions(functions.subList(start, end));
                monitor.checkCancelled();
                results.sort(Comparator.comparingLong(Result::rva));
                String filename = String.format("part-%04d.c", start / 512);
                try (BufferedWriter code = Files.newBufferedWriter(out.resolve(filename), StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW)) {
                    String style = System.getProperty("edf6.export.simplification", "decompile");
                    code.write("/* Ghidra pseudocode (" + style + "). Addresses are RVAs. Types and names can be inferred. */\n");
                    int line = 2;
                    for (Result result : results) {
                        String rva = String.format("0x%08X", result.rva());
                        String diagnostic = result.diagnostic() == null ? "" : result.diagnostic().replaceAll("[\\t\\r\\n]+", " ").strip();
                        if (result.code() == null) {
                            index.write(rva + "\t" + result.name() + "\t\t\tfailed\t" + diagnostic + "\n");
                        } else {
                            String body = "\n/* RVA " + rva + " */\n" + result.code().strip() + "\n";
                            index.write(rva + "\t" + result.name() + "\t" + filename + "\t" + (line + 1) + "\tok\t" + diagnostic + "\n");
                            code.write(body);
                            line += (int) body.chars().filter(ch -> ch == '\n').count();
                            succeeded++;
                        }
                        count++;
                    }
                }
                index.flush();
                println("Exported " + count + "/" + functions.size() + ", C pseudocode " + succeeded);
            }
        } finally {
            decompiler.dispose();
            callback.dispose();
        }
        Files.writeString(out.resolve("complete.txt"), "functions=" + count + "\npseudocode=" + succeeded
            + "\nsha256=" + sha256 + "\n");
    }

    private List<Function> existingFunctions() {
        List<Function> functions = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            MemoryBlock block = currentProgram.getMemory().getBlock(f.getEntryPoint());
            if (block != null && block.isExecute()) {
                functions.add(f);
            }
        }
        return functions;
    }

    private List<Function> seedCandidates(Path out, Set<Long> candidates) throws Exception {
        List<Long> starts = new ArrayList<>(candidates);
        starts.sort(Long::compare);
        List<Function> added = new ArrayList<>();
        Address base = currentProgram.getImageBase();
        try (BufferedWriter audit = Files.newBufferedWriter(out.resolve("candidates.tsv"),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW)) {
            audit.write("rva\tstatus\n");
            for (int i = 0; i < starts.size(); i++) {
                monitor.checkCancelled();
                long rva = starts.get(i);
                Address first = base.add(rva);
                long limit = i + 1 < starts.size() ? Math.min(starts.get(i + 1), rva + 0x1000) : rva + 0x1000;
                MemoryBlock block = currentProgram.getMemory().getBlock(first);
                Function enclosing = getFunctionContaining(first);
                String status;
                if (block == null || !block.isExecute()) {
                    status = "outside executable memory";
                } else if (enclosing != null) {
                    status = String.format("inside function 0x%08X", enclosing.getEntryPoint().subtract(base));
                } else {
                    Address last = base.add(limit - 1);
                    if (last.compareTo(block.getEnd()) > 0) {
                        last = block.getEnd();
                    }
                    FunctionIterator later = currentProgram.getFunctionManager().getFunctions(first, true);
                    Function next = later.hasNext() ? later.next() : null;
                    if (next != null && next.getEntryPoint().compareTo(last) <= 0) {
                        last = next.getEntryPoint().subtract(1);
                    }
                    if (getInstructionAt(first) == null && getInstructionContaining(first) == null) {
                        new DisassembleCommand(first, new AddressSet(first, last), true).applyTo(currentProgram, monitor);
                    }
                    Function function = getInstructionAt(first) == null ? null : createFunction(first, null);
                    status = function == null ? "no function recovered" : "seeded";
                    if (function != null) {
                        added.add(function);
                    }
                }
                audit.write(String.format("0x%08X\t%s%n", rva, status));
                if ((i + 1) % 2048 == 0) {
                    println("Seeded " + added.size() + " of " + (i + 1) + " examined targets");
                }
            }
        }
        println("Seeded " + added.size() + "/" + starts.size() + " candidate targets");
        return added;
    }

    private List<Function> seedUnwind(Path out) throws Exception {
        // Windows AMD64 RUNTIME_FUNCTION has three little-endian 32-bit RVAs.
        MemoryBlock table = currentProgram.getMemory().getBlock(".pdata");
        if (table == null) {
            throw new IllegalArgumentException("No .pdata block");
        }
        List<Function> added = new ArrayList<>();
        int covered = 0;
        int attempted = 0;
        try (BufferedWriter skipped = Files.newBufferedWriter(out.resolve("unwind-unresolved.tsv"),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW)) {
            skipped.write("begin_rva\tend_rva\treason\n");
            for (long delta = 0; delta + 12 <= table.getSize(); delta += 12) {
                monitor.checkCancelled();
                Address slot = table.getStart().add(delta);
                long firstRva = Integer.toUnsignedLong(currentProgram.getMemory().getInt(slot));
                long endRva = Integer.toUnsignedLong(currentProgram.getMemory().getInt(slot.add(4)));
                if (firstRva == 0 || endRva <= firstRva) {
                    continue;
                }
                Address first = currentProgram.getImageBase().add(firstRva);
                Address last = currentProgram.getImageBase().add(endRva - 1);
                MemoryBlock block = currentProgram.getMemory().getBlock(first);
                if (block == null || !block.isExecute() || !block.contains(last)) {
                    skipped.write(String.format("0x%08X\t0x%08X\toutside executable memory%n", firstRva, endRva));
                    continue;
                }
                Function enclosing = getFunctionContaining(first);
                if (enclosing != null) {
                    covered++;
                    if (!enclosing.getEntryPoint().equals(first)) {
                        long owner = enclosing.getEntryPoint().subtract(currentProgram.getImageBase());
                        skipped.write(String.format("0x%08X\t0x%08X\tinside function 0x%08X%n", firstRva, endRva, owner));
                    }
                    continue;
                }
                attempted++;
                if (getInstructionAt(first) == null) {
                    new DisassembleCommand(first, new AddressSet(first, last), true).applyTo(currentProgram, monitor);
                }
                Function function = getInstructionAt(first) == null ? null : createFunction(first, null);
                if (function == null) {
                    skipped.write(String.format("0x%08X\t0x%08X\tno function recovered%n", firstRva, endRva));
                } else {
                    added.add(function);
                }
                if (attempted % 2048 == 0) {
                    println("Seeded " + added.size() + " of " + attempted + " candidate unwind starts");
                }
            }
        }
        println("Existing function coverage at " + covered + " unwind starts, seeded " + added.size() + "/" + attempted);
        return added;
    }
}
