// @category EDF6

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class ExportInstructionIR extends GhidraScript {
    private static final Pattern ASM = Pattern.compile("^([0-9A-F]{8})  ((?:[0-9A-F]{2} ?)+)  +(.+)$");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Use: ExportInstructionIR.java annotated-assembly output-pcode");
        }
        Address base = currentProgram.getImageBase();
        PseudoDisassembler decoder = new PseudoDisassembler(currentProgram);
        HexFormat hex = HexFormat.of();
        int instructions = 0;
        int operations = 0;
        try (BufferedReader input = Files.newBufferedReader(Path.of(args[0]));
             BufferedWriter out = Files.newBufferedWriter(Path.of(args[1]), StandardOpenOption.CREATE_NEW)) {
            out.write("; Raw Ghidra P-code, one block per x64 instruction.\n");
            out.write("; Program SHA-256 " + currentProgram.getExecutableSHA256() + "\n");
            for (String line; (line = input.readLine()) != null;) {
                monitor.checkCancelled();
                if (line.isBlank() || line.startsWith(";")) {
                    if (line.startsWith("; EDF.dll SHA-256 ") && !line.endsWith(currentProgram.getExecutableSHA256())) {
                        throw new IllegalArgumentException("Assembly and Ghidra program hashes differ");
                    }
                    out.write(line + "\n");
                    continue;
                }
                Matcher fields = ASM.matcher(line);
                if (!fields.matches()) {
                    throw new IllegalArgumentException("Unrecognized assembly line: " + line);
                }
                long rva = Long.parseLong(fields.group(1), 16);
                Address address = base.add(rva);
                byte[] expected = hex.parseHex(fields.group(2).replace(" ", ""));
                PseudoInstruction ins = decoder.disassemble(address);
                if (ins == null || !Arrays.equals(ins.getBytes(), expected)) {
                    throw new IllegalStateException("Instruction boundary or byte disagreement at RVA " + fields.group(1));
                }
                out.write(line + "\n");
                for (PcodeOp op : ins.getPcode()) {
                    out.write("  " + render(op, base) + "\n");
                    operations++;
                }
                instructions++;
            }
            out.write("; instructions=" + instructions + " pcode_operations=" + operations + "\n");
        }
        println("Exported " + instructions + " instructions and " + operations + " P-code operations");
    }

    private String render(PcodeOp op, Address base) {
        StringBuilder line = new StringBuilder();
        if (op.getOutput() != null) {
            line.append(format(op.getOutput(), base)).append(" = ");
        }
        line.append(op.getMnemonic()).append('(');
        for (int i = 0; i < op.getNumInputs(); i++) {
            if (i > 0) {
                line.append(", ");
            }
            line.append(format(op.getInput(i), base));
        }
        return line.append(')').toString();
    }

    private String format(Varnode value, Address base) {
        int size = value.getSize();
        long offset = value.getOffset();
        String label;
        if (value.isRegister()) {
            Register register = currentProgram.getLanguage().getRegister(value.getAddress(), size);
            label = register == null ? String.format("register_%x", offset) : register.getName();
        } else if (value.isAddress() && value.getAddress().getAddressSpace().equals(base.getAddressSpace())) {
            label = offset >= base.getOffset() ? String.format("ram[RVA 0x%08X]", offset - base.getOffset())
                    : String.format("ram[0x%X]", offset);
        } else if (value.isConstant()) {
            label = String.format("0x%X", offset);
        } else {
            label = String.format("%s_%x", value.getAddress().getAddressSpace().getName(), offset);
        }
        return label + ":" + (size * 8);
    }
}
