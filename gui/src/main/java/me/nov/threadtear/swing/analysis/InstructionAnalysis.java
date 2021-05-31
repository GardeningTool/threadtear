package me.nov.threadtear.swing.analysis;

import java.util.List;
import java.util.stream.StreamSupport;

import me.nov.threadtear.logging.LogWrapper;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import me.nov.threadtear.execution.Clazz;
import me.nov.threadtear.util.*;
import me.nov.threadtear.util.format.Strings;

public class InstructionAnalysis implements Opcodes {
  public static void analyze(List<Clazz> classes) {
    LogWrapper.logger.debug("Analyzing all instructions...");
    LogWrapper.logger.debug("Jumps in proportion to references -> ");

    double jumpPercentage = classes.stream().map(c -> c.node.methods).flatMap(List::stream).mapToDouble(m -> Counting
            .percentOf(AbstractInsnNode.JUMP_INSN, m.instructions, AbstractInsnNode.METHOD_INSN,
                    AbstractInsnNode.FIELD_INSN, AbstractInsnNode.TYPE_INSN)).average().orElse(Double.NaN);

    double jumpPercentageCalculated = Math.round(jumpPercentage * 10000) / 100.0;
    double jumpPercentageThreshold = 11;
    LogWrapper.logger.debug(jumpPercentageCalculated + "%");
    LogWrapper.logger.debug("Normal proportion is about 11%.");
    LogWrapper.logger.debug("A higher value indicates flow obfuscation.");
    if (jumpPercentageCalculated > jumpPercentageThreshold) {
      LogWrapper.logger.debug(String.format("The value %f exceeds the threshold of %f. This indicates flow obfuscation is present.", jumpPercentageCalculated, jumpPercentageThreshold));
    } else {
      LogWrapper.logger.debug(String.format("The value %f does not exceed the threshold of %f", jumpPercentageCalculated, jumpPercentageThreshold));
    }
    LogWrapper.logger.debug("----------------------------------------------");

    LogWrapper.logger.debug("Average invokedynamics per method -> ");
    double invokedynamics = classes.stream().map(c -> c.node.methods).flatMap(List::stream)
            .mapToDouble(m -> Counting.count(m.instructions, AbstractInsnNode.INVOKE_DYNAMIC_INSN)).average()
            .orElse(Double.NaN);
    double invokeDynamicPercentage = Math.round(invokedynamics * 100) / 100.0;
    double invokeDynamcicThreshold = 0.4;
    LogWrapper.logger.debug(invokeDynamicPercentage + "");
    LogWrapper.logger.debug("Normally about 0.0 - 0.4.");
    LogWrapper.logger.debug("A higher value indicates reference obfuscation.");
    if (invokeDynamicPercentage > invokeDynamcicThreshold) {
      LogWrapper.logger.debug(String.format("The value %f exceeds the threshold of %f. This indicates reference obfuscation is present.", invokeDynamicPercentage, invokeDynamcicThreshold));
    } else {
      LogWrapper.logger.debug(String.format("The value %f does not exceed the threshold of %f.", invokeDynamicPercentage, invokeDynamcicThreshold));
    }
    LogWrapper.logger.debug("----------------------------------------------");

    LogWrapper.logger.debug("Rare stack operations averagely per method -> ");
    double stackop = classes.stream().map(c -> c.node.methods).flatMap(List::stream)
            .mapToDouble(m -> Counting.countOp(m.instructions, POP2, DUP2, DUP_X1, DUP_X2, DUP2_X1, DUP2_X2, SWAP))
            .average().orElse(Double.NaN);
    double stackOperationCalculated = Math.round(stackop * 100) / 100.0;
    double stackOperationThreshold = 0.1;
    LogWrapper.logger.debug(stackOperationCalculated + "");
    LogWrapper.logger.debug("Normally about 0.0 - 0.1.");
    LogWrapper.logger.debug("A higher value indicates flow obfuscation.");
    if (stackOperationCalculated > stackOperationThreshold) {
      LogWrapper.logger.debug(String.format("The value %f exceeds the threshold of %f. This indicates flow obfuscation is present.", stackOperationCalculated, stackOperationThreshold));
    } else {
      LogWrapper.logger.debug(String.format("The value %f does not exceed the threshold of %f.", stackOperationCalculated, stackOperationThreshold));
    }
    LogWrapper.logger.debug("----------------------------------------------");

    LogWrapper.logger.debug("Average standard deviation of letters in strings -> ");
    double sdev = classes.stream().map(c -> c.node.methods).flatMap(List::stream).map(m -> m.instructions.spliterator())
            .flatMap(insns -> StreamSupport.stream(insns, false))
            .filter(ain -> ain.getOpcode() == LDC && ((LdcInsnNode) ain).cst instanceof String &&
                    ((LdcInsnNode) ain).cst.toString().length() > 2)
            .mapToDouble(ain -> Strings.calcSdev(((LdcInsnNode) ain).cst.toString())).average().orElse(Double.NaN);
    double sdevCount = Math.round(sdev * 100) / 100.0;
    double sdevThreshold = 40;
    LogWrapper.logger.debug(Math.round(sdev * 100) / 100.0 + "");
    LogWrapper.logger.debug("Normally around 15 - 40.");
    LogWrapper.logger.debug("A higher value could indicate string obfuscation.");
    if (sdevCount > sdevThreshold) {
      LogWrapper.logger.debug(String.format("The value %f exceeds the threshold of %f. This indicates string encryption is present.", sdevCount, sdevThreshold));
    } else {
      LogWrapper.logger.debug("The value %f does not exceed the threshold of %f.", sdevCount, sdevThreshold);
    }
    LogWrapper.logger.debug("----------------------------------------------");

    LogWrapper.logger.debug("Percentage of high character value strings -> ");
    double highutf =
            classes.stream().map(c -> c.node.methods).flatMap(List::stream).map(m -> m.instructions.spliterator())
                    .flatMap(insns -> StreamSupport.stream(insns, false))
                    .filter(ain -> ain.getOpcode() == LDC && ((LdcInsnNode) ain).cst instanceof String &&
                            ((LdcInsnNode) ain).cst.toString().length() > 2)
                    .mapToDouble(ain -> Strings.isHighUTF(((LdcInsnNode) ain).cst.toString()) ? 1 : 0).average()
                    .orElse(Double.NaN);

    double highUtfCalculated = Math.round(highutf * 10000) / 100.0;
    double highUtfThreshold = 1;

    LogWrapper.logger.debug(highUtfCalculated + "");
    LogWrapper.logger.debug("Normally around 0% - 1%.");
    LogWrapper.logger.debug("A higher value could indicate string obfuscation.");

    if (highUtfCalculated > highUtfThreshold) {
      LogWrapper.logger.debug(String.format("The value %f exceeds the threshold of %f. This indicates string encryption is present.", highUtfCalculated, highUtfThreshold));
    } else {
      LogWrapper.logger.debug("The value %f does not exceed the threshold of %f.", highUtfCalculated, highUtfThreshold);
    }

    LogWrapper.logger.debug("----------------------------------------------");

    LogWrapper.logger.debug("NOP instructions averagely per method -> ");
    double nops = classes.stream().map(c -> c.node.methods).flatMap(List::stream)
            .mapToDouble(m -> Counting.countOp(m.instructions, NOP)).average().orElse(Double.NaN);

    double nopPercentage = Math.round(nops * 100) / 100.0;
    double nopThreshold = 0.1;
    LogWrapper.logger.debug(nopPercentage + "");
    LogWrapper.logger.debug("Normally about 0.0 - 0.1.");
    LogWrapper.logger.debug("A higher value indicates unoptimized code.");
    if (nopPercentage > nopThreshold) {
      LogWrapper.logger.debug(String.format("The value %f exceed the threshold of %f. This is an indicator of unoptimized code.", nopPercentage, nopThreshold));
    } else {
      LogWrapper.logger.debug(String.format("The value %f does not exceed the threshold of %f", nopPercentage, nopThreshold));
    }
    LogWrapper.logger.debug("----------------------------------------------");
  }
}
